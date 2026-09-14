"""Path investigation (#1 and #2): "why can't A reach B" answered as a hypothesis ledger.

Each hypothesis is a Python predicate over Nexus Dashboard data (the twin) and NX-OS JSON tables (NX-API). The
outcome of every hypothesis is one of confirmed / refuted / untested / not_applicable, and every outcome carries
the evidence references (device, command, timestamp, hash) that decided it. Nothing here guesses: when data is
missing the hypothesis stays untested and says why.

Hypotheses, in the order a senior engineer walks the path:
  H1  source endpoint learned on its leaf              (MAC table, ARP)
  H2  VLAN and VNI present and up on both leaves       (show vlan, show nve vni)
  H3  EVPN Type-2 route for the destination on the source leaf (l2route mac / mac-ip)
  H4  network deployed identically in both sites       (twin: networks + attachments)
  H5  border gateways forward Multi-Site               (nve multisite dci/fabric links, nve peers to the remote VIP)
  H6  ISN / DCI healthy                                (twin links oper state, Analyze L3 neighbors, core BGP)
  H7  destination endpoint learned on its leaf         (MAC table, port state, VLAN membership)
  H8  VRF route to the destination                     (routed traffic only)
  H9  no ACL on the host ports                         (interface running config)
  H10 data plane                                       (ping from the source host, error counters on the path ports)
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field, asdict

import yaml

from .config import Settings
from .db import DB
from .nd import NDClient, NDError
from .nxapi import NXAPIClient, NXAPIError, Evidence, rows
from .twin import Twin
from .util import norm_mac, norm_if

UTC = dt.timezone.utc


@dataclass
class Endpoint:
    ip: str
    mac: str | None = None
    leaf: str | None = None          # hostname
    leaf_ip: str | None = None
    port: str | None = None          # Ethernet1/3
    vlan: str | None = None
    vrf: str | None = None
    fabric: str | None = None
    container: str | None = None     # containerlab node name when known
    how: str = ""                    # how it was located


@dataclass
class Hypothesis:
    id: str
    name: str
    status: str = "untested"         # confirmed | refuted | untested | not_applicable
    detail: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class Ledger:
    src: Endpoint
    dst: Endpoint
    started_at: str
    hypotheses: list[Hypothesis] = field(default_factory=list)
    conclusion: str = ""
    failure_domain: str = ""
    blast_radius: dict = field(default_factory=dict)
    twin_age: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Investigator:
    def __init__(self, settings: Settings, nd: NDClient, nx: NXAPIClient, db: DB, twin: Twin):
        self.s, self.nd, self.nx, self.db, self.twin = settings, nd, nx, db, twin
        self._ev: list[Evidence] = []

    # ------------------------------------------------------------ helpers
    def _show(self, device_ip: str, cmd: str, ascii_output: bool = False) -> Evidence | None:
        try:
            ev = self.nx.show(device_ip, cmd, ascii_output=ascii_output); self._ev.append(ev); return ev
        except NXAPIError as e:
            self._ev.append(Evidence(device_ip, cmd, dt.datetime.now(UTC).timestamp(), "", f"ERROR {e}")); return None

    @staticmethod
    def _walk(obj, table_prefix: str) -> list[dict]:
        """Find every ROW_* list under any TABLE_* whose name starts with the prefix, at any depth."""
        out: list[dict] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.startswith("TABLE_") and k[6:].startswith(table_prefix) and isinstance(v, dict):
                    for rk, rv in v.items():
                        if rk.startswith("ROW_"):
                            out.extend(rv if isinstance(rv, list) else [rv])
                out.extend(Investigator._walk(v, table_prefix))
        elif isinstance(obj, list):
            for it in obj:
                out.extend(Investigator._walk(it, table_prefix))
        return out

    def _topology(self) -> dict:
        try:
            return yaml.safe_load(open(self.s.topology_file)) or {}
        except FileNotFoundError:
            return {}

    def _host_links(self) -> dict[str, tuple[str, str]]:
        """container host name -> (leaf hostname, Ethernet1/N) from the topology file."""
        out = {}
        for link in (self._topology().get("topology", {}).get("links") or []):
            eps = link.get("endpoints", [])
            if len(eps) != 2:
                continue
            (a, ap), (b, bp) = (e.partition(":")[::2] for e in eps)
            for h, hp, l, lp in ((a, ap, b, bp), (b, bp, a, ap)):
                if "host" in h and lp.startswith("eth"):
                    out[h] = (l, f"Ethernet1/{lp[3:]}")
        return out

    # ------------------------------------------------------------ locating endpoints
    def locate(self, ip: str) -> Endpoint:
        ep = Endpoint(ip=ip)
        # 1. the twin's endpoint table (Analyze connectivity/endpoints, telemetry)
        for r in self.twin.find_endpoint(ip=ip):
            ep.mac, ep.leaf, ep.port, ep.vlan, ep.vrf, ep.fabric = norm_mac(r["mac"]), r["switch_name"] or None, norm_if(r["interface"]) or None, r["vlan"], r["vrf"], r["fabric"]
            ep.how = f"twin endpoints (collected {r['collected_at']:%H:%M:%SZ})"
            break
        # 2. the topology file for the container name and the cabled leaf port (authoritative for the cabling)
        name = next((n for n, i in self.s.probe_hosts.items() if i == ip), None)
        if name:
            ep.container = name
            l = self._host_links().get(name)
            if l:
                if ep.leaf and ep.leaf != l[0]:
                    ep.how += f"; topology says {l[0]} {l[1]}"
                ep.leaf, ep.port = ep.leaf or l[0], ep.port or l[1]
                ep.how = ep.how or f"topology file ({l[0]} {l[1]})"
        if ep.leaf:
            sw = self.twin.switch_by_name(ep.leaf)
            if sw:
                ep.leaf_ip, ep.fabric = sw["ip"], ep.fabric or sw["fabric"]
        # 3. ARP on the leaf fills the MAC and the VRF when the twin did not
        if ep.leaf_ip and (not ep.mac or not ep.vrf):
            for vrf in self._candidate_vrfs():
                ev = self._show(ep.leaf_ip, f"show ip arp vrf {vrf}")
                if ev and not isinstance(ev.body, str):
                    for a in self._walk(ev.body, "adj"):
                        if a.get("ip-addr-out") == ip:
                            ep.mac, ep.vrf = ep.mac or norm_mac(a.get("mac")), ep.vrf or vrf
                            ep.vlan = ep.vlan or re.sub(r"^Vlan", "", str(a.get("intf-out", "")))
                            ep.how += f"; ARP on {ep.leaf}"
        if ep.vlan and str(ep.vlan).lower().startswith("vlan"):
            ep.vlan = ep.vlan[4:]
        if not ep.vlan and ep.vrf:
            net = self._network_for_ip(ip)
            if net:
                ep.vlan = str(net["vlan"])
        return ep

    def _candidate_vrfs(self) -> list[str]:
        return [r["name"] for r in self.db.query("SELECT DISTINCT name FROM vrfs")] or ["default"]

    def _network_for_ip(self, ip: str) -> dict | None:
        for n in self.db.query("SELECT fabric, name, vrf, vni, vlan, gateway FROM networks WHERE gateway IS NOT NULL"):
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_interface(n["gateway"]).network:
                    return n
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------ the investigation
    def run(self, src_ip: str, dst_ip: str, with_ping: bool = True) -> Ledger:
        self._ev = []
        src, dst = self.locate(src_ip), self.locate(dst_ip)
        L = Ledger(src=src, dst=dst, started_at=dt.datetime.now(UTC).isoformat(), twin_age=str((self.twin.freshness() or {}).get("finished_at", "no twin snapshot")))
        net = self._network_for_ip(src_ip)
        same_subnet = bool(net) and self._network_for_ip(dst_ip) == net
        vlan = src.vlan or (str(net["vlan"]) if net else None)
        vni = net["vni"] if net else None
        vrf = src.vrf or (net["vrf"] if net else None)

        # H1 source learned locally
        h = Hypothesis("H1", "source endpoint learned on its leaf")
        if src.leaf_ip and src.mac:
            ev = self._show(src.leaf_ip, f"show mac address-table address {src.mac}")
            entries = self._walk(ev.body, "mac_address") if ev and not isinstance(ev.body, str) else []
            local = [e for e in entries if not str(e.get("disp_port", "")).startswith("nve")]
            if local:
                h.status, h.detail = "confirmed", f"{src.mac} learned on {src.leaf} port {local[0].get('disp_port')} vlan {local[0].get('disp_vlan')}"
            else:
                h.status, h.detail = "refuted", f"{src.mac} not in the MAC table of {src.leaf}" + (f" (only via {entries[0].get('disp_port')})" if entries else "")
            h.evidence = [ev.ref()] if ev else []
        else:
            h.detail = f"could not locate the source: leaf={src.leaf} mac={src.mac} ({src.how})"
        L.hypotheses.append(h)

        # H2 VLAN + VNI on both leaves
        for role, ep in (("source", src), ("destination", dst)):
            h = Hypothesis("H2", f"VLAN {vlan} and VNI {vni} present and up on the {role} leaf {ep.leaf}")
            if ep.leaf_ip and vlan:
                ev1 = self._show(ep.leaf_ip, f"show vlan id {vlan}"); ev2 = self._show(ep.leaf_ip, "show nve vni")
                vl = self._walk(ev1.body, "vlanbriefid") if ev1 and not isinstance(ev1.body, str) else []
                vn = [v for v in (self._walk(ev2.body, "nve_vni") if ev2 and not isinstance(ev2.body, str) else []) if str(v.get("vni")) == str(vni)]
                vlan_ok = bool(vl) and vl[0].get("vlanshowbr-vlanstate") == "active"
                vni_ok = bool(vn) and vn[0].get("vni-state") == "Up"
                ports = str(vl[0].get("vlanshowplist-ifidx", "")) if vl else ""
                h.status = "confirmed" if vlan_ok and vni_ok else "refuted"
                h.detail = f"vlan {'active' if vlan_ok else 'MISSING or inactive'} (ports: {ports or 'none'}), vni {vni} {'Up' if vni_ok else 'MISSING or down'}"
                h.evidence = [e.ref() for e in (ev1, ev2) if e]
            else:
                h.detail = f"no leaf or VLAN known for the {role}"
            L.hypotheses.append(h)

        # H3 EVPN Type-2 for the destination on the source leaf. Bridged traffic needs the MAC route; the MAC-IP route only
        # exists while the destination leaf holds an ARP entry for the host, so it is reported but does not decide on its own.
        h = Hypothesis("H3", f"EVPN Type-2 route for {dst_ip} on the source leaf {src.leaf}")
        if src.leaf_ip:
            ev_ip = self._show(src.leaf_ip, "show l2route evpn mac-ip all")
            ip_hits = [r for r in (self._walk(ev_ip.body, "l2route_mac_ip_all") if ev_ip and not isinstance(ev_ip.body, str) else []) if r.get("host-ip") == dst_ip]
            if ip_hits:
                dst.mac = dst.mac or norm_mac(ip_hits[0].get("mac-addr"))
            ev_mac = self._show(src.leaf_ip, "show l2route evpn mac all") if dst.mac else None
            mac_hits = [r for r in (self._walk(ev_mac.body, "l2route_mac_all") if ev_mac and not isinstance(ev_mac.body, str) else []) if norm_mac(r.get("mac-addr")) == dst.mac]
            def nh(r): return ",".join(str(n.get("nh")) for n in self._walk(r, "nexthop")) or str(r.get("next-hop1", ""))
            parts = []
            if mac_hits:
                parts.append(f"MAC route {dst.mac} via {mac_hits[0].get('prod-type')} next hop {nh(mac_hits[0])}")
            elif dst.mac:
                parts.append(f"no MAC route for {dst.mac}")
            parts.append(f"MAC-IP route for {dst_ip}: {'via ' + str(ip_hits[0].get('prod-type')) + ' next hop ' + nh(ip_hits[0]) if ip_hits else 'absent (destination leaf holds no ARP entry for the host right now)'}")
            h.status = "confirmed" if (mac_hits or (ip_hits and not dst.mac)) else "refuted"
            h.detail = "; ".join(parts) if dst.mac or ip_hits else f"destination MAC unknown and no MAC-IP route for {dst_ip} on {src.leaf}"
            h.evidence = [e.ref() for e in (ev_ip, ev_mac) if e]
        else:
            h.detail = "source leaf unknown"
        L.hypotheses.append(h)

        # H4 network consistency across sites (twin)
        h = Hypothesis("H4", "network deployed identically in both sites")
        if net:
            nets = self.db.query("SELECT fabric, vni, vlan, gateway, status FROM networks WHERE name=%s ORDER BY fabric", (net["name"],))
            atts = self.db.query("SELECT fabric, switch_name, state, ports FROM attachments WHERE network=%s ORDER BY fabric, switch_name", (net["name"],))
            fabrics = {n["fabric"] for n in nets}; distinct = {(n["vni"], n["vlan"], n["gateway"]) for n in nets}
            bad = [a for a in atts if a["state"] != "DEPLOYED"]
            need = {ep.leaf for ep in (src, dst) if ep.leaf}
            have = {a["switch_name"] for a in atts if a["state"] == "DEPLOYED"}
            missing = need - have
            if len(distinct) == 1 and not bad and not missing:
                h.status, h.detail = "confirmed", f"{net['name']}: vni {net['vni']} vlan {net['vlan']} gw {net['gateway']} in {sorted(fabrics)}, {len(atts)} attachments DEPLOYED"
            else:
                h.status = "refuted"
                h.detail = (f"{net['name']}: " + ("definitions differ across fabrics; " if len(distinct) > 1 else "") +
                            (f"attachments not deployed: {[(a['switch_name'], a['state']) for a in bad]}; " if bad else "") +
                            (f"not attached on {sorted(missing)}" if missing else "")).strip("; ")
            h.evidence = [f"twin networks/attachments for {net['name']} (twin age {L.twin_age})"]
        else:
            h.detail = f"no network in the twin covers {src_ip}"
        L.hypotheses.append(h)

        # H5 border gateways and the remote site VIP
        h = Hypothesis("H5", "border gateways of the source site forward Multi-Site traffic")
        if src.fabric and dst.fabric and src.fabric != dst.fabric:
            bgws = self.db.query("SELECT hostname, host(mgmt_ip) AS ip FROM switches WHERE fabric=%s AND role='border gateway'", (src.fabric,))
            detail, ok = [], True
            for b in bgws:
                e1 = self._show(b["ip"], "show nve multisite dci-links"); e2 = self._show(b["ip"], "show nve multisite fabric-links")
                dci = self._walk(e1.body, "multisite_dci_link") if e1 and not isinstance(e1.body, str) else []
                fab = self._walk(e2.body, "multisite_fabric_link") if e2 and not isinstance(e2.body, str) else []
                up_d = [l["if-name"] for l in dci if l.get("if-state") == "Up"]; dn_d = [l["if-name"] for l in dci if l.get("if-state") != "Up"]
                up_f = [l["if-name"] for l in fab if l.get("if-state") == "Up"]
                if not up_d or not up_f:
                    ok = False
                detail.append(f"{b['hostname']}: dci up {up_d} down {dn_d}, fabric up {up_f}")
            # the source leaf must see the remote site's Multi-Site VIP as an NVE peer
            if src.leaf_ip:
                ev = self._show(src.leaf_ip, "show nve peers")
                peers = {p.get("peer-ip"): p.get("peer-state") for p in (self._walk(ev.body, "nve_peers") if ev and not isinstance(ev.body, str) else [])}
                vips = [p for p in peers if p.startswith("10.10.0.")]
                detail.append(f"{src.leaf} NVE peers to Multi-Site VIPs: {[(p, peers[p]) for p in vips] or 'NONE'}")
                if not any(peers[p] == "Up" for p in vips):
                    ok = False
            h.status, h.detail = ("confirmed" if ok else "refuted"), "; ".join(detail)
            h.evidence = [e.ref() for e in self._ev[-(2 * len(bgws) + 1):]]
        else:
            h.status, h.detail = "not_applicable", "same site, no border gateway on the path"
        L.hypotheses.append(h)

        # H6 ISN / DCI: every core must hold an established session to each border gateway the twin's underlay links say it is cabled to
        h = Hypothesis("H6", "inter-site network healthy (DCI links and core BGP sessions)")
        if src.fabric and dst.fabric and src.fabric != dst.fabric:
            links = self.db.query("SELECT sw1_name, sw1_if, sw2_name, sw2_if, oper_status, raw FROM links WHERE policy_type='multisiteUnderlay'")
            down = [l for l in links if str(l["oper_status"]).lower() != "up"]
            expected: dict[str, dict[str, str]] = {}          # core -> {bgw ip: bgw name}
            for l in links:
                ti = ((l["raw"] or {}).get("configData") or {}).get("templateInputs") or {}
                a_ip = str(ti.get("srcIpAddressMask") or "").split("/")[0]; b_ip = str(ti.get("dstIpAddress") or "").split("/")[0]
                for core, peer_ip, peer in ((l["sw1_name"], b_ip, l["sw2_name"]), (l["sw2_name"], a_ip, l["sw1_name"])):
                    if core and peer_ip and "core" in str(core) and "bgw" in str(peer):
                        expected.setdefault(core, {})[peer_ip] = peer
            cores = self.db.query("SELECT hostname, host(mgmt_ip) AS ip FROM switches WHERE role='core router'")
            core_detail, bad = [], False
            for c in cores:
                ev = self._show(c["ip"], "show bgp ipv4 unicast summary")
                nbrs = {n.get("neighborid"): n for n in (self._walk(ev.body, "neighbor") if ev and not isinstance(ev.body, str) else [])}
                exp = expected.get(c["hostname"], {})
                missing = [f"{ip} ({exp[ip]})" for ip in exp if ip not in nbrs or str(nbrs[ip].get("state", "")).lower() != "established"]
                stale = [ip for ip, n in nbrs.items() if ip not in exp and str(n.get("state", "")).lower() != "established"]
                if missing or not nbrs:
                    bad = True
                core_detail.append(f"{c['hostname']}: {len(exp)} expected border gateway sessions, {len(exp) - len(missing)} established" + (f", NOT established {missing}" if missing else "")
                                   + (f"; {len(stale)} neighbor(s) configured outside NDFC intent and idle {stale}" if stale else ""))
            try:
                l3 = self.nd.l3_neighbors("ISN"); nd_down = [n for n in (l3.get("neighbors") or l3.get("l3Neighbors") or []) if str(n.get("state") or n.get("status") or "").lower() not in ("established", "up")]
                core_detail.append(f"ND Analyze ISN neighbors not established: {len(nd_down)}")
            except NDError as e:
                core_detail.append(f"ND Analyze l3neighbors unavailable ({e.status})")
            h.status = "refuted" if (down or bad) else "confirmed"
            h.detail = (f"twin links down: {[(l['sw1_name'], l['sw1_if'], l['sw2_name'], l['sw2_if']) for l in down]}; " if down else f"all {len(links)} Multi-Site underlay links up in the twin; ") + "; ".join(core_detail)
            h.evidence = [f"twin links (age {L.twin_age})"] + [e.ref() for e in self._ev[-len(cores):]]
        else:
            h.status, h.detail = "not_applicable", "same site"
        L.hypotheses.append(h)

        # H7 destination learned on its leaf, port up, in the VLAN
        h = Hypothesis("H7", f"destination endpoint learned on its leaf {dst.leaf}")
        if dst.leaf_ip:
            ev = self._show(dst.leaf_ip, f"show mac address-table address {dst.mac}") if dst.mac else None
            entries = [e for e in (self._walk(ev.body, "mac_address") if ev and not isinstance(ev.body, str) else []) if not str(e.get("disp_port", "")).startswith("nve")]
            pev = self._show(dst.leaf_ip, f"show interface {dst.port}") if dst.port else None
            pif = self._walk(pev.body, "interface") if pev and not isinstance(pev.body, str) else []
            port_up = bool(pif) and pif[0].get("state") == "up" and pif[0].get("admin_state") == "up"
            vev = self._show(dst.leaf_ip, f"show vlan id {vlan}") if vlan else None
            vl = self._walk(vev.body, "vlanbriefid") if vev and not isinstance(vev.body, str) else []
            in_vlan = bool(vl) and dst.port and (dst.port in str(vl[0].get("vlanshowplist-ifidx", "")) or dst.port.replace("Ethernet", "Eth") in str(vl[0].get("vlanshowplist-ifidx", "")))
            parts = [f"mac {'learned on ' + entries[0].get('disp_port') if entries else 'NOT learned locally'}",
                     f"port {dst.port} {'up' if port_up else ('DOWN admin ' + str(pif[0].get('admin_state')) + ' oper ' + str(pif[0].get('state')) if pif else 'state unknown')}",
                     f"port {'in' if in_vlan else 'NOT in'} vlan {vlan} (members: {vl[0].get('vlanshowplist-ifidx') if vl else 'n/a'})"]
            h.status = "confirmed" if entries and port_up and in_vlan else "refuted"
            h.detail = "; ".join(parts); h.evidence = [e.ref() for e in (ev, pev, vev) if e]
        else:
            h.detail = f"destination leaf unknown ({dst.how})"
        L.hypotheses.append(h)

        # H8 VRF route (routed only)
        h = Hypothesis("H8", f"VRF route to {dst_ip} on the source leaf")
        if same_subnet:
            h.status, h.detail = "not_applicable", "same subnet, bridged"
        elif src.leaf_ip and vrf:
            ev = self._show(src.leaf_ip, f"show ip route {dst_ip} vrf {vrf}")
            pre = self._walk(ev.body, "prefix") if ev and not isinstance(ev.body, str) else []
            h.status = "confirmed" if pre else "refuted"; h.detail = f"route {pre[0].get('ipprefix') if pre else 'MISSING'} in vrf {vrf}"; h.evidence = [ev.ref()] if ev else []
        L.hypotheses.append(h)

        # H9 ACLs on the host ports
        h = Hypothesis("H9", "no access list on the host ports")
        found, evs = [], []
        for ep in (src, dst):
            if ep.leaf_ip and ep.port:
                ev = self._show(ep.leaf_ip, f"show running-config interface {ep.port}", ascii_output=True)
                if ev and isinstance(ev.body, str) and ev.body:
                    evs.append(ev.ref())
                    if re.search(r"access-group", ev.body):
                        found.append(f"{ep.leaf} {ep.port}")
        if evs:
            h.status = "refuted" if found else "confirmed"; h.detail = f"access-group present on {found}" if found else "no access-group on the host ports"; h.evidence = evs
        else:
            h.detail = "running config not retrievable over NX-API JSON-RPC ascii"
        L.hypotheses.append(h)

        # H10 data plane
        h = Hypothesis("H10", f"data plane: ping {dst_ip} from the source host, error counters on the path ports")
        parts, evs = [], []
        if with_ping and src.container:
            out = self._ping(src.container, dst_ip)
            parts.append(f"ping from {src.container}: {out}")
        for ep in (src, dst):
            if ep.leaf_ip and ep.port:
                ev = self._show(ep.leaf_ip, f"show interface {ep.port} counters errors")
                merged: dict = {}
                for r in (self._walk(ev.body, "interface") if ev and not isinstance(ev.body, str) else []):
                    merged.update({k: v for k, v in r.items() if k != "interface"})   # NX-OS returns one row per counter group
                if ev:
                    errs = {k: v for k, v in merged.items() if str(v) not in ("0", "--", "")}
                    parts.append(f"{ep.leaf} {ep.port} errors: {errs or 'none'}"); evs.append(ev.ref())
        if parts:
            m = re.search(r"(\d+) packets transmitted, (\d+) received", parts[0]) if with_ping and src.container else None
            ping_ok = (int(m.group(2)) > 0) if m else (not (with_ping and src.container))
            h.status = "confirmed" if ping_ok else "refuted"; h.detail = "; ".join(parts); h.evidence = evs
        else:
            h.detail = "no probe host and no ports known"
        L.hypotheses.append(h)

        # a silent host has no Type-2 route until it sends a frame; the H10 probe just made it talk, so re-check H3 once
        h3 = next((x for x in L.hypotheses if x.id == "H3"), None); h7 = next((x for x in L.hypotheses if x.id == "H7"), None)
        if h3 and h3.status == "refuted" and h7 and h7.status == "confirmed" and src.leaf_ip and dst.mac:
            ev = self._show(src.leaf_ip, "show l2route evpn mac all")
            hits = [r for r in (self._walk(ev.body, "l2route_mac_all") if ev and not isinstance(ev.body, str) else []) if norm_mac(r.get("mac-addr")) == dst.mac]
            if hits:
                nh = ",".join(str(n.get("nh")) for n in self._walk(hits[0], "nexthop"))
                h3.status = "confirmed"; h3.detail = f"MAC route {dst.mac} via {hits[0].get('prod-type')} next hop {nh} on the second check, after the probe made the host send traffic (absent on the first check)"
                h3.evidence.append(ev.ref())

        # conclusion: among the refuted hypotheses, the one closest to a cause names the failure domain. Access and
        # provisioning failures (H1, H7, H2, H4) explain control-plane symptoms (H3) and data-plane loss (H10), never the reverse.
        refuted = [x for x in L.hypotheses if x.status == "refuted"]
        confirmed = [x for x in L.hypotheses if x.status == "confirmed"]
        if not refuted:
            L.conclusion = f"No hypothesis refuted: {len(confirmed)} confirmed, {sum(1 for x in L.hypotheses if x.status == 'untested')} untested. The path {src_ip} -> {dst_ip} looks healthy from every vantage point checked."
            L.failure_domain = "none"
        else:
            precedence = ["H1", "H7", "H2", "H4", "H6", "H5", "H8", "H9", "H3", "H10"]
            first = sorted(refuted, key=lambda x: precedence.index(x.id) if x.id in precedence else 99)[0]
            L.failure_domain = {"H1": f"source access on {src.leaf}", "H2": "VLAN/VNI provisioning on a leaf", "H3": f"EVPN control plane into {src.leaf}",
                                "H4": "NDFC network deployment", "H5": f"border gateways of {src.fabric}", "H6": "inter-site network", "H7": f"destination access on {dst.leaf}",
                                "H8": f"routing in vrf {vrf}", "H9": "access lists", "H10": "data plane"}.get(first.id, first.id)
            others = [x.id for x in refuted if x is not first]
            L.conclusion = (f"Failure domain: {L.failure_domain}. Root hypothesis {first.id} ({first.name}): {first.detail}. "
                            f"Consequences also refuted: {others or 'none'}. Confirmed: {[x.id for x in confirmed]}.")
        L.blast_radius = self._blast_radius(net)
        self._store(L)
        return L

    def _ping(self, container: str, dst_ip: str) -> str:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", self.s.container_host,
               f"docker exec clab-multisite-{container} ping -c3 -W1 -q {dst_ip} 2>&1 | grep -E 'packets transmitted|rtt' | tr '\\n' ' '"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            return (out.stdout.strip() or out.stderr.strip() or "no output")[:200]
        except Exception as e:
            return f"probe failed: {e}"

    def _blast_radius(self, net: dict | None) -> dict:
        if not net:
            return {}
        atts = self.db.query("SELECT fabric, switch_name, state FROM attachments WHERE network=%s", (net["name"],))
        eps = self.db.query("SELECT count(*) AS n FROM endpoints WHERE vlan ILIKE %s", (f"%{net['vlan']}%",))
        return {"network": net["name"], "vrf": net["vrf"], "vni": net["vni"], "vlan": net["vlan"], "fabrics": sorted({a["fabric"] for a in atts}),
                "switches": sorted({a["switch_name"] for a in atts}), "endpoints_seen": eps[0]["n"] if eps else 0}

    def _store(self, L: Ledger) -> None:
        try:
            self.db.execute("INSERT INTO investigations (src, dst, ledger, conclusion, failure_domain) VALUES (%s,%s,%s,%s,%s)",
                            (L.src.ip, L.dst.ip, json.dumps(L.to_dict(), default=str), L.conclusion, L.failure_domain))
        except Exception:
            pass

    def evidence_bundle(self) -> list[dict]:
        return [e.to_dict() for e in self._ev]


def render(L: Ledger) -> str:
    lines = [f"Investigation {L.src.ip} -> {L.dst.ip}  (started {L.started_at}, twin age {L.twin_age})",
             f"  source: leaf {L.src.leaf} port {L.src.port} vlan {L.src.vlan} vrf {L.src.vrf} mac {L.src.mac}  [{L.src.how}]",
             f"  destination: leaf {L.dst.leaf} port {L.dst.port} vlan {L.dst.vlan} vrf {L.dst.vrf} mac {L.dst.mac}  [{L.dst.how}]", ""]
    mark = {"confirmed": "OK ", "refuted": "XX ", "untested": "?? ", "not_applicable": "-- "}
    for h in L.hypotheses:
        lines.append(f"{mark[h.status]}{h.id:<4}{h.name}")
        if h.detail:
            lines.append(f"       {h.detail}")
        for e in h.evidence:
            lines.append(f"       evidence: {e}")
    lines += ["", f"Conclusion: {L.conclusion}", f"Blast radius: {json.dumps(L.blast_radius)}"]
    return "\n".join(lines)
