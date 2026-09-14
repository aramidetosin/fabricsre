"""The fabric twin (#10): a timestamped cache of what Nexus Dashboard and the switches report.

Every collector writes rows with collected_at and a snapshot id. The twin is never the authority: an answer that
uses it must quote the age of the rows (see `freshness`). Sources per table are documented on each collector so a
reader can reproduce any row with one API call or one show command.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import time
from dataclasses import dataclass

import yaml

from .config import Settings
from .db import DB
from .nd import NDClient, NDError
from .nxapi import NXAPIClient, NXAPIError, rows
from .util import norm_mac, norm_if, norm_role, host_ip

UTC = dt.timezone.utc


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


@dataclass
class Twin:
    settings: Settings
    nd: NDClient
    nx: NXAPIClient
    db: DB

    # ------------------------------------------------------------ topology file (what is cabled)
    def cabled_ports(self) -> dict[str, set[str]]:
        """switch hostname -> set of NX-OS interface names that have a cable in the containerlab topology.
        containerlab ethN maps to Ethernet1/N on the N9Kv (vrnetlab), as documented in the topology file."""
        try:
            topo = yaml.safe_load(open(self.settings.topology_file))
        except FileNotFoundError:
            return {}
        out: dict[str, set[str]] = {}
        for link in (topo.get("topology", {}).get("links") or []):
            for ep in link.get("endpoints", []):
                node, _, port = ep.partition(":")
                if port.startswith("eth"):
                    out.setdefault(node, set()).add(f"Ethernet1/{port[3:]}")
        return out

    # ------------------------------------------------------------ collectors
    def refresh(self, fabrics: list[str] | None = None, with_switch_tables: bool = True) -> dict:
        fabrics = fabrics or [f for f in self.settings.fabrics]
        sid = self.db.start_snapshot("twin"); t = now(); counts: dict[str, int] = {}
        try:
            counts["fabrics"] = self._fabrics(sid, t, fabrics)
            for f in fabrics:
                if f == self.settings.fabric_group:
                    continue
                counts[f"{f}.switches"] = self._switches(sid, t, f)
                counts[f"{f}.links"] = self._links(sid, t, f)
                counts[f"{f}.vrfs"] = self._vrfs(sid, t, f)
                counts[f"{f}.networks"] = self._networks(sid, t, f)
                counts[f"{f}.attachments"] = self._attachments(sid, t, f)
                counts[f"{f}.endpoints"] = self._endpoints(sid, t, f)
                counts[f"{f}.interfaces"] = self._interfaces(sid, t, f)
            if with_switch_tables:
                counts["nve_peers"], counts["bgp_evpn"] = self._switch_tables(sid, t)
            # volatile tables only ever describe the latest snapshot; stale rows would masquerade as current state
            for table in ("endpoints",) + (("nve_peers", "bgp_evpn_neighbors") if with_switch_tables else ()):
                self.db.execute(f"DELETE FROM {table} WHERE snapshot_id IS DISTINCT FROM %s", (sid,))
            self.db.finish_snapshot(sid, "ok", json.dumps(counts))
        except Exception as e:  # keep the partial snapshot but mark it
            self.db.finish_snapshot(sid, "failed", f"{type(e).__name__}: {e}"[:500]); raise
        return {"snapshot_id": sid, "counts": counts}

    # source: GET /api/v1/manage/fabrics
    def _fabrics(self, sid, t, fabrics) -> int:
        rws = []
        for f in self.nd.fabrics():
            if f["name"] not in fabrics:
                continue
            m = f.get("management") or {}
            rws.append(dict(name=f["name"], category=f.get("category"), fabric_type=m.get("type"), bgp_asn=str(m.get("bgpAsn") or ""),
                            telemetry=bool(f.get("telemetryCollection")), license_tier=f.get("licenseTier"), raw=f, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("fabrics", rws, ["name"])

    # source: GET /api/v1/manage/fabrics/{f}/switches (+ /switches/{sid}/bgpAsn)
    def _switches(self, sid, t, fabric) -> int:
        rws = []
        for s in self.nd.switches(fabric):
            ad = s.get("additionalData") or {}
            try:
                asn = self.nd.bgp_asn(fabric, s["switchId"])
            except NDError:
                asn = ""
            rws.append(dict(serial=s["serialNumber"], fabric=fabric, hostname=s["hostname"], mgmt_ip=host_ip(s.get("fabricManagementIp")),
                            role=norm_role(s.get("switchRole")), model=s.get("model"), version=s.get("softwareVersion"), bgp_asn=asn,
                            sync_status=ad.get("configSyncStatus"), discovery_status=ad.get("discoveryStatus"), anomaly_level=s.get("anomalyLevel"),
                            uptime_s=_uptime_s(s.get("systemUpTime")), vpc=bool(s.get("vpcConfigured")), raw=s, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("switches", rws, ["serial"])

    # source: GET /api/v1/manage/links?fabricName=
    def _links(self, sid, t, fabric) -> int:
        rws = []
        for l in self.nd.links(fabric):
            cd = l.get("configData") or {}
            rws.append(dict(link_id=str(l.get("linkId")), fabric=fabric, policy_type=cd.get("policyType"), template=l.get("displayName") or cd.get("policyType"),
                            sw1_serial=l.get("srcSwitchId"), sw1_name=l.get("srcSwitchName"), sw1_if=norm_if(l.get("srcInterfaceName")),
                            sw2_serial=l.get("dstSwitchId"), sw2_name=l.get("dstSwitchName"), sw2_if=norm_if(l.get("dstInterfaceName")),
                            admin_status=l.get("aggregatedAdminStatus"), oper_status=l.get("aggregatedOperStatus") or l.get("linkState"), raw=l, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("links", rws, ["link_id"])

    # source: GET /api/v1/manage/fabrics/{f}/vrfs
    def _vrfs(self, sid, t, fabric) -> int:
        rws = [dict(fabric=fabric, name=v.get("vrfName") or v.get("name"), vni=v.get("vrfId"), status=v.get("vrfStatus") or v.get("status"),
                    raw=v, collected_at=t, snapshot_id=sid) for v in self.nd.vrfs(fabric)]
        return self.db.upsert_many("vrfs", rws, ["fabric", "name"])

    # source: GET /api/v1/manage/fabrics/{f}/networks
    def _networks(self, sid, t, fabric) -> int:
        rws = []
        for n in self.nd.networks(fabric):
            l3 = n.get("l3Data") or {}; l2 = n.get("l2Data") or {}
            rws.append(dict(fabric=fabric, name=n.get("networkName"), vrf=n.get("vrfName") or l3.get("vrfName"), vni=n.get("networkId") or n.get("vni"),
                            vlan=n.get("vlanId") or l2.get("vlanId"), gateway=l3.get("gatewayIpv4Address") or l3.get("gatewayIp"), status=n.get("networkStatus") or n.get("status"),
                            raw=n, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("networks", rws, ["fabric", "name"])

    # source (still legacy on 12.6): GET /top-down/fabrics/{f}/networks/attachments?network-names=
    def _attachments(self, sid, t, fabric) -> int:
        rws = []
        names = [r["name"] for r in self.db.query("SELECT name FROM networks WHERE fabric=%s", (fabric,))]
        for net in names:
            try:
                data = self.nd.legacy_attachments(fabric, net)
            except NDError:
                continue
            for item in data if isinstance(data, list) else []:
                for a in item.get("lanAttachList", []):
                    rws.append(dict(fabric=fabric, network=net, serial=a.get("switchSerialNo"), switch_name=a.get("switchName"),
                                    state=a.get("lanAttachState"), ports=a.get("portNames") or "", vlan=_int(a.get("vlanId")), raw=a, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("attachments", rws, ["fabric", "network", "serial"])

    # source: GET /api/v1/analyze/connectivity/endpoints?fabricName=   (telemetry must be on)
    def _endpoints(self, sid, t, fabric) -> int:
        rws = []
        try:
            eps = self.nd.endpoints(fabric)
        except NDError:
            eps = []
        for e in eps:
            mac = norm_mac(e.get("mac"))
            if not mac:
                continue
            ips = list(e.get("ipCollection") or []) or [a.get("ip") for a in (e.get("ipAttributes") or []) if isinstance(a, dict)] or [""]
            nodes = e.get("nodeNames") or [""]; ifs = e.get("interfaceNames") or [""]
            for ip in ips:
                rws.append(dict(fabric=fabric, ip=ip or "", mac=mac, vlan=re.sub(r"(?i)^vlan", "", str(e.get("encapsulation") or "")), vrf=e.get("vrfName") or e.get("vrf"),
                                switch_name=nodes[0] or "", interface=norm_if(ifs[0]) if ifs[0] else None, source="nd-analyze", raw=e, collected_at=t, snapshot_id=sid))
        return self.db.upsert_many("endpoints", rws, ["fabric", "mac", "source", "ip", "switch_name"]) if rws else 0

    # source: GET /api/v1/manage/fabrics/{f}/switches/{sid}/interfaces
    def _interfaces(self, sid, t, fabric) -> int:
        rws = []
        for s in self.db.query("SELECT serial FROM switches WHERE fabric=%s", (fabric,)):
            for i in self.nd.switch_interfaces(fabric, s["serial"]):
                od = i.get("operData") or {}; cd = i.get("configData") or {}; pol = ((cd.get("networkOS") or {}).get("policy") or {})
                nb = (od.get("neighbors") or [{}])[0]
                rws.append(dict(serial=s["serial"], name=norm_if(i.get("interfaceName")), fabric=fabric,
                                admin_up=_tri(pol.get("adminState"), od.get("adminStatus")), oper_up=_tri(None, od.get("operationalStatus")),
                                mode=od.get("mode") or cd.get("mode"), access_vlan=str(pol.get("accessVlan") or ""), allowed_vlans=str(pol.get("allowedVlans") or od.get("vlanRange") or ""),
                                description=pol.get("description"), ipv4=od.get("ipAddress") or pol.get("ipv4Address"),
                                policy=pol.get("policyType"), compliance=od.get("operationalDescription"),
                                anomaly_level=i.get("anomalyLevel"), neighbor_switch=nb.get("switchName"), neighbor_port=norm_if(nb.get("interfaceName")) or None,
                                raw=i, collected_at=t, snapshot_id=sid))
        rws = [r for r in rws if r["name"]]
        return self.db.upsert_many("interfaces", rws, ["serial", "name"])

    # source: NX-API `show nve peers`, `show bgp l2vpn evpn summary` on every VTEP and spine
    def _switch_tables(self, sid, t) -> tuple[int, int]:
        peers, nbrs = [], []
        for s in self.db.query("SELECT serial, hostname, host(mgmt_ip) AS ip, role FROM switches WHERE role <> 'core router'"):
            try:
                ev = self.nx.show(s["ip"], "show nve peers")
                for r in rows(ev.body, "TABLE_nve_peers", "ROW_nve_peers"):
                    peers.append(dict(serial=s["serial"], hostname=s["hostname"], peer_ip=r.get("peer-ip"), state=r.get("peer-state"), learn_type=r.get("learn-type"),
                                      uptime=r.get("uptime"), router_mac=r.get("router-mac"), collected_at=t, snapshot_id=sid))
            except NXAPIError:
                pass
            try:
                ev = self.nx.show(s["ip"], "show bgp l2vpn evpn summary")
                for vrf in rows(ev.body, "TABLE_vrf", "ROW_vrf"):
                    for af in rows(vrf, "TABLE_af", "ROW_af"):
                        for saf in rows(af, "TABLE_saf", "ROW_saf"):
                            for n in rows(saf, "TABLE_neighbor", "ROW_neighbor"):
                                nbrs.append(dict(serial=s["serial"], hostname=s["hostname"], neighbor=n.get("neighborid"), remote_as=str(n.get("neighboras")),
                                                 state=n.get("state"), up_down=n.get("time"), prefixes=_int(n.get("prefixreceived")), collected_at=t, snapshot_id=sid))
            except NXAPIError:
                pass
        return self.db.upsert_many("nve_peers", peers, ["serial", "peer_ip"]), self.db.upsert_many("bgp_evpn_neighbors", nbrs, ["serial", "neighbor"])

    # ------------------------------------------------------------ queries used by the other agents
    def freshness(self) -> dict:
        r = self.db.query("SELECT scope, status, started_at, finished_at, notes FROM snapshots WHERE scope='twin' ORDER BY id DESC LIMIT 1")
        return r[0] if r else {}

    def switch_by_name(self, name: str) -> dict | None:
        r = self.db.query("SELECT serial, fabric, hostname, host(mgmt_ip) AS ip, role, bgp_asn, sync_status, collected_at FROM switches WHERE hostname=%s", (name,))
        return r[0] if r else None

    def find_endpoint(self, ip: str | None = None, mac: str | None = None) -> list[dict]:
        if ip:
            return self.db.query("SELECT * FROM endpoints WHERE ip=%s AND switch_name <> '' ORDER BY collected_at DESC", (ip,))
        return self.db.query("SELECT * FROM endpoints WHERE mac=%s ORDER BY collected_at DESC", ((mac or "").lower(),))

    def uncabled_up_ports(self) -> list[dict]:
        """Interfaces that are admin up but have no cable in the topology: the source of the unconnected-port anomalies."""
        cabled = self.cabled_ports(); out = []
        for i in self.db.query("SELECT i.serial, s.hostname, i.name, i.admin_up, i.oper_up FROM interfaces i JOIN switches s USING (serial) WHERE i.name LIKE 'Ethernet%%'"):
            if i["admin_up"] and i["name"] not in cabled.get(i["hostname"], set()):
                out.append(i)
        return out


def _uptime_s(v) -> int | None:
    # Manage reports systemUpTime like "0 days, 3 hours, 12 minutes" or seconds; accept both
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    import re
    m = re.search(r"(\d+) days?, (\d+) hours?, (\d+) minutes?", str(v))
    return int(m.group(1)) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 if m else None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _tri(a, b):
    for v in (a, b):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("up", "true", "1", "enabled")
    return None
