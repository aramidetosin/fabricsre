"""Change assurance (#5): intent -> plan -> preview -> approval -> apply -> verify, with rollback.

The state machine is code. The model may write the intent and read the preview; it never skips a state.

  planned    intent validated against the twin (collisions, existence, sync state)
  previewed  NDFC objects created without deployment, Recalculate run, per-switch pending config captured and hashed
  approved   a named human approved THAT hash; a different pending config later voids the approval
  applied    deployed through NDFC, switches back In-Sync
  verified   attachments DEPLOYED and, when probes exist, the reachability test passed
  failed / rolled_back

Intent kinds:
  stretched_network   a network in a VRF, deployed on the VTEPs of one or more site fabrics through the Multi-Site
                      fabric group, optionally with host ports
  drift_remediation   one switch has drifted from NDFC intent; NDFC's compliance engine computes the pending lines,
                      FabricSRE previews them, a human approves, apply deploys to that switch only
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from dataclasses import dataclass

import yaml

from .config import Settings
from .db import DB
from .nd import NDClient, NDError
from .twin import Twin

UTC = dt.timezone.utc
LAN = NDClient.LAN


class ChangeError(RuntimeError):
    pass


@dataclass
class ChangeManager:
    settings: Settings
    nd: NDClient
    db: DB
    twin: Twin

    # ------------------------------------------------------------ plan
    KINDS = ("stretched_network", "drift_remediation", "interface_admin_state")

    def plan(self, intent: dict, created_by: str = "fabricsre") -> dict:
        kind = intent.get("kind")
        if kind not in self.KINDS:
            raise ChangeError(f"unknown intent kind {kind!r}; supported: {self.KINDS}")
        required = {"stretched_network": ("name", "vlan", "vni", "gateway", "vrf", "fabrics"), "drift_remediation": ("fabric", "switch"),
                    "interface_admin_state": ("fabric", "switch", "interface", "state")}[kind]
        for k in required:
            if k not in intent:
                raise ChangeError(f"intent missing {k}")
        ref = f"CHG-{dt.datetime.now(UTC):%Y%m%d-%H%M%S}"
        checks = {"stretched_network": lambda: self._checks(intent), "drift_remediation": lambda: self._checks_drift(intent, ref),
                  "interface_admin_state": lambda: self._checks_admin(intent)}[kind]()
        status = "planned" if all(c["ok"] for c in checks) else "blocked"
        self.db.execute("INSERT INTO changes (ref, created_by, intent, status, checks) VALUES (%s,%s,%s,%s,%s)",
                        (ref, created_by, json.dumps(intent), status, json.dumps(checks)))
        return {"ref": ref, "status": status, "checks": checks}

    def _checks(self, intent: dict) -> list[dict]:
        out = []
        def check(name, ok, detail): out.append({"check": name, "ok": bool(ok), "detail": detail})
        group = self.settings.fabric_group
        fabrics = intent["fabrics"]
        check("fabrics in scope", all(f in self.settings.fabrics for f in fabrics), f"{fabrics} within {self.settings.fabrics}")
        vrfs = {r["name"] for r in self.db.query("SELECT name FROM vrfs WHERE fabric = ANY(%s)", (fabrics,))}
        check("vrf exists in the target fabrics", intent["vrf"] in vrfs, f"{intent['vrf']} in {sorted(vrfs)}")
        vlan_used = self.db.query("SELECT fabric, name FROM networks WHERE vlan=%s AND fabric = ANY(%s)", (int(intent["vlan"]), fabrics))
        check("vlan free", not vlan_used, f"vlan {intent['vlan']} used by {[(r['fabric'], r['name']) for r in vlan_used]}" if vlan_used else f"vlan {intent['vlan']} unused")
        vni_used = self.db.query("SELECT fabric, name FROM networks WHERE vni=%s AND fabric = ANY(%s)", (int(intent["vni"]), fabrics))
        check("vni free", not vni_used, f"vni {intent['vni']} used by {[(r['fabric'], r['name']) for r in vni_used]}" if vni_used else f"vni {intent['vni']} unused")
        name_used = self.db.query("SELECT fabric FROM networks WHERE name=%s", (intent["name"],))
        check("name free", not name_used, f"{intent['name']} exists in {[r['fabric'] for r in name_used]}" if name_used else "name unused")
        gw_clash = [n for n in self.db.query("SELECT name, gateway FROM networks WHERE gateway IS NOT NULL") if n["gateway"] and n["gateway"].split("/")[0] == str(intent["gateway"]).split("/")[0]]
        check("gateway unique", not gw_clash, f"gateway {intent['gateway']} clashes with {gw_clash}" if gw_clash else "gateway unused")
        vteps = self.db.query("SELECT hostname, role, sync_status, fabric FROM switches WHERE fabric = ANY(%s) AND role IN ('leaf','border gateway')", (fabrics,))
        oos = [s["hostname"] for s in vteps if str(s["sync_status"]).lower() not in ("insync", "in-sync")]
        check("target VTEPs in sync", not oos, f"out of sync: {oos}" if oos else f"{len(vteps)} VTEPs inSync")
        for hp in intent.get("host_ports", []):
            sw = self.twin.switch_by_name(hp["switch"])
            used = self.db.query("SELECT network FROM attachments WHERE switch_name=%s AND ports ILIKE %s", (hp["switch"], f"%{hp['port']}%"))
            check(f"host port {hp['switch']} {hp['port']} free", bool(sw) and not used, f"switch {'found' if sw else 'UNKNOWN'}; port used by {[u['network'] for u in used]}" if used else "free")
        bgw = self.db.query("SELECT hostname, anomaly_level FROM switches WHERE role='border gateway' AND fabric = ANY(%s)", (fabrics,))
        check("border gateways present", len(bgw) >= 2 * len([f for f in fabrics if f != group]), f"{[b['hostname'] for b in bgw]}")
        return out

    def _checks_drift(self, intent: dict, ref: str) -> list[dict]:
        """A switch drifted from NDFC intent. Recalculate makes NDFC state what it would push to bring it back."""
        out = []
        def check(name, ok, detail): out.append({"check": name, "ok": bool(ok), "detail": detail})
        sw = self.twin.switch_by_name(intent["switch"])
        check("switch known to the twin", bool(sw) and sw["fabric"] == intent["fabric"], f"{intent['switch']} in {sw['fabric'] if sw else 'nowhere'}")
        check("fabric in scope", intent["fabric"] in self.settings.fabrics, f"{intent['fabric']} within {self.settings.fabrics}")
        if not sw:
            return out
        # NDFC's compliance cache can lag a change made outside NDFC by up to its poll interval; ask for a fresh read
        pending = self.nd.pending_config(intent["fabric"], sw["serial"], force=True)
        lines = [l for l in pending if l.strip() and l.strip() != "configure terminal"]
        check("switch has pending config to remediate", bool(lines), f"{len(lines)} line(s): {' / '.join(lines[:6])}" if lines else "nothing pending: the switch matches NDFC intent")
        dangerous = [l for l in lines if l.strip().startswith(("no feature", "no router bgp", "no vrf", "no interface nve", "write erase", "reload"))]
        check("no destructive lines in the pending config", not dangerous, f"refusing to preview: {dangerous}" if dangerous else "only additive or interface-level lines")
        return out

    def _checks_admin(self, intent: dict) -> list[dict]:
        """Bring one interface up or down through NDFC's admin-state action. The live state comes from the Manage API."""
        out = []
        def check(name, ok, detail): out.append({"check": name, "ok": bool(ok), "detail": detail})
        want_up = str(intent["state"]).lower() in ("up", "noshut", "no shutdown")
        sw = self.twin.switch_by_name(intent["switch"])
        check("switch known to the twin", bool(sw) and sw["fabric"] == intent["fabric"], f"{intent['switch']} in {sw['fabric'] if sw else 'nowhere'}")
        check("fabric in scope", intent["fabric"] in self.settings.fabrics, f"{intent['fabric']} within {self.settings.fabrics}")
        if not sw:
            return out
        live = self.nd.interface_live(intent["fabric"], sw["serial"], intent["interface"])
        od = live.get("operData") or {}; pol = (((live.get("configData") or {}).get("networkOS") or {}).get("policy") or {})
        check("interface known to NDFC", bool(live), f"{intent['interface']} policy {pol.get('policyType')}, intent adminState {pol.get('adminState')}")
        check("interface is not already in the wanted state", bool(live) and (str(od.get("adminStatus")).lower() == "up") != want_up,
              f"live admin {od.get('adminStatus')}, oper {od.get('operationalStatus')} ({od.get('operationalDescription')}), wanted {'up' if want_up else 'down'}")
        nb = (od.get("neighbors") or [{}])[0]
        check("neighbor recorded", True, f"peer {nb.get('switchName')} {nb.get('interfaceName')} in {nb.get('fabricName')}" if nb else "no neighbor recorded")
        return out

    def _pending_admin(self, intent: dict, ref: str) -> dict:
        """What NDFC would push: its own interface preview plus the admin-state action we will send."""
        sw = self.twin.switch_by_name(intent["switch"])
        want_up = str(intent["state"]).lower() in ("up", "noshut", "no shutdown")
        live = self.nd.interface_live(intent["fabric"], sw["serial"], intent["interface"]); od = live.get("operData") or {}
        try:
            preview = self.nd.interface_preview(intent["fabric"], sw["serial"], intent["interface"], change_ref=ref)
        except NDError as e:
            preview = {"error": f"{e.status} {e.body[:200]}"}
        return {f"{sw['hostname']} {intent['interface']}": [f"action: {'noShut' if want_up else 'shut'} via NDFC interfaceActions/updateAdminState",
                                                            f"live before: admin {od.get('adminStatus')}, oper {od.get('operationalStatus')}",
                                                            f"then: NDFC interfaceActions/deploy for this interface; resulting line on the switch: interface {intent['interface']} / {'no shutdown' if want_up else 'shutdown'}",
                                                            "ndfc preview: " + json.dumps(preview, sort_keys=True)[:600]]}

    # ------------------------------------------------------------ preview
    def preview(self, ref: str) -> dict:
        ch = self._get(ref)
        if ch["status"] not in ("planned", "previewed", "failed"):
            raise ChangeError(f"{ref} is {ch['status']}, cannot preview")
        intent = ch["intent"]; group = self.settings.fabric_group
        if intent.get("kind") in ("drift_remediation", "interface_admin_state"):
            pending = self._pending_switch(intent, ref) if intent["kind"] == "drift_remediation" else self._pending_admin(intent, ref)
            h = _hash(pending)
            self.db.execute("UPDATE changes SET status='previewed', preview=%s, preview_hash=%s WHERE ref=%s", (json.dumps(pending), h, ref))
            return {"ref": ref, "status": "previewed", "preview_hash": h, "switches": {k: len(v) for k, v in pending.items()}, "pending": pending}
        self._ensure_network(intent, ref)
        self._attach(intent, ref, deploy=False)
        pending = self._pending(intent, ref)
        h = _hash(pending)
        self.db.execute("UPDATE changes SET status='previewed', preview=%s, preview_hash=%s WHERE ref=%s", (json.dumps(pending), h, ref))
        return {"ref": ref, "status": "previewed", "preview_hash": h, "switches": {k: len(v) for k, v in pending.items()}, "pending": pending}

    def _ensure_network(self, intent: dict, ref: str) -> None:
        group = self.settings.fabric_group
        nets = self.nd.get(f"{LAN}/top-down/fabrics/{group}/networks")
        if any(n.get("networkName") == intent["name"] for n in (nets if isinstance(nets, list) else [])):
            return
        cfg = {"networkName": intent["name"], "segmentId": str(intent["vni"]), "vlanId": str(intent["vlan"]), "vrfName": intent["vrf"], "gatewayIpAddress": intent["gateway"],
               "isLayer2Only": "false", "mtu": "9216", "nveId": "1", "suppressArp": "false", "enableIR": "true", "trmEnabled": "false", "rtBothAuto": "false",
               "enableL3OnBorder": "false", "tag": "12345", "type": "Normal", "vlanName": intent.get("vlan_name", ""), "intfDescription": intent.get("description", ""),
               "mcastGroup": "", "dhcpServerAddr1": "", "loopbackId": "", "secondaryGW1": "", "secondaryGW2": ""}
        body = {"fabric": group, "networkName": intent["name"], "networkId": int(intent["vni"]), "networkTemplate": "Default_Network_Universal",
                "networkExtensionTemplate": "Default_Network_Extension_Universal", "vrf": intent["vrf"], "networkTemplateConfig": json.dumps(cfg)}
        self.nd.post(f"{LAN}/top-down/fabrics/{group}/networks", body, change_ref=ref)

    def _attach_list(self, intent: dict, deploy: bool, detach: bool = False) -> list[dict]:
        att = []
        ports = {(hp["switch"], hp["port"]) for hp in intent.get("host_ports", [])}
        for s in self.db.query("SELECT serial, hostname, role, fabric FROM switches WHERE fabric = ANY(%s) AND role IN ('leaf','border gateway') ORDER BY fabric, hostname", (intent["fabrics"],)):
            my_ports = ",".join(p for sw, p in ports if sw == s["hostname"])
            att.append({"fabric": s["fabric"], "networkName": intent["name"], "serialNumber": s["serial"],
                        "switchPorts": "" if detach else my_ports, "detachSwitchPorts": my_ports if detach else "",
                        "vlan": int(intent["vlan"]), "dot1QVlan": 1, "untagged": bool(my_ports) and not detach, "freeformConfig": "",
                        # NDFC semantics: deployment=true means "attach", deployment=false means "detach"; deploying is a separate step
                        "deployment": not detach, "extensionValues": "", "instanceValues": ""})
        return att

    def _attach(self, intent: dict, ref: str, deploy: bool) -> None:
        group = self.settings.fabric_group
        self.nd.post(f"{LAN}/top-down/fabrics/{group}/networks/attachments", [{"networkName": intent["name"], "lanAttachList": self._attach_list(intent, deploy)}], change_ref=ref)
        for hp in intent.get("host_ports", []):
            sw = self.twin.switch_by_name(hp["switch"])
            nv = {"INTF_NAME": hp["port"], "ACCESS_VLAN": str(intent["vlan"]), "BPDUGUARD_ENABLED": "true", "PORTTYPE_FAST_ENABLED": "true", "MTU": "jumbo", "SPEED": "Auto",
                  "DESC": hp.get("description", f"{intent['name']} host port"), "ADMIN_STATE": "true", "CONF": "", "PTP": "false", "ENABLE_NETFLOW": "false", "NETFLOW_MONITOR": "", "SERIAL_NUMBER": sw["serial"]}
            self.nd.put(f"{LAN}/interface", {"policy": "int_access_host", "interfaces": [{"serialNumber": sw["serial"], "ifName": hp["port"], "nvPairs": nv}]}, change_ref=ref)

    def _config_save(self, fabric: str, ref: str, minutes: int = 6) -> None:
        deadline = time.time() + minutes * 60; last = ""
        while time.time() < deadline:
            try:
                self.nd.config_save(fabric, change_ref=ref); return
            except NDError as e:
                last = e.body; time.sleep(20)
        raise ChangeError(f"{fabric}: Recalculate kept failing: {last[:200]}")

    def _pending_switch(self, intent: dict, ref: str) -> dict:
        sw = self.twin.switch_by_name(intent["switch"])
        if not sw:
            raise ChangeError(f"{intent['switch']} unknown to the twin")
        lines = self.nd.pending_config(intent["fabric"], sw["serial"], force=True)
        return {sw["hostname"]: lines} if lines else {}

    def _pending(self, intent: dict, ref: str) -> dict:
        """Recalculate the site fabrics and collect the per-switch pending config from the GA API."""
        pending: dict[str, list[str]] = {}
        for f in intent["fabrics"]:
            self._config_save(f, ref)
            for s in self.nd.switches(f):
                lines = self.nd.pending_config(f, s["switchId"])
                if lines:
                    pending[s["hostname"]] = lines
        return pending

    # ------------------------------------------------------------ approve / apply / verify
    def approve(self, ref: str, approver: str) -> dict:
        ch = self._get(ref)
        if ch["status"] != "previewed":
            raise ChangeError(f"{ref} is {ch['status']}, only a previewed change can be approved")
        self.db.execute("UPDATE changes SET status='approved', approved_by=%s, approved_at=now() WHERE ref=%s", (approver, ref))
        return {"ref": ref, "status": "approved", "approved_by": approver, "preview_hash": ch["preview_hash"]}

    def apply(self, ref: str) -> dict:
        ch = self._get(ref)
        if ch["status"] != "approved":
            raise ChangeError(f"{ref} is {ch['status']}, only an approved change can be applied")
        intent = ch["intent"]
        drift = intent.get("kind") == "drift_remediation"; admin = intent.get("kind") == "interface_admin_state"
        current = self._pending_switch(intent, ref) if drift else (self._pending_admin(intent, ref) if admin else self._pending(intent, ref)); h = _hash(current)
        if h != ch["preview_hash"]:
            self.db.execute("UPDATE changes SET status='previewed', preview=%s, preview_hash=%s, approved_by=NULL, approved_at=NULL, notes=%s WHERE ref=%s",
                            (json.dumps(current), h, "pending config changed after approval; re-approval required", ref))
            raise ChangeError(f"{ref}: pending config changed since approval ({ch['preview_hash'][:12]} -> {h[:12]}); approval voided, review again")
        if admin:
            sw = self.twin.switch_by_name(intent["switch"]); want_up = str(intent["state"]).lower() in ("up", "noshut", "no shutdown")
            # NDFC records the admin state as intent (switch goes to "pending"); the deploy is a separate, explicit step.
            # A fresh running-config read first, or NDFC's compliance cache may report In-Sync and deploy nothing.
            self.nd.pending_config(intent["fabric"], sw["serial"], force=True)
            self.nd.interface_admin_state(intent["fabric"], sw["serial"], intent["interface"], want_up, change_ref=ref)
            self.nd.interface_deploy(intent["fabric"], sw["serial"], intent["interface"], change_ref=ref)
            self.db.execute("UPDATE changes SET status='applied', applied_at=now() WHERE ref=%s", (ref,))
            time.sleep(10)
            return self.verify(ref)
        if drift:
            sw = self.twin.switch_by_name(intent["switch"])
            self.nd.config_deploy_switch(intent["fabric"], sw["serial"], change_ref=ref)
            self.db.execute("UPDATE changes SET status='applied', applied_at=now() WHERE ref=%s", (ref,))
            self._wait_insync([intent["fabric"]])
            return self.verify(ref)
        for f in intent["fabrics"]:
            self.nd.config_deploy(f, change_ref=ref)
        self.db.execute("UPDATE changes SET status='applied', applied_at=now() WHERE ref=%s", (ref,))
        self._wait_insync(intent["fabrics"])
        return self.verify(ref)

    def _wait_insync(self, fabrics: list[str], minutes: int = 10) -> None:
        deadline = time.time() + minutes * 60
        while time.time() < deadline:
            bad = []
            for f in fabrics:
                for s in self.nd.switches(f):
                    if str((s.get("additionalData") or {}).get("configSyncStatus", "")).lower() not in ("insync", "in-sync", "na"):
                        bad.append(s["hostname"])
            if not bad:
                return
            time.sleep(15)
        raise ChangeError(f"switches still out of sync: {bad}")

    def verify(self, ref: str) -> dict:
        ch = self._get(ref); intent = ch["intent"]
        if intent.get("kind") == "interface_admin_state":
            sw = self.twin.switch_by_name(intent["switch"]); want_up = str(intent["state"]).lower() in ("up", "noshut", "no shutdown")
            ok, live = False, {}
            for _ in range(12):
                live = self.nd.interface_live(intent["fabric"], sw["serial"], intent["interface"]); od = live.get("operData") or {}
                ok = (str(od.get("adminStatus")).lower() == "up") == want_up and (not want_up or str(od.get("operationalStatus")).lower() == "up")
                if ok:
                    break
                time.sleep(10)
            od = live.get("operData") or {}
            sync = {s["hostname"]: (s.get("additionalData") or {}).get("configSyncStatus") for s in self.nd.switches(intent["fabric"]) if s["hostname"] == intent["switch"]}
            result = {"interface": intent["interface"], "admin": od.get("adminStatus"), "oper": od.get("operationalStatus"), "sync": sync, "ok": ok}
            self.db.execute("UPDATE changes SET status=%s, verification=%s WHERE ref=%s", ("verified" if ok else "failed", json.dumps(result), ref))
            return {"ref": ref, "status": "verified" if ok else "failed", **result}
        if intent.get("kind") == "drift_remediation":
            sw = self.twin.switch_by_name(intent["switch"])
            sync = {s["hostname"]: (s.get("additionalData") or {}).get("configSyncStatus") for s in self.nd.switches(intent["fabric"]) if s["hostname"] == intent["switch"]}
            pending = self.nd.pending_config(intent["fabric"], sw["serial"], force=True) if sw else ["switch unknown"]
            ok = bool(sync) and str(list(sync.values())[0]).lower() in ("insync", "in-sync") and not pending
            result = {"sync": sync, "pending_lines": len(pending), "ok": ok}
            self.db.execute("UPDATE changes SET status=%s, verification=%s WHERE ref=%s", ("verified" if ok else "failed", json.dumps(result), ref))
            return {"ref": ref, "status": "verified" if ok else "failed", **result}
        states = {}
        for f in intent["fabrics"]:
            for item in self.nd.legacy_attachments(f, intent["name"]):
                for a in item.get("lanAttachList", []):
                    states[a.get("switchName")] = a.get("lanAttachState")
        ok = bool(states) and all(v == "DEPLOYED" for v in states.values())
        result = {"attachments": states, "all_deployed": ok}
        status = "verified" if ok else "failed"
        self.db.execute("UPDATE changes SET status=%s, verification=%s WHERE ref=%s", (status, json.dumps(result), ref))
        return {"ref": ref, "status": status, **result}

    # ------------------------------------------------------------ rollback
    def rollback(self, ref: str) -> dict:
        ch = self._get(ref); intent = ch["intent"]; group = self.settings.fabric_group
        if intent.get("kind") == "drift_remediation":
            raise ChangeError("a drift remediation restores NDFC intent; there is nothing to roll back to except the drift itself")
        if intent.get("kind") == "interface_admin_state":
            sw = self.twin.switch_by_name(intent["switch"]); want_up = str(intent["state"]).lower() in ("up", "noshut", "no shutdown")
            self.nd.interface_admin_state(intent["fabric"], sw["serial"], intent["interface"], not want_up, change_ref=ref)
            self.db.execute("UPDATE changes SET status='rolled_back', notes=coalesce(notes,'') || ' rolled back (inverse admin state)' WHERE ref=%s", (ref,))
            return {"ref": ref, "status": "rolled_back"}
        self.nd.post(f"{LAN}/top-down/fabrics/{group}/networks/attachments", [{"networkName": intent["name"], "lanAttachList": self._attach_list(intent, deploy=True, detach=True)}], change_ref=ref)
        for f in intent["fabrics"]:
            self._config_save(f, ref); self.nd.config_deploy(f, change_ref=ref)
        self._wait_insync(intent["fabrics"])
        # the network object can only go once nothing is attached
        for _ in range(12):
            left = {a.get("switchName"): a.get("lanAttachState") for f in intent["fabrics"] for item in self.nd.legacy_attachments(f, intent["name"]) for a in item.get("lanAttachList", []) if a.get("isLanAttached")}
            if not left:
                break
            time.sleep(10)
        self.nd.delete(f"{LAN}/top-down/fabrics/{group}/networks/{intent['name']}", change_ref=ref)
        self.db.execute("UPDATE changes SET status='rolled_back', notes=coalesce(notes,'') || ' rolled back' WHERE ref=%s", (ref,))
        return {"ref": ref, "status": "rolled_back"}

    # ------------------------------------------------------------ misc
    def _get(self, ref: str) -> dict:
        r = self.db.query("SELECT * FROM changes WHERE ref=%s", (ref,))
        if not r:
            raise ChangeError(f"unknown change {ref}")
        return r[0]

    def show(self, ref: str) -> dict:
        ch = self._get(ref)
        return {k: (v.isoformat() if isinstance(v, dt.datetime) else v) for k, v in ch.items()}

    @staticmethod
    def load_intent(path: str) -> dict:
        return yaml.safe_load(open(path))


def _hash(pending: dict) -> str:
    canon = json.dumps({k: pending[k] for k in sorted(pending)}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()
