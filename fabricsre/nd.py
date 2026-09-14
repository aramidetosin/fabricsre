"""Nexus Dashboard client for FabricSRE.

One thin, boring HTTP layer over the Nexus Dashboard 4.3.1 GA API groups (Manage, Analyze, Infra) with the
legacy NDFC paths kept only where the GA surface has no equivalent yet (per-switch policies, discovery,
config-save/deploy used by the fabric build script, the Insights anomaly feed).

Design rules
- Reads and writes are separate methods. Every write requires a `change_ref` and is refused without one.
- Every call is recorded in the audit table (who, what, status, duration) when a database handle is given.
- Nothing here reasons. It fetches, validates status codes, and returns parsed JSON.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import Settings


class NDError(RuntimeError):
    def __init__(self, status: int | str, path: str, body: str):
        super().__init__(f"ND {status} {path}: {body[:300]}")
        self.status, self.path, self.body = status, path, body


class WriteRefused(PermissionError):
    """Raised when a write is attempted without a change reference."""


@dataclass
class CallRecord:
    ts: float
    method: str
    path: str
    status: int | str
    ms: int
    change_ref: Optional[str] = None
    note: str = ""


@dataclass
class NDClient:
    settings: Settings
    audit_sink: Any = None  # object with .record(CallRecord) or None
    _token: Optional[str] = field(default=None, init=False, repr=False)
    _token_ts: float = field(default=0.0, init=False, repr=False)
    _ctx: ssl.SSLContext = field(default_factory=lambda: _insecure_ctx(), init=False, repr=False)

    # ---------------------------------------------------------------- auth
    def login(self) -> str:
        body = {"userName": self.settings.nd_user, "userPasswd": self.settings.nd_password, "domain": self.settings.nd_domain}
        status, data = self._raw("POST", "/login", body, auth=False)
        if status != 200 or not isinstance(data, dict) or "jwttoken" not in data:
            raise NDError(status, "/login", json.dumps(data)[:300])
        self._token, self._token_ts = data["jwttoken"], time.time()
        return self._token

    def _headers(self) -> dict:
        if not self._token or time.time() - self._token_ts > self.settings.nd_token_ttl_s:
            self.login()
        return {"Authorization": f"Bearer {self._token}", "Cookie": f"AuthCookie={self._token}", "Content-Type": "application/json"}

    # ---------------------------------------------------------------- transport
    def _raw(self, method: str, path: str, body: Any = None, auth: bool = True, timeout: int = 60, form: bool = False):
        headers = self._headers() if auth else {"Content-Type": "application/json"}
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
        req = urllib.request.Request(self.settings.nd_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, _parse(raw)
        except urllib.error.HTTPError as e:
            return e.code, _parse(e.read())

    def _call(self, method: str, path: str, body: Any = None, *, change_ref: Optional[str] = None, timeout: int = 60,
              form: bool = False, retries: int = 2, ok=(200, 201, 202, 207)) -> Any:   # 207: NDFC multi-status previews
        if method != "GET" and not change_ref:
            raise WriteRefused(f"{method} {path} refused: no change_ref")
        t0 = time.time(); status: int | str = "ERR"; data: Any = None
        for attempt in range(retries + 1):
            try:
                status, data = self._raw(method, path, body, timeout=timeout, form=form)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                status, data = "ERR", str(e)
            if status == 401 and attempt < retries:
                self.login(); continue
            if isinstance(status, int) and status >= 500 and attempt < retries:
                time.sleep(2 + 3 * attempt); continue
            break
        ms = int((time.time() - t0) * 1000)
        if self.audit_sink is not None:
            try:
                self.audit_sink.record(CallRecord(time.time(), method, path, status, ms, change_ref))
            except Exception:  # auditing must never break the call path
                pass
        if status not in ok:
            raise NDError(status, path, data if isinstance(data, str) else json.dumps(data))
        return data

    # ---------------------------------------------------------------- GA reads
    def get(self, path: str, **query) -> Any:
        q = {k: v for k, v in query.items() if v is not None}
        return self._call("GET", path + ("?" + urllib.parse.urlencode(q) if q else ""))

    def get_all(self, path: str, key: str, page: int = 200, **query) -> list:
        """Follow the Manage/Analyze offset+max pagination until the meta.counts.remaining is 0."""
        items: list = []; offset = 0
        while True:
            data = self.get(path, max=page, offset=offset, **query)
            chunk = data.get(key, []) if isinstance(data, dict) else []
            items.extend(chunk)
            remaining = ((data.get("meta") or {}).get("counts") or {}).get("remaining", 0) if isinstance(data, dict) else 0
            if not chunk or not remaining:
                return items
            offset += len(chunk)

    # Manage
    def fabrics(self) -> list: return self.get("/api/v1/manage/fabrics").get("fabrics", [])
    def fabric(self, name: str) -> dict: return self.get(f"/api/v1/manage/fabrics/{name}")
    def switches(self, fabric: str) -> list: return self.get_all(f"/api/v1/manage/fabrics/{fabric}/switches", "switches")
    def switch_interfaces(self, fabric: str, switch_id: str) -> list:
        return self.get_all(f"/api/v1/manage/fabrics/{fabric}/switches/{switch_id}/interfaces", "interfaces")
    def links(self, fabric: str) -> list: return self.get_all("/api/v1/manage/links", "links", fabricName=fabric)
    def networks(self, fabric: str) -> list: return self.get_all(f"/api/v1/manage/fabrics/{fabric}/networks", "networks")
    def vrfs(self, fabric: str) -> list: return self.get_all(f"/api/v1/manage/fabrics/{fabric}/vrfs", "vrfs")
    def pending_config(self, fabric: str, switch_id: str, force: bool = False) -> list:
        """force=True makes NDFC re-read the running config from the switch instead of using its compliance cache."""
        return self.get(f"/api/v1/manage/fabrics/{fabric}/switches/{switch_id}/pendingConfig", forceShowRun="true" if force else None).get("pendingConfigs", [])
    def diff(self, fabric: str, switch_id: str, force: bool = False) -> list:
        return self.get(f"/api/v1/manage/fabrics/{fabric}/switches/{switch_id}/diff", forceShowRun="true" if force else None).get("diffConfigs", [])
    def fabric_preview(self, fabric: str) -> list:
        return self.get(f"/api/v1/manage/fabrics/{fabric}/actions/preview").get("items", [])
    def bgp_asn(self, fabric: str, switch_id: str) -> str:
        return str(self.get(f"/api/v1/manage/fabrics/{fabric}/switches/{switch_id}/bgpAsn").get("bgpAsn", ""))
    def deployment_history(self, fabric: str, max_records: int = 500) -> list:
        return self.get(f"/api/v1/manage/fabrics/{fabric}/deploymentHistory", max=max_records).get("deploymentRecords", [])
    def policy_history(self, fabric: str, max_records: int = 500) -> list:
        return self.get(f"/api/v1/manage/fabrics/{fabric}/policyHistory", max=max_records).get("policies", [])
    def post_processing_rules(self) -> list:
        return self.get("/api/v1/manage/anomalyRules/postProcessingRules").get("rules", []) or []

    # Analyze
    def anomalies(self, fabric: Optional[str] = None, max_records: int = 500, **query) -> list:
        return self.get("/api/v1/analyze/anomalies/details", fabricName=fabric, max=max_records, **query).get("anomalies", [])
    def anomaly_summary(self, fabric: str) -> dict: return self.get("/api/v1/analyze/anomalies/summary", fabricName=fabric)
    def root_events(self, fabric: str, max_records: int = 100) -> list:
        return self.get("/api/v1/analyze/alerts/rootcause/rootEvents", fabricName=fabric, max=max_records).get("events", [])
    def events(self, max_records: int = 500, **query) -> list:
        return self.get("/api/v1/analyze/eventManagement/events", max=max_records, **query).get("events", [])
    def endpoints(self, fabric: str) -> list:
        return self.get_all("/api/v1/analyze/connectivity/endpoints", "endpoints", fabricName=fabric)
    def l3_neighbors(self, fabric: str) -> dict: return self.get("/api/v1/analyze/connectivity/l3neighbors/details", fabricName=fabric)
    def interfaces_state(self, fabric: str) -> list:
        return self.get_all("/api/v1/analyze/interfaces", "interfaces", fabricName=fabric)
    def telemetry_status(self, fabric: str) -> dict: return self.get("/api/v1/analyze/telemetry/statusOverview", fabricName=fabric)
    def inter_fabrics(self) -> Any: return self.get("/api/v1/analyze/interFabrics/detail")

    # Infra
    def audit_records(self, max_records: int = 500, **query) -> list:
        return self.get("/api/v1/infra/auditRecords", max=max_records, **query).get("auditRecords", [])
    def fabric_audit_records(self, fabric: str, max_records: int = 500) -> list:
        return self.get("/api/v1/infra/fabricAuditRecords", fabricName=fabric, max=max_records).get("auditRecords", [])
    def about(self) -> dict: return self.get("/api/v1/infra/about")

    # ---------------------------------------------------------------- legacy reads still needed on 12.6
    LAN = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest"
    def legacy_inventory(self, fabric: str) -> list: return self.get(f"{self.LAN}/control/fabrics/{fabric}/inventory/switchesByFabric")
    def legacy_attachments(self, fabric: str, network: str) -> list:
        return self.get(f"{self.LAN}/top-down/fabrics/{fabric}/networks/attachments", **{"network-names": network})
    def legacy_switch_policies(self, serial: str) -> list: return self.get(f"{self.LAN}/control/policies/switches/{serial}/SWITCH/SWITCH")

    # ---------------------------------------------------------------- writes (all gated by change_ref)
    def put(self, path: str, body: Any, *, change_ref: str, timeout: int = 120) -> Any:
        return self._call("PUT", path, body, change_ref=change_ref, timeout=timeout)
    def post(self, path: str, body: Any = None, *, change_ref: str, timeout: int = 900, form: bool = False) -> Any:
        return self._call("POST", path, body if body is not None else {}, change_ref=change_ref, timeout=timeout, form=form)
    def delete(self, path: str, *, change_ref: str) -> Any:
        return self._call("DELETE", path, change_ref=change_ref, ok=(200, 201, 202, 204))

    def config_save(self, fabric: str, *, change_ref: str) -> Any:
        return self.post(f"{self.LAN}/control/fabrics/{fabric}/config-save", {}, change_ref=change_ref)
    def interface_preview(self, fabric: str, serial: str, ifname: str, *, change_ref: str) -> Any:
        return self.post(f"/api/v1/manage/fabrics/{fabric}/interfaceActions/preview", {"interfaces": [{"interfaceName": ifname, "switchId": serial}]}, change_ref=change_ref, timeout=120)
    def interface_admin_state(self, fabric: str, serial: str, ifname: str, up: bool, *, change_ref: str) -> Any:
        return self.post(f"/api/v1/manage/fabrics/{fabric}/interfaceActions/updateAdminState",
                         {"interfaces": [{"adminState": "noShut" if up else "shut", "interfaceName": ifname, "switchId": serial}]}, change_ref=change_ref, timeout=300)
    def interface_deploy(self, fabric: str, serial: str, ifname: str, *, change_ref: str) -> Any:
        return self.post(f"/api/v1/manage/fabrics/{fabric}/interfaceActions/deploy", {"interfaces": [{"interfaceName": ifname, "switchId": serial}]}, change_ref=change_ref, timeout=600)
    def interface_live(self, fabric: str, serial: str, ifname: str) -> dict:
        for i in self.switch_interfaces(fabric, serial):
            if i.get("interfaceName") == ifname:
                return i
        return {}
    def config_deploy_switch(self, fabric: str, serial: str, *, change_ref: str) -> Any:
        return self.post(f"{self.LAN}/control/fabrics/{fabric}/config-deploy/{serial}", {}, change_ref=change_ref)
    def config_deploy(self, fabric: str, *, change_ref: str, all_msd: bool = False) -> Any:
        suffix = "?inclAllMSDSwitches=true" if all_msd else ""
        return self.post(f"{self.LAN}/control/fabrics/{fabric}/config-deploy{suffix}", {}, change_ref=change_ref)


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse(raw: bytes) -> Any:
    s = raw.strip()
    if s[:1] in (b"{", b"["):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass
    return raw.decode(errors="replace")
