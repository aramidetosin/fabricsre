"""Read-only NX-API access to the switches (JSON-RPC over HTTPS).

The forwarding-plane evidence for investigations comes from here: MAC and ARP tables, l2route, NVE peers and
VNIs, BGP EVPN routes, interface counters. Only commands on the allowlist are sent, and only `show` commands.
Every result is wrapped as Evidence: device, command, timestamp and a hash of the raw payload, so a finding can
always be traced back to the exact output that produced it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any

from .config import Settings

ALLOWED_PREFIXES = (
    "show mac address-table", "show ip arp", "show l2route", "show nve", "show bgp l2vpn evpn", "show bgp ipv4 unicast",
    "show ip route", "show ip bgp", "show interface", "show vlan", "show running-config interface", "show running-config bgp",
    "show system uptime", "show version", "show lldp neighbors", "show ip interface", "show vrf", "show port-channel summary",
    "show vpc", "show logging last", "show accounting log", "show forwarding", "show ip adjacency", "show telemetry",
    "show feature", "show fabric forwarding", "show evpn", "show hardware", "show module", "show clock",
)


class NXAPIError(RuntimeError):
    pass


@dataclass
class Evidence:
    device: str
    command: str
    collected_at: float
    sha256: str
    body: Any  # parsed NX-OS JSON table, or a string for ascii output

    def ref(self) -> str:
        return f"{self.device} `{self.command}` @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.collected_at))} sha256:{self.sha256[:12]}"

    def to_dict(self) -> dict:
        d = asdict(self); d["collected_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.collected_at)); return d


class NXAPIClient:
    def __init__(self, settings: Settings, timeout: int = 60):
        self.settings, self.timeout = settings, timeout
        self._ctx = ssl.create_default_context(); self._ctx.check_hostname = False; self._ctx.verify_mode = ssl.CERT_NONE
        self._auth = "Basic " + base64.b64encode(f"{settings.nx_user}:{settings.nx_password}".encode()).decode()

    @staticmethod
    def _check(cmd: str) -> None:
        c = " ".join(cmd.split())
        if not c.startswith("show ") or not c.startswith(ALLOWED_PREFIXES):
            raise NXAPIError(f"command not on the read-only allowlist: {cmd!r}")
        if any(tok in c for tok in (";", "|", "conf", "clear", "reload", "write", "copy", "delete")):
            # pipes are fine on the CLI, but the JSON output is what we parse; keep commands plain
            if "|" in c:
                raise NXAPIError(f"pipes are not allowed, filter in code instead: {cmd!r}")
            raise NXAPIError(f"command rejected: {cmd!r}")

    def show(self, device: str, cmd: str, ascii_output: bool = False) -> Evidence:
        self._check(cmd)
        method = "cli_ascii" if ascii_output else "cli"
        payload = [{"jsonrpc": "2.0", "method": method, "params": {"cmd": cmd, "version": 1}, "id": 1}]
        req = urllib.request.Request(f"https://{device}/ins", data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json-rpc", "Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise NXAPIError(f"{device} HTTP {e.code} for {cmd!r}: {e.read()[:200]!r}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise NXAPIError(f"{device} unreachable for {cmd!r}: {e}") from e
        data = json.loads(raw)
        item = data[0] if isinstance(data, list) else data      # single call: NX-API returns a dict, not a list
        if "error" in item:
            raise NXAPIError(f"{device} {cmd!r}: {item['error']}")
        body = (item.get("result") or {}).get("body", "" if ascii_output else {})
        if ascii_output and isinstance(body, dict):
            body = body.get("msg", "")
        return Evidence(device, cmd, time.time(), hashlib.sha256(raw).hexdigest(), body)

    def show_many(self, device: str, cmds: list[str]) -> dict[str, Evidence]:
        return {c: self.show(device, c) for c in cmds}


def rows(table: Any, table_key: str, row_key: str) -> list[dict]:
    """NX-OS JSON tables come as TABLE_x/ROW_x, with ROW_x being a dict for one row or a list for many."""
    if not isinstance(table, dict):
        return []
    t = table.get(table_key)
    if t is None:
        return []
    r = t.get(row_key) if isinstance(t, dict) else None
    if r is None:
        return []
    return r if isinstance(r, list) else [r]
