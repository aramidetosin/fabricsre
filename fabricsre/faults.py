"""Fault injection library for test fabrics. This is the evaluation harness for the investigator and the triage.

Every fault knows how to inject, how to restore, and which hypothesis in the investigation ledger it is expected
to refute. Faults touch the switches directly over NX-API configuration commands, which the read-only client
refuses by design, so this module carries its own guarded config path:
  - FABRICSRE_ALLOW_FAULTS=1 must be set in the environment,
  - the target must be a switch known to the twin,
  - every injection is written to the timeline as source "fabricsre".
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import ssl
import time
import urllib.request
from dataclasses import dataclass

from .config import Settings
from .db import DB

UTC = dt.timezone.utc


class FaultRefused(PermissionError):
    pass


@dataclass
class Fault:
    name: str
    description: str
    device: str            # hostname
    inject_cmds: list[str]
    restore_cmds: list[str]
    expected_refuted: list[str]   # hypothesis ids the investigator must refute while the fault is active
    expected_titles: list[str]    # ND anomaly titles expected to appear


def catalog(settings: Settings) -> dict[str, Fault]:
    """Faults for the two-site reference fabric. Interface names follow the topology file."""
    return {
        "dci_link_down": Fault("dci_link_down", "Shut the DCI link dc1-bgw1 Eth1/3 to core1. Half the DC1 Multi-Site underlay is gone.",
                               "dc1-bgw1", ["interface Ethernet1/3", "shutdown"], ["interface Ethernet1/3", "no shutdown"],
                               ["H6"], ["BGP_PEER_CONNECTION_DOWN"]),
        "dci_both_down": Fault("dci_both_down", "Shut both DCI links of dc1-bgw1 (Eth1/3 and Eth1/4). dc1-bgw1 loses the ISN entirely.",
                               "dc1-bgw1", ["interface Ethernet1/3-4", "shutdown"], ["interface Ethernet1/3-4", "no shutdown"],
                               ["H6", "H5"], ["BGP_PEER_CONNECTION_DOWN"]),
        "host_port_down": Fault("host_port_down", "Shut the host port dc2-leaf1 Eth1/3 (dc2-host1).",
                                "dc2-leaf1", ["interface Ethernet1/3", "shutdown"], ["interface Ethernet1/3", "no shutdown"],
                                ["H7"], []),
        "host_port_wrong_vlan": Fault("host_port_wrong_vlan", "Move dc2-leaf1 Eth1/3 to access VLAN 2301: the host is up but in the wrong broadcast domain.",
                                      "dc2-leaf1", ["vlan 2301", "interface Ethernet1/3", "switchport access vlan 2301"],
                                      ["interface Ethernet1/3", "switchport access vlan 2300", "no vlan 2301"],
                                      ["H7", "H2"], []),
        "nve_down": Fault("nve_down", "Shut nve1 on dc1-leaf2: the leaf stops being a VTEP.",
                          "dc1-leaf2", ["interface nve1", "shutdown"], ["interface nve1", "no shutdown"],
                          ["H2", "H3"], []),
    }


class FaultInjector:
    def __init__(self, settings: Settings, db: DB | None = None):
        self.settings, self.db = settings, db
        self._ctx = ssl.create_default_context(); self._ctx.check_hostname = False; self._ctx.verify_mode = ssl.CERT_NONE
        self._auth = "Basic " + base64.b64encode(f"{settings.nx_user}:{settings.nx_password}".encode()).decode()

    def _guard(self, fault: Fault) -> str:
        if os.environ.get("FABRICSRE_ALLOW_FAULTS") != "1":
            raise FaultRefused("set FABRICSRE_ALLOW_FAULTS=1 to inject faults (test fabrics only)")
        ip = self._ip(fault.device)
        if not ip:
            raise FaultRefused(f"{fault.device} is not a switch known to the twin")
        return ip

    def _ip(self, hostname: str) -> str | None:
        if self.db is None:
            return None
        r = self.db.query("SELECT host(mgmt_ip) AS ip FROM switches WHERE hostname=%s", (hostname,))
        return r[0]["ip"] if r else None

    def _config(self, ip: str, cmds: list[str]) -> list:
        payload = [{"jsonrpc": "2.0", "method": "cli", "params": {"cmd": c, "version": 1}, "id": i + 1} for i, c in enumerate(["configure terminal"] + cmds)]
        req = urllib.request.Request(f"https://{ip}/ins", data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json-rpc", "Authorization": self._auth})
        with urllib.request.urlopen(req, context=self._ctx, timeout=90) as resp:
            data = json.loads(resp.read())
        data = data if isinstance(data, list) else [data]
        errors = [d.get("error") for d in data if d.get("error")]
        if errors:
            raise RuntimeError(f"config on {ip} failed: {errors}")
        return data

    def _log(self, fault: Fault, action: str) -> None:
        if self.db is None:
            return
        line = f"fabricsre {action} fault {fault.name} on {fault.device}: {'; '.join(fault.inject_cmds if action == 'injected' else fault.restore_cmds)}"
        self.db.add_timeline([dict(ts=dt.datetime.now(UTC), source="fabricsre", fabric=None, device=fault.device, actor="fabricsre", kind=f"fault-{action}",
                                   severity="warning" if action == "injected" else "info", summary=line, ref=fault.name, raw=None,
                                   fingerprint=hashlib.sha256(f"{line}{time.time()}".encode()).hexdigest())])

    def inject(self, fault: Fault) -> dict:
        ip = self._guard(fault); self._config(ip, fault.inject_cmds); self._log(fault, "injected")
        return {"fault": fault.name, "device": fault.device, "injected_at": dt.datetime.now(UTC).isoformat(), "expected_refuted": fault.expected_refuted}

    def restore(self, fault: Fault) -> dict:
        ip = self._guard(fault); self._config(ip, fault.restore_cmds); self._log(fault, "restored")
        return {"fault": fault.name, "device": fault.device, "restored_at": dt.datetime.now(UTC).isoformat()}
