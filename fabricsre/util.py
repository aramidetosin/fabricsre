"""Small normalisers shared by the collectors and the investigator."""
from __future__ import annotations

import re


def norm_mac(mac: str | None) -> str:
    """Any MAC notation -> NX-OS dotted lowercase (aac1.ab85.ab21), the form the switch tables use."""
    if not mac:
        return ""
    h = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}" if len(h) == 12 else mac.lower()


def norm_if(name: str | None) -> str:
    """eth1/3, Eth1/3, ethernet1/3 -> Ethernet1/3; Vlan/port-channel names pass through with NX-OS capitalisation."""
    if not name:
        return ""
    n = name.strip()
    m = re.match(r"^(?:eth|ethernet)(\d+/\d+(?:/\d+)?)$", n, re.I)
    if m:
        return f"Ethernet{m.group(1)}"
    m = re.match(r"^(?:po|port-channel)(\d+)$", n, re.I)
    if m:
        return f"port-channel{m.group(1)}"
    m = re.match(r"^vlan(\d+)$", n, re.I)
    if m:
        return f"Vlan{m.group(1)}"
    return n


def norm_role(role: str | None) -> str:
    """Manage API roles are camelCase (borderGateway, coreRouter); the legacy API and NDFC screens use spaced lower case."""
    if not role:
        return ""
    return re.sub(r"(?<!^)(?=[A-Z])", " ", role).lower().strip()


def host_ip(v: str | None) -> str | None:
    return v.split("/")[0] if v else None
