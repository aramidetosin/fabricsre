"""Settings for FabricSRE. Everything comes from environment variables (or a .env file loaded by the caller).
No credential is ever written to a log, a database row, or a tool result."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit(f"missing required environment variable {name}")
    return val or ""


@dataclass
class Settings:
    nd_url: str = field(default_factory=lambda: _env("FABRICSRE_ND_URL", "https://10.80.15.232").rstrip("/"))
    nd_user: str = field(default_factory=lambda: _env("FABRICSRE_ND_USER", "admin"))
    nd_password: str = field(default_factory=lambda: _env("FABRICSRE_ND_PASSWORD", required=True))
    nd_domain: str = field(default_factory=lambda: _env("FABRICSRE_ND_DOMAIN", "local"))
    nd_token_ttl_s: int = 20 * 60
    # read-only switch access for NX-API show commands
    nx_user: str = field(default_factory=lambda: _env("FABRICSRE_NX_USER", "admin"))
    nx_password: str = field(default_factory=lambda: _env("FABRICSRE_NX_PASSWORD", required=True))
    # database: postgresql://user:pass@host/db
    db_url: str = field(default_factory=lambda: _env("FABRICSRE_DB_URL", "postgresql:///fabricsre"))
    # fabrics in scope, comma separated; the agent never touches a fabric outside this list
    fabrics: list[str] = field(default_factory=lambda: [f for f in _env("FABRICSRE_FABRICS", "DC1,DC2,ISN,MULTISITE").split(",") if f])
    fabric_group: str = field(default_factory=lambda: _env("FABRICSRE_FABRIC_GROUP", "MULTISITE"))
    # containerlab topology, used to tell cabled ports from unused ones
    topology_file: str = field(default_factory=lambda: _env("FABRICSRE_TOPOLOGY", os.path.expanduser("~/fabricsre/multisite.clab.yml")))
    # syslog file fed by ND anomaly export and switch syslog (rsyslog on this host)
    syslog_file: str = field(default_factory=lambda: _env("FABRICSRE_SYSLOG_FILE", "/var/log/nd-remote.log"))
    # hosts (containerlab) used as probes for the reachability matrix, name -> ip
    probe_hosts: dict = field(default_factory=lambda: dict(
        p.split("=") for p in _env("FABRICSRE_PROBE_HOSTS", "dc1-host1=192.168.100.11,dc1-host2=192.168.100.12,dc2-host1=192.168.100.21,dc2-host2=192.168.100.22").split(",") if "=" in p))
    container_host: str = field(default_factory=lambda: _env("FABRICSRE_CONTAINER_HOST", "root@10.80.15.10"))  # where the probe containers run (ssh)


def load_dotenv(path: str = os.path.expanduser("~/fabricsre/.env")) -> None:
    """Minimal .env loader: KEY=VALUE lines, no export keyword, no quotes processing beyond stripping."""
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass
