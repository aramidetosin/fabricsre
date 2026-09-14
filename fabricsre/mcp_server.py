"""MCP server for FabricSRE: the tool layer any agent host (Claude Code, Claude Desktop, n8n) can call.

Read tools are open. The change tools follow the state machine in change.py and refuse to skip states; approval
is deliberately NOT exposed as a tool, so a human approves from the CLI with their name attached.
Run:  fabricsre-mcp   (stdio transport)
"""
from __future__ import annotations

import json

try:                                   # mcp 2.x renamed FastMCP to MCPServer; keep both import paths working
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:                     # mcp 1.x
    from mcp.server.fastmcp import FastMCP

from .config import Settings, load_dotenv

mcp = FastMCP("fabricsre")
_ctx = {}


def ctx():
    if not _ctx:
        from .db import DB
        from .nd import NDClient
        from .nxapi import NXAPIClient
        from .twin import Twin
        load_dotenv(); s = Settings(); db = DB(s.db_url); nd = NDClient(s, audit_sink=db); nx = NXAPIClient(s)
        _ctx.update(s=s, db=db, nd=nd, nx=nx, twin=Twin(s, nd, nx, db))
    return _ctx


def _j(o) -> str:
    return json.dumps(o, default=str)


@mcp.tool()
def fabric_status() -> str:
    """Nexus Dashboard version, telemetry state per fabric and the age of the twin snapshot."""
    c = ctx(); tel = {}
    for f in c["s"].fabrics:
        if f != c["s"].fabric_group:
            try:
                tel[f] = c["nd"].telemetry_status(f).get("telemetryStatusDescription")
            except Exception as e:
                tel[f] = f"n/a ({e})"
    return _j({"nd": c["nd"].about().get("buildVersion"), "telemetry": tel, "twin": c["twin"].freshness()})


@mcp.tool()
def twin_refresh(with_switch_tables: bool = True) -> str:
    """Re-collect the twin from Nexus Dashboard (and NVE/BGP tables from the switches). Returns row counts."""
    return _j(ctx()["twin"].refresh(with_switch_tables=with_switch_tables))


@mcp.tool()
def twin_query(sql: str) -> str:
    """Read-only SQL over the twin (tables: fabrics, switches, interfaces, links, vrfs, networks, attachments, endpoints,
    nve_peers, bgp_evpn_neighbors, timeline_events, anomalies, incidents, changes, investigations). SELECT only."""
    q = sql.strip().rstrip(";")
    if not q.lower().startswith("select") or ";" in q:
        return _j({"error": "SELECT statements only"})
    if " limit " not in q.lower():
        q += " LIMIT 500"
    try:
        return _j(ctx()["db"].query(q))
    except Exception as e:               # a bad query is data for the caller, not a crash of the server
        return _j({"error": f"{type(e).__name__}: {e}"[:400]})


@mcp.tool()
def locate_endpoint(ip: str) -> str:
    """Where an IP lives: leaf, port, VLAN, VRF, MAC, and how that was established."""
    from .investigate import Investigator
    c = ctx(); return _j(Investigator(c["s"], c["nd"], c["nx"], c["db"], c["twin"]).locate(ip).__dict__)


@mcp.tool()
def investigate(src_ip: str, dst_ip: str, with_ping: bool = True) -> str:
    """Why can't src reach dst: walks the EVPN Multi-Site path and returns the hypothesis ledger with evidence."""
    from .investigate import Investigator
    c = ctx(); I = Investigator(c["s"], c["nd"], c["nx"], c["db"], c["twin"])
    L = I.run(src_ip, dst_ip, with_ping=with_ping)
    return _j({"ledger": L.to_dict(), "evidence": I.evidence_bundle()})


@mcp.tool()
def show(device: str, command: str) -> str:
    """Run one allow-listed NX-OS show command on a switch (hostname or mgmt IP) and return the JSON body with an evidence reference."""
    c = ctx(); sw = c["twin"].switch_by_name(device)
    ev = c["nx"].show(sw["ip"] if sw else device, command)
    return _j({"evidence": ev.ref(), "body": ev.body})


@mcp.tool()
def timeline(since_minutes: int = 60, fabric: str | None = None, device: str | None = None, collect_first: bool = True) -> str:
    """What changed: deployments, policies, events, anomalies, audit records and syslog in one ordered list."""
    import datetime as dt
    from .timeline import Timeline
    c = ctx(); T = Timeline(c["s"], c["nd"], c["db"])
    if collect_first:
        T.collect()
    end = dt.datetime.now(dt.timezone.utc)
    return _j(T.window(end - dt.timedelta(minutes=since_minutes), end, fabric=fabric, device=device))


@mcp.tool()
def triage_poll() -> str:
    """Pull anomalies from Nexus Dashboard, suppress known noise, correlate into incidents. Returns counts and open incidents."""
    from .triage import Triage
    c = ctx(); Tr = Triage(c["s"], c["nd"], c["db"], c["twin"]); r = Tr.poll(); Tr.close_resolved()
    return _j({"poll": r, "open_incidents": Tr.open_incidents()})


@mcp.tool()
def change_plan(intent_yaml: str) -> str:
    """Validate a change intent (YAML; kinds stretched_network, drift_remediation, interface_admin_state) against the twin. Creates a change ref. No device is touched."""
    import yaml
    from .change import ChangeManager
    c = ctx(); return _j(ChangeManager(c["s"], c["nd"], c["db"], c["twin"]).plan(yaml.safe_load(intent_yaml), created_by="mcp"))


@mcp.tool()
def change_preview(ref: str) -> str:
    """Create the NDFC objects without deploying, run Recalculate, and return the exact per-switch pending config plus its hash."""
    from .change import ChangeManager
    c = ctx(); return _j(ChangeManager(c["s"], c["nd"], c["db"], c["twin"]).preview(ref))


@mcp.tool()
def change_apply(ref: str) -> str:
    """Deploy an APPROVED change. Refuses unless a human approved the current preview hash from the CLI (fabricsre change approve)."""
    from .change import ChangeManager
    c = ctx(); return _j(ChangeManager(c["s"], c["nd"], c["db"], c["twin"]).apply(ref))


@mcp.tool()
def change_show(ref: str) -> str:
    """State, checks, preview hash, approver and verification of a change."""
    from .change import ChangeManager
    c = ctx(); return _j(ChangeManager(c["s"], c["nd"], c["db"], c["twin"]).show(ref))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
