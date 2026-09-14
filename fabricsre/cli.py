"""FabricSRE command line. Every capability is reachable here without any model in the loop."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys

from . import __version__
from .config import Settings, load_dotenv


def _ctx():
    from .db import DB
    from .nd import NDClient
    from .nxapi import NXAPIClient
    from .twin import Twin
    load_dotenv()
    s = Settings(); db = DB(s.db_url); nd = NDClient(s, audit_sink=db); nx = NXAPIClient(s)
    return s, db, nd, nx, Twin(s, nd, nx, db)


def _out(obj, as_json: bool):
    if as_json:
        print(json.dumps(obj, indent=2, default=str))
    elif isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(obj)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fabricsre", description="SRE agent toolkit for Nexus Dashboard managed VXLAN EVPN fabrics")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    sub.add_parser("init-db", help="create or update the PostgreSQL schema")
    sub.add_parser("status", help="ND version, telemetry, twin freshness")

    t = sub.add_parser("twin", help="the fabric twin (#10)").add_subparsers(dest="sub", required=True)
    t.add_parser("refresh").add_argument("--no-switch-tables", action="store_true")
    t.add_parser("freshness"); t.add_parser("uncabled"); t.add_parser("switches")
    e = t.add_parser("endpoint"); e.add_argument("--ip"); e.add_argument("--mac")

    tl = sub.add_parser("timeline", help="what changed (#8)").add_subparsers(dest="sub", required=True)
    tl.add_parser("collect")
    sh = tl.add_parser("show"); sh.add_argument("--since", default="60m", help="e.g. 30m, 6h, 2d"); sh.add_argument("--until"); sh.add_argument("--fabric"); sh.add_argument("--device")

    tr = sub.add_parser("triage", help="anomalies to incidents (#3)").add_subparsers(dest="sub", required=True)
    tr.add_parser("poll"); tr.add_parser("incidents"); tr.add_parser("close-resolved")
    tail = tr.add_parser("tail"); tail.add_argument("--seconds", type=int, default=300); tail.add_argument("--from-start", action="store_true")

    inv = sub.add_parser("investigate", help="why can't A reach B (#1, #2)"); inv.add_argument("src"); inv.add_argument("dst"); inv.add_argument("--no-ping", action="store_true"); inv.add_argument("--evidence", action="store_true")

    ch = sub.add_parser("change", help="change assurance (#5)").add_subparsers(dest="sub", required=True)
    ch.add_parser("plan").add_argument("intent")
    for name in ("preview", "apply", "verify", "rollback", "show"):
        ch.add_parser(name).add_argument("ref")
    a = ch.add_parser("approve"); a.add_argument("ref"); a.add_argument("--by", required=True)
    ch.add_parser("list")

    f = sub.add_parser("fault", help="fault injection for test fabrics (eval harness)").add_subparsers(dest="sub", required=True)
    f.add_parser("list"); f.add_parser("inject").add_argument("name"); f.add_parser("restore").add_argument("name")
    ev = sub.add_parser("eval", help="inject a fault, investigate, check the ledger, restore"); ev.add_argument("name"); ev.add_argument("--src", default="192.168.100.11"); ev.add_argument("--dst", default="192.168.100.21"); ev.add_argument("--settle", type=int, default=90)

    args = ap.parse_args(argv)
    if args.cmd == "version":
        print(__version__); return 0
    s, db, nd, nx, twin = _ctx()

    if args.cmd == "init-db":
        db.init_schema(); print("schema ok"); return 0
    if args.cmd == "status":
        about = nd.about(); tel = {}
        for fb in s.fabrics:
            if fb != s.fabric_group:
                try:
                    tel[fb] = nd.telemetry_status(fb).get("telemetryStatusDescription")
                except Exception as ex:
                    tel[fb] = f"n/a ({ex})"
        _out({"nd": about.get("buildVersion"), "product": about.get("productName"), "telemetry": tel, "twin": twin.freshness()}, args.json); return 0

    if args.cmd == "twin":
        if args.sub == "refresh":
            _out(twin.refresh(with_switch_tables=not args.no_switch_tables), args.json)
        elif args.sub == "freshness":
            _out(twin.freshness(), args.json)
        elif args.sub == "uncabled":
            _out(twin.uncabled_up_ports(), args.json)
        elif args.sub == "switches":
            _out(db.query("SELECT fabric, hostname, role, host(mgmt_ip) AS ip, bgp_asn, sync_status, anomaly_level, collected_at FROM switches ORDER BY fabric, hostname"), args.json)
        elif args.sub == "endpoint":
            _out(twin.find_endpoint(ip=args.ip, mac=args.mac), args.json)
        return 0

    if args.cmd == "timeline":
        from .timeline import Timeline
        T = Timeline(s, nd, db)
        if args.sub == "collect":
            _out(T.collect(), args.json)
        else:
            end = dt.datetime.now(dt.timezone.utc) if not args.until else dt.datetime.fromisoformat(args.until)
            start = end - _dur(args.since)
            rows = T.window(start, end, fabric=args.fabric, device=args.device)
            if args.json:
                _out(rows, True)
            else:
                for r in rows:
                    print(f"{r['ts']:%Y-%m-%d %H:%M:%S}Z  {r['source']:<12} {r['severity'] or '':<8} {(r['fabric'] or ''):<9} {(r['device'] or '')[:18]:<18} {r['summary'][:150]}")
                print(f"-- {len(rows)} events between {start:%H:%M:%S} and {end:%H:%M:%S}Z")
        return 0

    if args.cmd == "triage":
        from .triage import Triage
        Tr = Triage(s, nd, db, twin)
        if args.sub == "poll":
            _out(Tr.poll(), args.json)
        elif args.sub == "tail":
            _out({"incidents_opened": Tr.tail_syslog(args.seconds, args.from_start)}, args.json)
        elif args.sub == "close-resolved":
            _out({"closed": Tr.close_resolved()}, args.json)
        else:
            _out(Tr.open_incidents(), args.json)
        return 0

    if args.cmd == "investigate":
        from .investigate import Investigator, render
        I = Investigator(s, nd, nx, db, twin)
        L = I.run(args.src, args.dst, with_ping=not args.no_ping)
        if args.json:
            _out({"ledger": L.to_dict(), "evidence": I.evidence_bundle() if args.evidence else None}, True)
        else:
            print(render(L))
            if args.evidence:
                print("\nEvidence bundle:"); [print(" ", json.dumps(e, default=str)[:300]) for e in I.evidence_bundle()]
        return 0 if L.failure_domain == "none" else 2

    if args.cmd == "change":
        from .change import ChangeManager
        C = ChangeManager(s, nd, db, twin)
        if args.sub == "plan":
            _out(C.plan(C.load_intent(args.intent)), args.json)
        elif args.sub == "preview":
            _out(C.preview(args.ref), args.json)
        elif args.sub == "approve":
            _out(C.approve(args.ref, args.by), args.json)
        elif args.sub == "apply":
            _out(C.apply(args.ref), args.json)
        elif args.sub == "verify":
            _out(C.verify(args.ref), args.json)
        elif args.sub == "rollback":
            _out(C.rollback(args.ref), args.json)
        elif args.sub == "show":
            _out(C.show(args.ref), args.json)
        else:
            _out(db.query("SELECT ref, status, created_at, approved_by, applied_at FROM changes ORDER BY created_at DESC"), args.json)
        return 0

    if args.cmd in ("fault", "eval"):
        from .faults import FaultInjector, catalog
        cat = catalog(s); FI = FaultInjector(s, db)
        if args.cmd == "fault":
            if args.sub == "list":
                _out({k: {"device": v.device, "description": v.description, "expected_refuted": v.expected_refuted} for k, v in cat.items()}, args.json)
            elif args.sub == "inject":
                _out(FI.inject(cat[args.name]), args.json)
            else:
                _out(FI.restore(cat[args.name]), args.json)
            return 0
        import time
        from .investigate import Investigator, render
        fault = cat[args.name]; I = Investigator(s, nd, nx, db, twin)
        print(f"== eval {fault.name}: {fault.description}")
        print("injected:", FI.inject(fault)); print(f"settling {args.settle}s ..."); time.sleep(args.settle)
        try:
            twin.refresh(with_switch_tables=False)
            L = I.run(args.src, args.dst); print(render(L))
            refuted = {h.id for h in L.hypotheses if h.status == "refuted"}
            hit = set(fault.expected_refuted) & refuted
            verdict = "PASS" if hit else "FAIL"
            print(f"\n== verdict: {verdict}. expected refuted {fault.expected_refuted}, got {sorted(refuted)}, failure domain: {L.failure_domain}")
        finally:
            print("restored:", FI.restore(fault))
        return 0 if verdict == "PASS" else 3
    return 0


def _dur(s: str) -> dt.timedelta:
    """'30m', '6h', '2d' -> timedelta"""
    n, u = int(s[:-1]), s[-1]
    return {"m": dt.timedelta(minutes=n), "h": dt.timedelta(hours=n), "d": dt.timedelta(days=n)}[u]


if __name__ == "__main__":
    sys.exit(main())
