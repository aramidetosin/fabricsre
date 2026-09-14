"""Change timeline (#8): one ordered table built from every clock in the system.

Sources
- Manage  /fabrics/{f}/deploymentHistory       what NDFC pushed, per command, with status
- Manage  /fabrics/{f}/policyHistory           policy creates/updates/deletes
- Analyze /eventManagement/events              port up/down and other switch events NDFC recorded
- Analyze /anomalies/details                   anomaly start and clear times
- Infra   /auditRecords, /fabricAuditRecords   who did what on Nexus Dashboard
- rsyslog file on this host                    ND anomaly export lines and raw switch syslog
- our own changes table                        what FabricSRE itself planned, approved and applied

Every row gets a fingerprint so re-collection never duplicates. Clock note: ND timestamps are UTC from ND's own
clock; syslog lines carry the receiver's clock. Both are stored as received, and the CLI prints the source next to
each row so a reader can judge skew instead of trusting a merged order blindly.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass

from .config import Settings
from .db import DB
from .nd import NDClient, NDError

UTC = dt.timezone.utc
EXPORTER_RE = re.compile(
    r"^(?P<rts>\S+) (?P<from>\S+) (?P<fac>\S+) Exporter\[\d+\]\[Facility: (?P<f2>\w+), Severity: (?P<sev>\w+)\] "
    r"FabricName : (?P<fabric>\S+) Title : (?P<title>\S+) NDSeverity : (?P<ndsev>\w+) (?:Nodes : (?P<nodes>\[[^\]]*\]) )?(?P<rest>.*)$")


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def _ts(v) -> dt.datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return dt.datetime.fromtimestamp(v / 1000 if v > 1e11 else v, UTC)
    s = str(v).replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d-%H:%M:%S"):
        try:
            return dt.datetime.fromisoformat(s) if fmt is None else dt.datetime.strptime(str(v), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


@dataclass
class Timeline:
    settings: Settings
    nd: NDClient
    db: DB

    def collect(self, fabrics: list[str] | None = None) -> dict:
        fabrics = fabrics or [f for f in self.settings.fabrics]
        sid = self.db.start_snapshot("timeline"); counts = {}
        try:
            counts["deployments"] = self._deployments(fabrics)
            counts["policies"] = self._policies(fabrics)
            counts["events"] = self._events()
            counts["anomalies"] = self._anomalies(fabrics)
            counts["audit"] = self._audit(fabrics)
            counts["syslog"] = self._syslog()
            self.db.finish_snapshot(sid, "ok", json.dumps(counts))
        except Exception as e:
            self.db.finish_snapshot(sid, "failed", f"{type(e).__name__}: {e}"[:500]); raise
        return counts

    def _deployments(self, fabrics) -> int:
        ev = []
        for f in fabrics:
            try:
                recs = self.nd.deployment_history(f)
            except NDError:
                continue
            for r in recs:
                ts = _ts(r.get("completeTimestamp") or r.get("submitTimestamp"))
                if not ts:
                    continue
                cmds = [c.get("command") for c in r.get("configCommandResponses", []) if c.get("command") not in (None, "configure terminal")]
                failed = [c for c in r.get("configCommandResponses", []) if str(c.get("status", "")).upper() not in ("SUCCESS", "")]
                ev.append(dict(ts=ts, source="deployment", fabric=f, device=(r.get("switchName") or r.get("hostname")) or r.get("hostName"), actor=r.get("user"),
                               kind=r.get("source") or "deploy", severity="error" if failed else "info",
                               summary=f"NDFC deployed {len(cmds)} lines to {r.get('switchName') or r.get('hostname') or r.get('hostName')}: {r.get('status')}"
                                       + (f"; first lines: {' / '.join(cmds[:3])}" if cmds else "") + (f"; FAILED: {failed[0].get('command')} {str(failed[0].get('cliResponse'))[:80]}" if failed else ""),
                               ref=str(r.get("id") or r.get("deploymentId") or ""), raw=r,
                               fingerprint=_fp("dep", f, (r.get("switchName") or r.get("hostname")), ts.isoformat(), r.get("status"), len(cmds))))
        return self.db.add_timeline(ev)

    def _policies(self, fabrics) -> int:
        ev = []
        for f in fabrics:
            try:
                recs = self.nd.policy_history(f)
            except NDError:
                continue
            for p in recs:
                ts = _ts(p.get("createTimestamp") or p.get("modifiedTimestamp"))
                if not ts:
                    continue
                ev.append(dict(ts=ts, source="policy", fabric=f, device=p.get("switchName"), actor=p.get("user") or p.get("modifiedBy"),
                               kind=p.get("actionPerformed") or "policy", severity="info",
                               summary=f"policy {p.get('templateName') or p.get('policyName')} {p.get('actionPerformed') or ''} on {p.get('switchName') or 'fabric'} ({p.get('policyId') or ''})".strip(),
                               ref=str(p.get("policyId") or ""), raw=p, fingerprint=_fp("pol", f, p.get("policyId"), ts.isoformat(), p.get("actionPerformed"))))
        return self.db.add_timeline(ev)

    def _events(self) -> int:
        ev = []
        for e in self.nd.events(max_records=1000):
            ts = _ts(e.get("lastSeenTime") or e.get("firstSeenTime") or e.get("lastSeen"))
            if not ts:
                continue
            ev.append(dict(ts=ts, source="event", fabric=e.get("fabricName"), device=e.get("switchName") or e.get("hostName"), actor=None,
                           kind=e.get("eventRecordType"), severity=(e.get("severity") or "").lower(),
                           summary=f"{e.get('eventRecordType')}: {e.get('description')}", ref=str(e.get("eventId") or ""), raw=e,
                           fingerprint=_fp("evt", e.get("eventId"), ts.isoformat(), e.get("description"))))
        return self.db.add_timeline(ev)

    def _anomalies(self, fabrics) -> int:
        ev = []
        for f in fabrics:
            try:
                anoms = self.nd.get_all("/api/v1/analyze/anomalies/details", "anomalies", fabricName=f)
            except NDError:
                continue
            for a in anoms:
                st = _ts(a.get("startTimestamp")); en = _ts(a.get("endTimestamp")) if a.get("cleared") else None
                nodes = ",".join(a.get("nodeNames") or [])
                base = f"{a.get('severity')} {a.get('mnemonicTitle')} on {nodes or a.get('device')}: {(a.get('anomalyString') or '')[:160]}"
                if st:
                    ev.append(dict(ts=st, source="anomaly", fabric=f, device=nodes or None, actor=None, kind="raised", severity=a.get("severity"),
                                   summary="raised " + base, ref=a.get("anomalyId"), raw=None, fingerprint=_fp("anr", a.get("anomalyId"), st.isoformat())))
                if en and en != st:
                    ev.append(dict(ts=en, source="anomaly", fabric=f, device=nodes or None, actor=None, kind="cleared", severity=a.get("severity"),
                                   summary="cleared " + base, ref=a.get("anomalyId"), raw=None, fingerprint=_fp("anc", a.get("anomalyId"), en.isoformat())))
        return self.db.add_timeline(ev)

    def _audit(self, fabrics) -> int:
        ev = []
        for r in self.nd.audit_records(max_records=1000):
            ts = _ts(r.get("creationTime"))
            if ts:
                ev.append(dict(ts=ts, source="audit", fabric=None, device=None, actor=r.get("username") or r.get("user"), kind=r.get("action"), severity="info",
                               summary=f"ND {r.get('action')} {r.get('affectedResource')} by {r.get('username') or r.get('user')} from {r.get('clientIp')}: {(r.get('description') or '')[:120]}",
                               ref=str(r.get("id") or ""), raw=r, fingerprint=_fp("aud", ts.isoformat(), r.get("action"), r.get("affectedResource"), r.get("description"))))
        for f in fabrics:
            try:
                recs = self.nd.fabric_audit_records(f, max_records=1000)
            except NDError:
                continue
            for r in recs:
                ts = _ts(r.get("creationTime"))
                if ts:
                    ev.append(dict(ts=ts, source="fabric_audit", fabric=f, device=None, actor=r.get("username") or r.get("user"), kind=r.get("action"), severity="info",
                                   summary=f"{f}: {r.get('action')} {r.get('affectedResource')} by {r.get('username') or r.get('user')}: {(r.get('description') or '')[:120]}",
                                   ref=str(r.get("id") or ""), raw=r, fingerprint=_fp("fau", f, ts.isoformat(), r.get("action"), r.get("affectedResource"), r.get("description"))))
        return self.db.add_timeline(ev)

    def _syslog(self) -> int:
        ev = []
        try:
            lines = open(self.settings.syslog_file, errors="replace").read().splitlines()
        except FileNotFoundError:
            return 0
        for line in lines[-20000:]:
            parsed = parse_exporter_line(line)
            if parsed:
                ev.append(dict(ts=parsed["ts"], source="syslog", fabric=parsed["fabric"], device=",".join(parsed["nodes"]) or None, actor="nd-exporter",
                               kind="anomaly-cleared" if parsed["cleared"] else ("anomaly-suppressed" if parsed.get("suppressed") else "anomaly-raised"), severity=parsed["nd_severity"],
                               summary=f"ND exported {'clear' if parsed['cleared'] else ('suppression' if parsed.get('suppressed') else 'raise')} of {parsed['title']} ({parsed['nd_severity']}) nodes {parsed['nodes']}: {parsed['text'][:140]}",
                               ref=parsed["title"], raw=None, fingerprint=_fp("sys", line)))
                continue
            m = re.match(r"^(\S+) (\S+) (\S+) (.*)$", line)
            if m and "fabricsre-test" not in line:
                ts = _ts(m.group(1))
                if ts:
                    ev.append(dict(ts=ts, source="syslog", fabric=None, device=m.group(2), actor=None, kind=m.group(3), severity=m.group(3).split(".")[-1],
                                   summary=m.group(4)[:300], ref=None, raw=None, fingerprint=_fp("sysraw", line)))
        return self.db.add_timeline(ev)

    # ------------------------------------------------------------ queries
    def window(self, start: dt.datetime, end: dt.datetime, fabric: str | None = None, device: str | None = None, sources: list[str] | None = None) -> list[dict]:
        sql = "SELECT ts, source, fabric, device, actor, kind, severity, summary, ref FROM timeline_events WHERE ts BETWEEN %s AND %s"
        params: list = [start, end]
        if sources:
            sql += " AND source = ANY(%s)"; params.append(list(sources))
        if fabric:
            sql += " AND (fabric=%s OR fabric IS NULL)"; params.append(fabric)
        if device:
            sql += " AND device ILIKE %s"; params.append(f"%{device}%")
        return self.db.query(sql + " ORDER BY ts", params)

    def before(self, point: dt.datetime, minutes: int = 60, **kw) -> list[dict]:
        return self.window(point - dt.timedelta(minutes=minutes), point, **kw)


def parse_exporter_line(line: str) -> dict | None:
    m = EXPORTER_RE.match(line)
    if not m:
        return None
    rest = m.group("rest")
    cleared = re.search(r"Cleared : (\w+)", rest)
    if m.group("nodes") is None:
        # fabric-level messages name the switch as "Switch [hostname/serial]:" instead of a Nodes list
        sw = re.search(r"Switch \[([^/\]]+)/", rest)
        nodes = [sw.group(1)] if sw else []
    else:
        try:
            nodes = json.loads(m.group("nodes"))
        except json.JSONDecodeError:
            nodes = [m.group("nodes").strip("[]")]
    supp = re.search(r"Suppressed : (\w+)", rest); ack = re.search(r"Acknowledged : (\w+)", rest)
    return dict(ts=_ts(m.group("rts")), sender=m.group("from"), fabric=m.group("fabric"), title=m.group("title"), nd_severity=m.group("ndsev").lower(),
                nodes=nodes, cleared=(cleared.group(1).lower() == "true") if cleared else False,
                suppressed=(supp.group(1).lower() == "true") if supp else False, acknowledged=(ack.group(1).lower() == "true") if ack else False,
                text=re.sub(r" Cleared : .*$", "", rest))
