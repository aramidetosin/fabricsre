"""Incident triage (#3): anomalies in, incidents out.

Two inputs feed the same pipeline:
- the Analyze anomaly API, polled (`Triage.poll`), and
- the ND anomaly export arriving over syslog on this host (`Triage.tail_syslog`), which is the event-driven path.

Correlation is deliberately simple and explainable. Anomalies are grouped into one incident when, inside a time
window, they touch the same device, or the two ends of the same link in the twin, or a BGP peer address that the
twin maps to a link. No model is involved; the model only narrates an incident afterwards.

Suppression: ND's own post-processing rule already hides the unconnected-port noise. On top of that the triage
ignores anomalies on interfaces that the topology file says have no cable, so a fresh cluster without the rule
behaves the same way.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import time
from dataclasses import dataclass

from .config import Settings
from .db import DB
from .nd import NDClient, NDError
from .timeline import parse_exporter_line
from .twin import Twin

UTC = dt.timezone.utc
NOISE_TITLES = {"CONNECTIVITY_INTERFACE_STATUS"}          # only when the interface is uncabled
INFORMATIONAL_TITLES = {"Fabric_Configuration"}            # e.g. "periodic copy run start skipped during deployment"
# virtual N9Kv interfaces report bandwidth as 100 percent utilised whatever the load; the metric carries no information there
PLATFORM_NOISE = {"N9K-C9300v": {"INTERFACE_UTILIZATION_HIGH_THRESHOLD"}}
WINDOW = dt.timedelta(minutes=30)   # ND raises related anomalies over several minutes (BGP down at once, LLDP flap up to 7 minutes later)


@dataclass
class Triage:
    settings: Settings
    nd: NDClient
    db: DB
    twin: Twin

    # ------------------------------------------------------------ ingestion
    def poll(self, fabrics: list[str] | None = None) -> dict:
        fabrics = fabrics or [f for f in self.settings.fabrics if f != self.settings.fabric_group]
        new, updated = [], 0
        uncabled = {(i["hostname"], i["name"].lower()) for i in self.twin.uncabled_up_ports()}
        for f in fabrics:
            try:
                anoms = self.nd.get_all("/api/v1/analyze/anomalies/details", "anomalies", fabricName=f)
            except NDError as e:
                continue
            for a in anoms:
                row = self._row(f, a, uncabled)
                existing = self.db.query("SELECT cleared, suppressed_by FROM anomalies WHERE anomaly_id=%s", (row["anomaly_id"],))
                self.db.upsert("anomalies", row, ["anomaly_id"])
                if not existing:
                    new.append(row)
                elif existing[0]["cleared"] != row["cleared"]:
                    updated += 1
        incidents = self.correlate([r for r in new if not r["suppressed_by"] and not r["cleared"]])
        return {"new": len(new), "updated": updated, "incidents_opened": incidents}

    def _models(self) -> dict:
        if not hasattr(self, "_model_cache"):
            self._model_cache = {r["hostname"]: r["model"] for r in self.db.query("SELECT hostname, model FROM switches")}
        return self._model_cache

    def _row(self, fabric: str, a: dict, uncabled: set) -> dict:
        nodes = a.get("nodeNames") or []
        entity = a.get("entityName") or ""
        suppressed = None
        models = self._models()
        if a.get("mnemonicTitle") in NOISE_TITLES and nodes and (nodes[0], entity.lower()) in uncabled:
            suppressed = "uncabled-port"
        elif nodes and a.get("mnemonicTitle") in PLATFORM_NOISE.get(models.get(nodes[0], ""), set()):
            suppressed = f"platform-noise:{models.get(nodes[0])}"
        elif a.get("mnemonicTitle") in INFORMATIONAL_TITLES:
            suppressed = "informational"
        elif a.get("acknowledged"):
            suppressed = "acknowledged-in-nd"
        return dict(anomaly_id=str(a["anomalyId"]), fabric=fabric, severity=a.get("severity"), category=a.get("category"), title=a.get("mnemonicTitle"),
                    description=(a.get("anomalyString") or "")[:1000], nodes=nodes, entity=entity, is_root=bool(a.get("isRoot")),
                    correlated_count=int(a.get("correlatedAnomaliesCount") or 0), started_at=_ts(a.get("startTimestamp")), cleared=bool(a.get("cleared")),
                    suppressed_by=suppressed, raw=a, last_seen=dt.datetime.now(UTC))

    def tail_syslog(self, follow_seconds: int = 0, from_start: bool = False) -> int:
        """Read ND exporter lines from the rsyslog file; with follow_seconds > 0 keep tailing that long.
        Each raise line becomes a candidate anomaly (fetched in full from the API by title + node) and is correlated."""
        path = self.settings.syslog_file; opened = 0
        try:
            fh = open(path, errors="replace")
        except FileNotFoundError:
            return opened
        if not from_start:
            fh.seek(0, 2)
        deadline = time.time() + follow_seconds
        while True:
            line = fh.readline()
            if not line:
                if time.time() >= deadline:
                    break
                time.sleep(1); continue
            p = parse_exporter_line(line.rstrip("\n"))
            if not p or p["cleared"] or p.get("suppressed"):
                continue
            # the export can arrive seconds before the anomaly API lists the record: retry briefly, then fall back to the line itself
            rows = []
            for attempt in range(4):
                rows = self._fetch_by_signature(p["fabric"], p["title"], p["nodes"])
                if rows:
                    break
                time.sleep(10)
            if not rows:
                # only a fresh line justifies an incident without an API record; an old line whose anomaly is already
                # cleared in ND (typical on --from-start) is history, not an incident
                if p["ts"] and (dt.datetime.now(UTC) - p["ts"]) > dt.timedelta(minutes=15):
                    continue
                rows = [self._row_from_export(p)]
                self.db.upsert("anomalies", rows[0], ["anomaly_id"])
            opened += self.correlate(rows, source="syslog")
        return opened

    def _row_from_export(self, p: dict) -> dict:
        """An anomaly row built from the ND export line alone, used when the API has not listed it yet."""
        import hashlib
        aid = "export:" + hashlib.sha256(f"{p['fabric']}|{p['title']}|{p['nodes']}|{p['text']}".encode()).hexdigest()[:16]
        ent = re.search(r"\[(?:default:)?([^\]]+)\]", p["text"])
        return dict(anomaly_id=aid, fabric=p["fabric"], severity=p["nd_severity"], category="exported", title=p["title"], description=p["text"][:1000],
                    nodes=list(p["nodes"]), entity=(ent.group(1) if ent else ""), is_root=False, correlated_count=0, started_at=p["ts"], cleared=False,
                    suppressed_by=None, raw={"source": "nd-syslog-export", "line": p["text"]}, last_seen=dt.datetime.now(UTC))

    def _fetch_by_signature(self, fabric: str, title: str, nodes: list[str]) -> list[dict]:
        uncabled = {(i["hostname"], i["name"].lower()) for i in self.twin.uncabled_up_ports()}
        out = []
        try:
            anoms = self.nd.get_all("/api/v1/analyze/anomalies/details", "anomalies", fabricName=fabric)
        except NDError:
            return out
        for a in anoms:
            if a.get("mnemonicTitle") == title and set(a.get("nodeNames") or []) & set(nodes) and not a.get("cleared"):
                row = self._row(fabric, a, uncabled); self.db.upsert("anomalies", row, ["anomaly_id"])
                if not row["suppressed_by"]:
                    out.append(row)
        return out

    # ------------------------------------------------------------ correlation
    def correlate(self, rows: list[dict], source: str = "poll") -> int:
        """Attach each new anomaly to an open incident that shares a device or link inside the window, else open one."""
        opened = 0
        link_index = self._link_index()
        for r in rows:
            keys = self._keys(r, link_index)
            inc = self._find_open_incident(keys, r["started_at"] or dt.datetime.now(UTC))
            if inc:
                self.db.execute("UPDATE incidents SET anomaly_ids = array_append(anomaly_ids, %s), devices = ARRAY(SELECT DISTINCT unnest(devices || %s::text[])), "
                                "severity = CASE WHEN %s='critical' OR severity='critical' THEN 'critical' WHEN %s='major' OR severity='major' THEN 'major' ELSE severity END, "
                                "summary = summary || E'\\n+ ' || %s WHERE id=%s AND NOT (%s = ANY(anomaly_ids))",
                                (r["anomaly_id"], list(r["nodes"]), r["severity"], r["severity"], f"{r['severity']} {r['title']} on {','.join(r['nodes'])}: {r['description'][:120]}", inc["id"], r["anomaly_id"]))
            else:
                title = self._title(r, keys)
                hint = ("next: fabricsre investigate <src> <dst> across the affected link; if the switch shows pending config after Recalculate, "
                        "plan a drift_remediation change" if r["title"] in ("BGP_PEER_CONNECTION_DOWN", "LLDP_FLAP", "CONNECTIVITY_INTERFACE_STATUS") else "next: fabricsre investigate <src> <dst>")
                self.db.execute("INSERT INTO incidents (fabric, title, severity, root_anomaly_id, anomaly_ids, devices, summary, ledger) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                                (r["fabric"], title, r["severity"], r["anomaly_id"], [r["anomaly_id"]], list(r["nodes"]),
                                 f"{r['severity']} {r['title']} on {','.join(r['nodes'])}: {r['description'][:200]}\n{hint}", json.dumps({"keys": sorted(keys), "source": source})))
                opened += 1
        return opened

    def _link_index(self) -> dict:
        """device -> set(link keys) and peer ip -> link key, from the twin's links and interface addresses."""
        idx: dict = {"dev": {}, "ip": {}}
        for l in self.db.query("SELECT link_id, sw1_name, sw1_if, sw2_name, sw2_if, raw FROM links"):
            key = f"link:{l['sw1_name']}:{l['sw1_if']}<->{l['sw2_name']}:{l['sw2_if']}"
            for d in (l["sw1_name"], l["sw2_name"]):
                if d:
                    idx["dev"].setdefault(d, set()).add(key)
            raw = l.get("raw") or {}
            for k, v in ((raw.get("configData") or {}).get("templateInputs") or {}).items():
                if isinstance(v, str) and re.match(r"^\d+\.\d+\.\d+\.\d+", v):
                    idx["ip"][v.split("/")[0]] = key
        for i in self.db.query("SELECT s.hostname, i.name, i.ipv4 FROM interfaces i JOIN switches s USING (serial) WHERE i.ipv4 IS NOT NULL AND i.ipv4 <> ''"):
            idx["ip"].setdefault(i["ipv4"].split("/")[0], f"if:{i['hostname']}:{i['name']}")
        return idx

    def _keys(self, r: dict, idx: dict) -> set[str]:
        keys = {f"dev:{n}" for n in r["nodes"]}
        for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", r["description"]):
            if ip in idx["ip"]:
                keys.add(idx["ip"][ip])
                # the peer of a /31 is the other end of the same link
                try:
                    a = ipaddress.ip_address(ip); peer = str(a + 1 if int(a) % 2 == 0 else a - 1)
                    if peer in idx["ip"]:
                        keys.add(idx["ip"][peer])
                except ValueError:
                    pass
        if r["entity"] and r["nodes"]:
            ifname = _norm_if(r["entity"])
            for k in idx["dev"].get(r["nodes"][0], set()):
                if f"{r['nodes'][0]}:{ifname}" in k:
                    keys.add(k)
        return keys

    def _find_open_incident(self, keys: set[str], ts: dt.datetime) -> dict | None:
        for inc in self.db.query("SELECT id, ledger, opened_at FROM incidents WHERE status='open' AND opened_at > %s ORDER BY id DESC", (ts - WINDOW,)):
            ik = set((inc["ledger"] or {}).get("keys", []))
            if ik & keys and any(not k.startswith("dev:") for k in ik & keys) or (ik & keys and len(ik & keys) >= 1 and all(k.startswith("dev:") for k in keys | ik) is False and ik & keys):
                return inc
            if ik & keys:
                return inc
        return None

    @staticmethod
    def _title(r: dict, keys: set[str]) -> str:
        links = [k for k in keys if k.startswith("link:")]
        where = links[0][5:] if links else (",".join(r["nodes"]) or r["fabric"])
        ent = f" ({r['entity']})" if r.get("entity") and not links else ""
        return f"{r['title']} on {where}{ent}"

    # ------------------------------------------------------------ housekeeping
    def close_resolved(self) -> int:
        """Close incidents whose critical and major anomalies ND has cleared. Warnings such as LLDP flaps age out on
        their own minutes later and must not keep a resolved incident open; they are listed in the closing note."""
        n = 0
        for inc in self.db.query("SELECT id, anomaly_ids FROM incidents WHERE status='open'"):
            rows = self.db.query("SELECT severity, cleared, title, nodes FROM anomalies WHERE anomaly_id = ANY(%s)", (inc["anomaly_ids"],))
            if not rows:
                continue
            serious = [r for r in rows if r["severity"] in ("critical", "major")]
            if serious and all(r["cleared"] for r in serious):
                left = [f"{r['title']} on {','.join(r['nodes'] or [])}" for r in rows if not r["cleared"]]
                note = "\nresolved: all critical/major anomalies cleared in ND" + (f"; still open in ND (warnings): {left}" if left else "")
                self.db.execute("UPDATE incidents SET status='resolved', closed_at=now(), summary = summary || %s WHERE id=%s", (note, inc["id"])); n += 1
            elif all(r["cleared"] for r in rows):
                self.db.execute("UPDATE incidents SET status='resolved', closed_at=now() WHERE id=%s", (inc["id"],)); n += 1
        return n

    def open_incidents(self) -> list[dict]:
        return self.db.query("SELECT id, opened_at, fabric, severity, title, devices, anomaly_ids, summary FROM incidents WHERE status='open' ORDER BY opened_at DESC")


def _norm_if(name: str) -> str:
    n = name.lower().replace("ethernet", "eth").replace("eth", "Ethernet")
    return n if n.startswith("Ethernet") else name


def _ts(v):
    if not v:
        return None
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
