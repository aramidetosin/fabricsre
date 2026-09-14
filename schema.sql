-- FabricSRE v1 schema (PostgreSQL 16). The twin tables are caches of Nexus Dashboard and NX-OS state: every row
-- carries collected_at and the snapshot that produced it, and no answer is given without quoting that age.
-- The change, incident and audit tables are the system's own durable state.

CREATE TABLE IF NOT EXISTS snapshots (
  id            BIGSERIAL PRIMARY KEY,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ,
  scope         TEXT NOT NULL,              -- 'twin' | 'timeline' | 'triage'
  status        TEXT NOT NULL DEFAULT 'running',
  notes         TEXT
);

-- ------------------------------------------------------------------ twin (#10)
CREATE TABLE IF NOT EXISTS fabrics (
  name          TEXT PRIMARY KEY,
  category      TEXT, fabric_type TEXT, bgp_asn TEXT, telemetry BOOLEAN, license_tier TEXT,
  raw           JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id)
);
CREATE TABLE IF NOT EXISTS switches (
  serial        TEXT PRIMARY KEY,
  fabric        TEXT NOT NULL, hostname TEXT NOT NULL, mgmt_ip INET, role TEXT, model TEXT, version TEXT,
  bgp_asn TEXT, sync_status TEXT, discovery_status TEXT, anomaly_level TEXT, uptime_s BIGINT, vpc BOOLEAN,
  raw           JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id)
);
CREATE INDEX IF NOT EXISTS switches_fabric_idx ON switches(fabric);
CREATE TABLE IF NOT EXISTS interfaces (
  serial        TEXT NOT NULL, name TEXT NOT NULL,
  fabric TEXT, admin_up BOOLEAN, oper_up BOOLEAN, mode TEXT, access_vlan TEXT, allowed_vlans TEXT, description TEXT,
  ipv4 TEXT, policy TEXT, compliance TEXT, anomaly_level TEXT, neighbor_switch TEXT, neighbor_port TEXT,
  raw           JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (serial, name)
);
CREATE TABLE IF NOT EXISTS links (
  link_id       TEXT PRIMARY KEY,
  fabric TEXT, policy_type TEXT, template TEXT,
  sw1_serial TEXT, sw1_name TEXT, sw1_if TEXT, sw2_serial TEXT, sw2_name TEXT, sw2_if TEXT,
  admin_status TEXT, oper_status TEXT,
  raw           JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id)
);
CREATE TABLE IF NOT EXISTS vrfs (
  fabric TEXT NOT NULL, name TEXT NOT NULL, vni INT, status TEXT,
  raw JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (fabric, name)
);
CREATE TABLE IF NOT EXISTS networks (
  fabric TEXT NOT NULL, name TEXT NOT NULL, vrf TEXT, vni INT, vlan INT, gateway TEXT, status TEXT,
  raw JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (fabric, name)
);
CREATE TABLE IF NOT EXISTS attachments (
  fabric TEXT NOT NULL, network TEXT NOT NULL, serial TEXT NOT NULL, switch_name TEXT, state TEXT, ports TEXT, vlan INT,
  raw JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (fabric, network, serial)
);
CREATE TABLE IF NOT EXISTS endpoints (
  fabric TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL, vlan TEXT, vrf TEXT, switch_name TEXT NOT NULL DEFAULT '', interface TEXT, source TEXT NOT NULL,
  raw JSONB NOT NULL, collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (fabric, mac, source, ip, switch_name)
);
CREATE TABLE IF NOT EXISTS nve_peers (
  serial TEXT NOT NULL, hostname TEXT, peer_ip TEXT NOT NULL, state TEXT, learn_type TEXT, uptime TEXT, router_mac TEXT,
  collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (serial, peer_ip)
);
CREATE TABLE IF NOT EXISTS bgp_evpn_neighbors (
  serial TEXT NOT NULL, hostname TEXT, neighbor TEXT NOT NULL, remote_as TEXT, state TEXT, up_down TEXT, prefixes INT,
  collected_at TIMESTAMPTZ NOT NULL, snapshot_id BIGINT REFERENCES snapshots(id),
  PRIMARY KEY (serial, neighbor)
);

-- ------------------------------------------------------------------ timeline (#8)
CREATE TABLE IF NOT EXISTS timeline_events (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL,
  source        TEXT NOT NULL,     -- deployment | policy | event | anomaly | audit | fabric_audit | syslog | fabricsre
  fabric        TEXT, device TEXT, actor TEXT, kind TEXT, severity TEXT,
  summary       TEXT NOT NULL,
  ref           TEXT,              -- id in the source system
  raw           JSONB,
  fingerprint   TEXT UNIQUE        -- de-duplicates re-collection
);
CREATE INDEX IF NOT EXISTS timeline_ts_idx ON timeline_events(ts);

-- ------------------------------------------------------------------ triage (#3)
CREATE TABLE IF NOT EXISTS anomalies (
  anomaly_id    TEXT PRIMARY KEY,
  fabric TEXT, severity TEXT, category TEXT, title TEXT, description TEXT, nodes TEXT[], entity TEXT,
  is_root BOOLEAN, correlated_count INT, started_at TIMESTAMPTZ, cleared BOOLEAN, suppressed_by TEXT,
  raw JSONB NOT NULL, first_seen TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS incidents (
  id            BIGSERIAL PRIMARY KEY,
  opened_at     TIMESTAMPTZ NOT NULL DEFAULT now(), closed_at TIMESTAMPTZ,
  fabric TEXT, title TEXT NOT NULL, severity TEXT, status TEXT NOT NULL DEFAULT 'open',
  root_anomaly_id TEXT, anomaly_ids TEXT[] NOT NULL DEFAULT '{}', devices TEXT[] NOT NULL DEFAULT '{}',
  summary TEXT, ledger JSONB
);

-- ------------------------------------------------------------------ change assurance (#5)
CREATE TABLE IF NOT EXISTS changes (
  ref           TEXT PRIMARY KEY,          -- CHG-<n> or an external ticket id
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(), created_by TEXT,
  intent        JSONB NOT NULL,
  status        TEXT NOT NULL DEFAULT 'planned',  -- planned | previewed | approved | applied | verified | failed | rolled_back
  preview_hash  TEXT,                      -- sha256 over the per-switch pending config the human approved
  preview       JSONB, checks JSONB,
  approved_by   TEXT, approved_at TIMESTAMPTZ,
  applied_at    TIMESTAMPTZ, verification JSONB, notes TEXT
);


-- ------------------------------------------------------------------ investigations (#1, #2)
CREATE TABLE IF NOT EXISTS investigations (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), src TEXT NOT NULL, dst TEXT NOT NULL,
  ledger JSONB NOT NULL, conclusion TEXT, failure_domain TEXT
);

-- ------------------------------------------------------------------ audit of everything this system did
CREATE TABLE IF NOT EXISTS api_calls (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), method TEXT NOT NULL, path TEXT NOT NULL,
  status TEXT NOT NULL, ms INT, change_ref TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS api_calls_ts_idx ON api_calls(ts);
