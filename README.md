# FabricSRE

An SRE agent toolkit for Cisco Nexus Dashboard managed VXLAN EVPN fabrics. Built and verified against a real deployment:
Nexus Dashboard 4.3.1.175 with NDFC 12.6.0.267, two eBGP Multi-AS sites, an NDFC managed ISN, one Multi-Site
fabric group, fourteen N9K-C9300v switches under containerlab.

The build is written up in two posts on levelupit.xyz:

- [FabricSRE part 1: an SRE agent for Cisco Nexus Dashboard](https://www.levelupit.xyz/fabricsre-part-1-an-sre-agent-for-cisco-nexus-dashboard/), the rules, the fabric twin, the ten-hypothesis investigation and the fault harness (publishes 22 September 2026).
- [FabricSRE part 2: triage, change assurance and the timeline](https://www.levelupit.xyz/fabricsre-part-2-triage-change-assurance-and-the-timeline/), anomaly export, triage, a full incident, the change state machine, the timeline and the MCP server (publishes 23 September 2026).

The division of labour is fixed:

- **The model reasons.** It writes intents, orders hypotheses, and narrates results.
- **Deterministic code acts.** Every hypothesis is a predicate over real data; every write goes through a state machine.
- **Nexus Dashboard and NX-OS remain the source of truth.** The twin is a timestamped cache, never an authority.

## Capabilities

| # | Capability | Entry point | Data |
|---|---|---|---|
| 1, 2 | Path investigation: "why can't A reach B" as a hypothesis ledger with evidence | `fabricsre investigate SRC DST` | Analyze endpoints, twin, NX-API show tables, host probe |
| 3 | Triage: anomalies to incidents, polled or event-driven from ND's syslog export | `fabricsre triage poll`, `triage tail` | Analyze anomalies, rsyslog file, twin links |
| 5 | Change assurance: intent, preview, approval bound to the preview hash, apply, verify, rollback | `fabricsre change ...` | Manage pending config and diff, legacy top-down APIs |
| 8 | Timeline: one ordered table from every clock in the system | `fabricsre timeline show --since 2h` | deployment/policy history, events, anomalies, audit records, syslog |
| 10 | Twin: fabrics, switches, interfaces, links, VRFs, networks, attachments, endpoints, NVE peers, BGP EVPN neighbours | `fabricsre twin refresh` | Manage, Analyze, NX-API |
| eval | Fault injection harness that proves the investigator names the injected fault | `fabricsre eval dci_link_down` | NX-API config (test fabrics only, env gated) |

Every capability is also exposed as MCP tools (`fabricsre-mcp`, stdio) so Claude Code, Claude Desktop or n8n can drive
it. Approval is deliberately not an MCP tool: a human approves from the CLI with their name.

## Architecture

```
 engineer / Claude ──CLI or MCP──▶ fabricsre
                                      │
        ┌──────────────┬──────────────┼──────────────┬──────────────┐
    investigate      triage        change         timeline        twin
   (H1..H10 code)  (correlate)  (state machine) (merge clocks)  (collectors)
        └──────────────┴──────────────┼──────────────┴──────────────┘
                                      │
                         nd.py (GA Manage/Analyze/Infra + legacy where GA lacks writes)
                         nxapi.py (read-only, allow-listed show commands, Evidence objects)
                         db.py (PostgreSQL: twin, timeline, anomalies, incidents, changes, api_calls)
                                      │
                    Nexus Dashboard 4.3.1 ◀── syslog export ──▶ rsyslog on the runtime host
                    NX-OS switches (NX-API JSON-RPC)      containerlab hosts (ssh, ping probes)
```

### Investigation ledger (H1 to H10)

H1 source learned on its leaf; H2 VLAN and VNI up on both leaves; H3 EVPN Type-2 route for the destination on the
source leaf; H4 network deployed identically in both sites; H5 border gateways forward Multi-Site (DCI and fabric
links up, NVE peer to the remote VIP); H6 ISN healthy (every core holds an established session to each border
gateway the twin's underlay links expect); H7 destination learned on its leaf, port up, in the VLAN; H8 VRF route
(routed traffic only); H9 no ACL on the host ports; H10 data plane (ping from the source host, error counters).

Each outcome is confirmed, refuted, untested or not_applicable and carries evidence references of the form
`device \`command\` @ timestamp sha256:...`. The first refuted hypothesis in path order names the failure domain.
There is no invented confidence number: confidence is the count of confirmed and refuted hypotheses.

### Change assurance state machine

```
planned ─▶ previewed ─▶ approved ─▶ applied ─▶ verified
   │           ▲            │ (pending config hash differs at apply time)
 blocked       └────────────┘  approval voided, review again
                                      any state ─▶ rolled_back
```

The approval is bound to the sha256 of the per-switch pending config the human saw. If Recalculate produces a
different pending config later, apply refuses and the change drops back to previewed.

Intent kinds:

- `stretched_network`: a network in a VRF on the VTEPs of one or more site fabrics, optionally with host ports.
  Preview creates the NDFC objects without deploying and reads the pending config per switch.
- `drift_remediation`: one switch back to NDFC intent. Plan asks NDFC for a fresh running-config read
  (`pendingConfig?forceShowRun=true`), because NDFC's compliance cache can report In-Sync for minutes after a change
  made outside NDFC. Preview is exactly what NDFC will push; apply deploys to that switch only.
- `interface_admin_state`: bring one interface up or down through NDFC's interface actions. Apply refreshes the
  compliance view first, records the admin state, then deploys the interface; verify waits for admin and oper state.

Rollback: a stretched network is detached, deployed and deleted; an admin-state change is inverted; a drift
remediation has nothing to roll back to except the drift itself, so it refuses.

### Triage

Anomalies are polled from Analyze or arrive as ND syslog export lines (`Exporter[..] FabricName : X Title : Y
NDSeverity : ... Nodes : [...] ... Cleared : false ... Suppressed : false`). Noise is suppressed by explainable rules:
interfaces with no cable in the topology file, informational fabric messages, and platform noise (N9K-C9300v reports
every interface as 100 percent utilised). Remaining anomalies are grouped into an incident when they share a device,
a link, or a /31 peer address inside a ten minute window.

## Runtime

- Host: dns02 (Ubuntu 24.04, Python 3.12, PostgreSQL 16, rsyslog receiving on UDP/TCP 514 into `/var/log/nd-remote.log`).
- Secrets: `~/fabricsre/.env` (see `.env.example`). Nothing is logged or stored.
- Deploy: `./deploy.sh dns02` (rsync, venv, pip, database role, schema).
- Nexus Dashboard side, done once: platform log server `dns02-syslog`, system anomaly streaming, per-fabric
  `externalStreamingSettings.syslog` (do not send `facility`, ND sets LOCAL0), telemetry collection out-of-band,
  one post-processing rule suppressing `CONNECTIVITY_INTERFACE_STATUS` at minor severity
  (`suppressActionAcknowledged: true` is required by the API although absent from the schema).

## Nexus Dashboard 4.3.1 / NDFC 12.6 facts this code depends on

- Manage switch identifier is the serial number; roles are camelCase (`borderGateway`, `coreRouter`).
- `/api/v1/manage/fabrics/{f}/switches/{sid}/pendingConfig` and `/diff` give the preview; `deploymentHistory` and
  `policyHistory` give the timeline; `/api/v1/manage/links?fabricName=` gives IFCs with `templateInputs`.
- `/api/v1/analyze/anomalies/details` ignores `sort=-startTimestamp`; page with offset and max.
- Analyze connectivity endpoints, L3 neighbours and interfaces answer only when fabric telemetry is enabled.
- Writes with no GA equivalent still use the legacy `lan-fabric/rest` paths: network create and attach
  (`top-down`), interface policies, config-save and config-deploy.
- NX-API JSON-RPC returns a dict for a single call and a list for a batch; ascii output is not available on this
  build, so H9 stays untested until a JSON form of the running config is used.
- NDFC's compliance cache: after a change made on the switch CLI, `pendingConfig` and `diff` keep answering from the
  last poll and the switch stays In-Sync. `forceShowRun=true` re-reads the switch; the diff then shows the missing
  line and the switch flips to outOfSync. The interface admin-state action and the "perform shut/no shut" legacy
  call both answer "No Commands to execute. In-Sync" until that refresh happens.
- `interfaceActions/preview` answers HTTP 207 with the running and pending config of the interface; treat 207 as success.
- Anomaly post-processing rules need a top-level `suppressActionAcknowledged: true` that the schema does not list.
- Network attachments: `deployment: true` means attach, `deployment: false` means detach; deploying is a separate call.
- ND anomaly start timestamps run two to three minutes earlier than the receiver clock for the same event; the
  timeline prints the source next to every row instead of pretending the clocks agree.

## Tests

`pytest` covers the parsers with lines and tables recorded from the reference fabric. `fabricsre eval <fault>` is the live
evaluation: inject, settle, investigate, assert the expected hypothesis is refuted, restore.

## Using it

Everything runs on dns02 under `~/fabricsre/.venv/bin/fabricsre`. Log in with `ssh dns02` and prefix the commands
below with `~/fabricsre/.venv/bin/`, or add that directory to PATH.

### The daily loop

```bash
fabricsre status                      # ND version, telemetry per fabric, twin age
fabricsre twin refresh                # ~7 s; run before anything that reasons about state
fabricsre timeline collect            # pull deployments, policies, events, anomalies, audit, syslog
fabricsre triage poll                 # anomalies -> incidents, noise suppressed with a reason
fabricsre triage incidents            # what is open right now
fabricsre triage close-resolved       # close incidents whose anomalies ND has cleared
```

### When someone says "A cannot reach B"

```bash
fabricsre investigate 192.168.100.11 192.168.100.21            # ledger H1..H10, failure domain, blast radius
fabricsre investigate 192.168.100.11 192.168.100.21 --evidence # same, plus the raw evidence bundle
fabricsre --json investigate 192.168.100.11 192.168.100.21     # machine readable, for a model or a ticket
```
Exit code 0 means no hypothesis refuted, 2 means a failure domain was named.

### When someone says "what changed?"

```bash
fabricsre timeline show --since 2h
fabricsre timeline show --since 6h --fabric DC1 --device dc1-bgw1
```

### Event-driven triage (instead of polling)

```bash
fabricsre triage tail --seconds 3600          # follow ND's syslog export for an hour, open incidents as they arrive
```

### An incident, from ND export to verified fix

```bash
fabricsre triage tail --seconds 600                    # incident opens from the ND syslog export within seconds
fabricsre investigate 192.168.100.11 192.168.100.21    # names the failure domain and the link
fabricsre change plan intents/fix-dc1-bgw1.yaml        # drift_remediation: NDFC re-reads the switch, lists the missing lines
fabricsre change preview CHG-<ref>                     # the exact lines, hashed
fabricsre change approve CHG-<ref> --by "your name"
fabricsre change apply CHG-<ref>                       # deploys to that switch only, verifies In-Sync
fabricsre triage close-resolved                        # closes once ND clears the critical and major anomalies
```

### A change, from intent to verified

```bash
cp intents/net-b.yaml intents/my-change.yaml && $EDITOR intents/my-change.yaml
fabricsre change plan intents/my-change.yaml           # checks against the twin -> CHG-<ref>
fabricsre change preview CHG-<ref>                     # NDFC objects created, Recalculate, per-switch pending config + hash
fabricsre change approve CHG-<ref> --by "your name"    # binds your approval to that hash
fabricsre change apply CHG-<ref>                       # refuses if the pending config changed; deploys; verifies
fabricsre change show CHG-<ref>
fabricsre change rollback CHG-<ref>                    # detach, deploy, delete the network object
```

### Proving the investigator against the fabric

```bash
fabricsre fault list
FABRICSRE_ALLOW_FAULTS=1 fabricsre eval dci_link_down --settle 150     # inject, investigate, assert, restore
FABRICSRE_ALLOW_FAULTS=1 fabricsre eval host_port_down --settle 60
```

### Letting Claude drive it (MCP)

The same capabilities are MCP tools served over stdio by `fabricsre-mcp`. Run this on the machine where Claude Code
runs (it needs `ssh dns02` to work from there, not Claude on dns02):

```bash
claude mcp add -s user fabricsre -- ssh dns02 /home/user/fabricsre/.venv/bin/fabricsre-mcp
```

Then ask in plain words: "trace how 192.168.100.11 is shared across both sites, hop by hop", "why can't
192.168.100.11 reach 192.168.100.21", "what changed on DC1 in the last two hours", "any open incidents".

Claude then has `fabric_status`, `twin_refresh`, `twin_query` (SELECT only), `locate_endpoint`, `investigate`, `show`
(allow-listed show commands), `timeline`, `triage_poll`, `change_plan`, `change_preview`, `change_apply` and `change_show`.
Approval is not a tool: `change_apply` only works after a human ran `fabricsre change approve` on the CLI.

### Keeping it running unattended

Suggested systemd timers on dns02 (not installed by default): `twin refresh` every 15 minutes, `timeline collect`
every 15 minutes, `triage poll` every 5 minutes, and `triage tail --seconds 3600` as a restarting service for the
event-driven path.
