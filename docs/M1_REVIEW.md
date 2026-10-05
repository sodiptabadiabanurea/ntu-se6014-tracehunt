# M1 completion review

Last updated: 5 October 2026.

## Status

**M1 is complete and merged to `main`.**

- Pull request: #12 — `M1: clean rebuild of secured ELK integration`
- Final PR head: `2e6fab7cffaff14fb063d7ed225bd1672770d444`
- Merge commit: `23db5f407ea168b6fd35b86b3a27445ba46563b8`
- Superseded PR #9 was closed after the replacement merged.

M1 now owns the shared secured Elasticsearch 8.12 / Logstash / Kibana integration, production index templates, Logstash writer identity, and the M4 read-only Elasticsearch identity.

## Portability blocker and resolution

The earlier independent VPS review reported that `/setup/setup_security.sh` behaved as a directory and that the required roles, users, and templates were absent.

The follow-up investigation found that the VPS working copy used during that review was stale at `cf567dae289cd06f53d1d315d052d42bbde8a488` and did not contain `m1-elk/setup_security.sh`. The old short bind syntax could silently create a directory when a source path was missing, making the test setup itself ambiguous.

The final replacement hardens this failure mode:

- host bind mounts use long syntax with `bind.create_host_path: false`;
- `setup_security.sh` verifies all mounted setup inputs are readable regular files before contacting Elasticsearch;
- the raw-ingestion health check allows a longer readiness window for slower ARM64/self-hosted first-start conditions.

A missing setup file can no longer silently turn into a directory and continue as if bootstrap succeeded.

## Final GitHub CI evidence

Final head `2e6fab7cffaff14fb063d7ed225bd1672770d444` passed both workflow triggers:

- push run `37302161258`, integration job `111737196390`: **success**
- pull-request run `37302167847`, integration job `111737217588`: **success**

Both final runs passed:

- static JSON, shell, PowerShell, and Docker Compose validation;
- secured Elasticsearch 8.12 startup;
- one-shot security bootstrap;
- Logstash pipeline readiness;
- Kibana reachability;
- raw TCP ingestion into `tracehunt-raw-*`;
- M3-shaped normalized indexing;
- M4 read-only retrieval;
- explicit HTTP 403 on attempted M4 write;
- clean stack shutdown and volume removal.

## Independent Oracle VPS evidence

Validation host:

- Docker 29.6.1
- Docker Compose v5.3.1
- architecture: ARM64
- M1 stack validation head: `66c86dcb46fc11c47a1f4650c5a8002c97718d46`
- current M3 PR #7 validation head: `ebd77c7548e1c58224576b2eeda3ecb8e4466404`

The only M1 change after the VPS stack validation was `2e6fab7`, which fixed PowerShell newline formatting in the already-tested ARM64 retry-window change. The two final GitHub Actions runs above validate that exact final PR head.

The VPS final validation reported:

```text
{"accepted":5,"processed":5,"quarantined":0}
m3_bulk_export=5_events
security_setup_exit=0
cluster_health=green
bootstrap_resources=ok
logstash_kibana_ports=ok
raw_ingestion=ok
m3_bulk_ingestion=ok routes={"sysmon": 1, "windows-security": 2, "zeek": 2}
m4_read_allowed_write_denied=ok
least_privilege_contract=ok
FINAL_M1_VPS_VALIDATION=SUCCESS
```

This proves the real M3 bulk-export path is accepted by the merged M1 mapping and can be read through the exact M4 least-privilege account.

A focused ARM64 raw-ingestion diagnostic also confirmed the Logstash writer and raw pipeline independently:

```text
raw_event_found_after_s=2
RAW_DIAGNOSTIC=SUCCESS
```

The final validation scope exited and the VPS agent reported no background jobs remaining.

## Final M1 deliverable checklist

| Deliverable | Final state |
|---|---|
| Shared Elasticsearch / Logstash / Kibana Compose stack | Complete |
| Elasticsearch security enabled | Complete |
| Localhost-only published service ports | Complete |
| One-shot security bootstrap | Complete |
| Bootstrap fails hard on missing mounted inputs | Complete |
| Least-privilege Logstash writer for `tracehunt-raw-*` | Complete |
| M4 `tracehunt_ro` read-only account | Complete |
| M4 write denial | Verified |
| Raw landing index template | Complete |
| Normalized M3 production index template | Complete |
| Raw Logstash ingestion | Verified in CI and ARM64 VPS |
| M3 real bulk export compatibility | Verified |
| M3 -> M1 -> M4 integration | Verified |
| GitHub clean-stack integration CI | Green |
| Independent Oracle VPS portability | Green |
| Clean shutdown / no validation leftovers | Verified |
| Replacement merged to `main` | Complete |

## Verdict

**M1 = 100% complete for its defined TraceHunt scope.**

Future M2/M3/M4 integration work should treat the merged M1 contracts on `main` as the shared ELK source of truth.
