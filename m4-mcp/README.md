# M4: TraceHunt MCP server

Read-only MCP tools over the ELK stack, with an append-only evidence ledger.
This module is owned by M4 and reviewed by M5.

## What it provides

Seven typed tools, exposed over MCP stdio:

| Tool | Purpose |
|---|---|
| `list_data_sources` | Allowlisted indices, availability, doc counts |
| `get_time_bounds` | Earliest/latest `@timestamp` per index |
| `search_events` | Bounded search: index + time window + typed filters |
| `aggregate_events` | `terms` or `date_histogram` aggregation |
| `run_sequence_query` | Entities present in every named step (sequence check) |
| `fetch_evidence` | Full documents by id (max 50 per call), for citations |
| `get_query_history` | Audit trail of the current hunt run |

Guardrails (all configurable via environment):

- Indices are allowlisted; wildcard or unknown index names are rejected.
- Time windows are mandatory and capped (`TRACEHUNT_MAX_WINDOW_HOURS`, default 72).
- Result size is capped (`TRACEHUNT_MAX_SIZE`, default 500).
- No raw query DSL: filters are typed `{field, op, value}` with `op` limited to `eq`, `match`, `exists`.
- Every call, success or failure, is appended to the evidence ledger before returning: run id, timestamp, tool, exact canonical query, SHA-256 hash, result count, returned doc ids, duration.
- The server only ever issues search/count/mget requests. It holds no write path.

## Layout

```
tracehunt_mcp/    the package (config, validation, queries, backend, ledger, tools, server)
tests/            unit tests (no network; fake ES backend)
dev/              local development stack: docker-compose.yml, seed_lab.py
es/               read-only role definition for the shared stack
```

## Quick start (development)

Requires Python 3.11+ and uv (or plain pip), plus Docker for the dev stack.

```bash
cd m4-mcp
uv venv .venv && uv pip install -p .venv/bin/python -e ".[dev]"

# unit tests, no network needed
.venv/bin/python -m pytest tests/

# local Elasticsearch with lab data
docker compose -f dev/docker-compose.yml up -d
.venv/bin/python dev/seed_lab.py http://localhost:19200

# integration tests against the local ES
TRACEHUNT_ES_URL=http://localhost:19200 TRACEHUNT_LEDGER_PATH=/tmp/m4-ledger.jsonl \
  .venv/bin/python -m pytest tests/test_integration.py

# run the server (stdio)
TRACEHUNT_ES_URL=http://localhost:19200 TRACEHUNT_LEDGER_PATH=/tmp/m4-ledger.jsonl \
  .venv/bin/tracehunt-mcp
```

## Wiring into an agent client

Any MCP client works. Example for a Claude-style client config:

```json
{
  "mcpServers": {
    "tracehunt": {
      "command": "/path/to/m4-mcp/.venv/bin/tracehunt-mcp",
      "env": {
        "TRACEHUNT_ES_URL": "http://localhost:9200",
        "TRACEHUNT_ES_USERNAME": "tracehunt_ro",
        "TRACEHUNT_ES_PASSWORD": "***",
        "TRACEHUNT_LEDGER_PATH": "/path/to/evidence/ledger.jsonl",
        "TRACEHUNT_RUN_ID": "run-hunt-01"
      }
    }
  }
}
```

Set one `TRACEHUNT_RUN_ID` per hunt run so the ledger and the two-run
repeatability experiment (M6) can be sliced by run.

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `TRACEHUNT_ES_URL` | `http://localhost:9200` | Elasticsearch base URL |
| `TRACEHUNT_ES_USERNAME` / `TRACEHUNT_ES_PASSWORD` | unset | Basic auth for secured stacks |
| `TRACEHUNT_ES_CA_CERT` | unset | CA bundle path for TLS stacks |
| `TRACEHUNT_INDICES` | `windows-security,sysmon,zeek` | Allowlist, comma separated |
| `TRACEHUNT_LEDGER_PATH` | `evidence/ledger.jsonl` | Append-only ledger location |
| `TRACEHUNT_RUN_ID` | generated | Hunt run identifier |
| `TRACEHUNT_DEFAULT_SIZE` / `TRACEHUNT_MAX_SIZE` | 50 / 500 | Result size defaults and cap |
| `TRACEHUNT_MAX_WINDOW_HOURS` | 72 | Time window cap |
| `TRACEHUNT_REQUEST_TIMEOUT_S` | 10 | Per-request ES timeout |
| `TRACEHUNT_MAX_SEQ_STEPS` | 5 | Sequence query step cap |
| `TRACEHUNT_MAX_AGG_BUCKETS` | 100 | Aggregation bucket cap |

## Read-only Elasticsearch role (for M1's shared stack)

Create a user the server can authenticate with; the role below only allows
reading the allowlisted indices. Apply it in Kibana Dev Tools or with the
role API:

```bash
curl -u elastic:$ELASTIC_PASSWORD -X PUT "$TRACEHUNT_ES_URL/_security/role/tracehunt_readonly" \
  -H 'Content-Type: application/json' -d @es/readonly_role.json
curl -u elastic:$ELASTIC_PASSWORD -X PUT "$TRACEHUNT_ES_URL/_security/user/tracehunt_ro" \
  -H 'Content-Type: application/json' \
  -d '{"password":"CHANGE_ME","roles":["tracehunt_readonly"],"full_name":"TraceHunt MCP read-only"}'
```

This enforces the read-only contract at the cluster level, not just in code.

## Evidence ledger format

One JSON object per line in `TRACEHUNT_LEDGER_PATH`:

```json
{"seq": 7, "run_id": "run-hunt-01", "ts": "2026-10-01T09:15:02.123+00:00",
 "tool": "search_events", "status": "ok",
 "query": {"index": "windows-security", "start": "...", "end": "...", "filters": [...], "size": 50, "sort": "asc"},
 "query_hash": "sha256-hex", "result_count": 3,
 "doc_ids": ["..."], "doc_ids_truncated": false, "duration_ms": 41}
```

Failed calls are recorded with `"status": "error"` and the message, so a
report can show what was attempted even when the stack was down. The file
is append-only with fsync; never edit it by hand. M5 cites `seq` and
`query_hash` values from it; M6 compares hashes across the two frozen runs.
