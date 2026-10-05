# M3 Schema Interface

Implemented interface for **tracehunt-schema 1.0.0**. Run Python examples from
`m3-schema` or install the package with `python -m pip install -e .`.

## Input

- Python API: one JSON-compatible `dict`, or a list of records for the agent.
- CLI: UTF-8 NDJSON containing one JSON object per non-empty line.
- Supported sources: `windows-security`, `sysmon`, `zeek`, and `custom-json`.
- `source_hint` is optional; otherwise the source is classified from record fields.
- `raw_text` is optional; valid Unicode strings preserve the original event text exactly.

Bundled parsers accept decoded Windows/Winlogbeat JSON and Zeek conn/DNS/HTTP
JSON, including nested, dotted, and mixed fields. Flat Sysmon `EventID`, `Image`, and
`CommandLine` fields can be classified without a source hint. JSON must contain
finite values, valid Unicode, string object keys, and at most 64 levels of nesting.
CLI decoding rejects duplicate keys. Malformed records are quarantined individually;
later records continue through both `normalize` and `onboard`.
Conflicting nested and dotted values for the same field are rejected. Distinctive
source fields keep malformed known records on their bundled validation path.

## Python API

```python
from tracehunt_schema import SchemaAgent, SchemaPipeline, SchemaRegistry
from tracehunt_schema.config import Config

registry = SchemaRegistry("approved-parsers")
config = Config.load("config.example.json")
pipeline = SchemaPipeline(registry=registry, config=config)
agent = SchemaAgent(registry=registry, config=config)

result = pipeline.process(record, source_hint="sysmon", raw_text=wire_text)
batch = agent.process_batch(records, source_hint=None, raw_texts=wire_texts)
```

`record`/`records` contain input events; `wire_text`/`wire_texts` contain their
optional original text. The API returns results without writing event,
quarantine, or decision files; the CLI persists those outputs.

| Interface | Contract |
|---|---|
| `SchemaPipeline(registry=None, config=None)` | Defaults to bundled parsers and default configuration |
| `process(record, source_hint=None, raw_text=None, schema_id=None, schema_version=None)` | Returns an accepted or quarantined result; a version pin requires an ID |
| `SchemaAgent(registry=None, config=None, generator=None, max_attempts=2, max_samples=16, review_only=False, frozen=False)` | Uses the rules generator by default; attempts range 1-3 and sample limits range 1-64 |
| `process_batch(records, source_hint=None, raw_texts=None)` | Returns ordered `results`, per-format `decisions`, and a `summary`; supplied raw texts must match the input count |
| `SchemaRegistry(directory=None)` | Loads bundled definitions and an optional local registry directory |
| `list_schemas()` / `get_schema(schema_id, version=None)` | Returns copied definitions; an omitted version selects the latest version |
| `select(source, record)` | Returns a matching parser or `None`; ambiguous matches raise `SchemaError` |
| `approve(spec, samples, config=None, expected_events=None)` | Validates custom samples, optionally compares complete golden events, and registers an immutable ID/version |

Agent summaries contain `processed`, `accepted`, `quarantined`, and
`created_schemas`. All records in an unknown-format group are validated before
activation. Review-only mode retains candidates without registration; frozen
mode disables generation. Approved parsers remain usable in both modes.
Invalid parser definitions raise `SchemaError`; file failures raise `OSError`.
Registration conflicts quarantine the affected group without stopping other groups.

## Accepted result

```json
{
  "status": "accepted",
  "source": "windows-security",
  "index": "windows-security",
  "document_id": "<sha256-hex>",
  "schema_id": "windows-security",
  "schema_version": "1.0.0",
  "event": {
    "@timestamp": "2026-09-30T07:00:00.000000Z",
    "event": {"code": "4625", "outcome": "failure"},
    "host": {"name": "WS-01"},
    "user": {"name": "lab-user"}
  }
}
```

The example event is abbreviated. `event` is the document payload; routing and
the stable document ID are outside it. Each complete event retains
`event.original`, `ecs.version`, `tracehunt.source_type`, `tracehunt.source_hash`,
and `tracehunt.schema.id`/`version`/`hash`. Unmapped fields remain in the original.

| Emitted fields | Value type |
|---|---|
| `@timestamp` | UTC ISO 8601 string |
| `event.code`, `event.id`, `host.name`, `user.name`, `user.domain` | String; Windows/Sysmon event codes are canonical non-negative decimal strings |
| `source.ip`, `destination.ip` | Validated IP string |
| `source.port`, `destination.port` | Integer, 0-65535 |
| `process.executable`, `process.name`, `process.command_line`, `process.entity_id` | String |
| `process.pid`, `process.parent.pid` | Integer, 0 through 2^63 - 1 |
| `dns.question.name`, `http.request.method`, `url.original`, `url.domain` | String |
| `http.response.status_code` | Integer, 0 through 2^63 - 1 |

Fields depend on the source record and parser. The full emitted-field mapping
is in [`es/index-template.example.json`](es/index-template.example.json). `document_id` is a hash of
the input, source, parser definition/version, ECS version, and timezone setting.
Bulk exports use it as `_id`; plain event exports do not include routing or `_id`.

For Zeek HTTP, bare `host` is the HTTP Host header and supplies `url.domain`
without its optional port; IPv6 brackets are retained. Explicit nested or dotted
`host.name` supplies computer metadata. Whitespace-only keyword values, including
usernames and executable paths, are invalid; internal spaces in paths are preserved.
Executable paths must contain a filename. All `integer` mappings use the
non-negative signed 64-bit range; `port` mappings retain the 0-65535 range.

## Quarantined result

Failures contain `status: "quarantined"`, `source`, `schema_id`, `schema_version`,
`raw_record`, `raw_text`, and `errors`. Each error has `code`, `field`, and
`message`. Unavailable source/schema/field values may be `null`.

The CLI adds `input_file` and `line_number`, then appends and flushes failures
to the quarantine file. Malformed JSON has `raw_record: null` and preserves
its original line in `raw_text`. Quarantined records are excluded from accepted
exports. `QuarantineWriter(path).append(failure)` is also available from
`tracehunt_schema.io` for single-process file persistence.

Invalid UTF-8 lines also include `raw_bytes_base64` containing the original line
bytes without the line ending; `raw_text` uses replacement characters for display.
Invalid Python API values use `raw_record: null` and a textual representation
when no original text is supplied. Representations of excessively nested inputs
are abbreviated so the quarantine result remains serializable.
Invalid API `raw_text` values are quarantined with an escaped textual representation.

Output files must be outside bundled and custom parser registry directories.
Input, configuration, and output files must be distinct, including hard links.
Configuration and registry JSON readers accept UTF-8 BOMs and reject duplicate keys.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `ecs_version` | `8.11.0` | ECS label attached to emitted events |
| `naive_timezone` | `null` | Reject naive timestamps; an explicit offset such as `+08:00` enables conversion |
| `routes` | Source name mapped to the same index name | Concrete lowercase output indices for the four supported sources |

Sysmon `UtcTime` is explicitly UTC. Custom parsers use exact leaf-field
signatures. Existing `(schema_id, version)` definitions cannot be replaced.
