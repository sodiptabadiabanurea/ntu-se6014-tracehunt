"""Optional offline field-mutation probe for pipeline and batch resilience."""

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline
from tracehunt_schema.fields import canonical_json
from tracehunt_schema.io import load_samples


def leaves(value, path=()):
    for key, child in value.items():
        if isinstance(child, dict) and child:
            yield from leaves(child, path + (key,))
        else:
            yield path + (key,)


def main():
    pipeline = SchemaPipeline()
    values = [None, True, False, 0, -1, 2**63, 10**5000, 1.5, float("nan"), float("inf"),
              "", " ", "-", "NaN", "1_000", "\ud800", "C:\\", "valid", [], {},
              ["value"], {"name": "value"}, b"bytes"]
    probes = []
    failures = []
    for fixture in ("known-mixed.ndjson", "winlogbeat.ndjson", "zeek.ndjson", "sysmon-flat.ndjson"):
        for original in load_samples(ROOT / "fixtures" / fixture):
            known = pipeline.process(original)["source"]
            for path in leaves(original):
                for replacement in values:
                    for hint in (None, known):
                        record = deepcopy(original)
                        parent = record
                        for key in path[:-1]:
                            parent = parent[key]
                        parent[path[-1]] = replacement
                        try:
                            result = pipeline.process(record, source_hint=hint)
                            assert result["status"] in ("accepted", "quarantined")
                            canonical_json(result).encode("utf-8")
                            probes.append(record)
                        except Exception as exc:
                            failures.append({"fixture": fixture, "field": ".".join(path), "hint": hint,
                                             "replacement_type": type(replacement).__name__,
                                             "exception": type(exc).__name__, "message": str(exc)[:160]})

    agent_count = 0
    for offset in range(0, len(probes), 64):
        records = probes[offset:offset + 64]
        try:
            batch = SchemaAgent(frozen=True).process_batch(records)
            assert len(batch["results"]) == len(records)
            canonical_json(batch).encode("utf-8")
            agent_count += len(records)
        except Exception as exc:
            failures.append({"batch_offset": offset, "exception": type(exc).__name__, "message": str(exc)[:160]})

    summary = {"pipeline_mutations": len(probes), "agent_mutations": agent_count,
               "unexpected_failures": len(failures), "examples": failures[:10]}
    report = ROOT / "output" / "whole-review" / "mutation-check.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
