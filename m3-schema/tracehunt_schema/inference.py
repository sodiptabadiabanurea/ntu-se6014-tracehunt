"""Deterministic candidate generation used by manual tools and the schema agent.

This module proposes declarative mappings. It does not activate a parser,
execute generated code, invent enrichment, or claim to be an LLM agent.
"""

from .config import Config
from .errors import RecordError, SchemaError
from .fields import digest, leaf_paths, validate_record
from .parser import normalize
from .registry import FIELD_TYPES, validate_definition

ALIASES = {
    "@timestamp": ["event_time", "time", "timestamp", "ts", "@timestamp"],
    "host.name": ["machine", "hostname", "host_name", "host.name"],
    "user.name": ["account", "username", "user_name", "user.name"],
    "event.code": ["code", "event_code", "event.code"],
    "process.executable": ["executable", "image", "process.executable"],
    "process.command_line": ["cmd", "command", "command_line", "process.command_line"],
    "source.ip": ["origin_ip", "src_ip", "source_ip", "source.ip"],
    "destination.ip": ["target_ip", "dst_ip", "destination_ip", "destination.ip"],
    "destination.port": ["target_port", "dst_port", "destination.port"],
}


def infer_candidate(samples: list[dict], schema_id: str = "custom-json",
                    version: str = "1.0.0", config: Config | None = None) -> dict:
    config = config or Config()
    if not samples or not all(isinstance(s, dict) for s in samples):
        raise SchemaError("candidate generation requires non-empty JSON object samples")
    for sample in samples:
        validate_record(sample)
    signature = leaf_paths(samples[0])
    if any(leaf_paths(s) != signature for s in samples):
        raise SchemaError("use a batch with one consistent field signature")
    mappings = []
    for target, aliases in ALIASES.items():
        present = [alias for alias in aliases if alias in signature]
        if len(present) > 1:
            raise SchemaError(f"ambiguous aliases for {target}: {present}; review the mapping explicitly")
        if present:
            mappings.append({"target": target, "sources": present, "type": FIELD_TYPES[target]})
    if not any(m["target"] == "@timestamp" for m in mappings):
        raise SchemaError("no supported timestamp field found; provide a reviewed mapping")
    if len(mappings) < 2:
        raise SchemaError("a candidate needs a timestamp and at least one meaningful event field")
    spec = {"id": schema_id, "version": version, "source": "custom-json",
            "dataset": "custom.json", "description": "Rule-generated candidate; review field semantics before approval.",
            "signature": signature, "required": ["@timestamp"], "mappings": mappings}
    validate_definition(spec)
    results = []
    for number, sample in enumerate(samples, 1):
        try:
            normalize(sample, spec, config)
            results.append({"sample": number, "status": "passed", "errors": []})
        except RecordError as exc:
            results.append({"sample": number, "status": "failed", "errors": [exc.as_dict()]})
    mapped_sources = {s for m in mappings for s in m["sources"]}
    return {"status": "candidate", "generator": "deterministic-alias-rules",
            "schema": spec, "sample_hash": digest(samples),
            "validation": {"passed": all(r["status"] == "passed" for r in results),
                           "sample_count": len(samples), "results": results},
            "unmapped_fields": sorted(set(signature) - mapped_sources),
            "review_required": True}
