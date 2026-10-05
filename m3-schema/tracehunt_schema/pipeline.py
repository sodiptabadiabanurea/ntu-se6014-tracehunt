"""Connector-facing API. Every input becomes an accepted or quarantined result."""

from copy import deepcopy

from .classifier import SOURCES, classify
from .config import Config
from .errors import RecordError, SchemaError
from .fields import canonical_json, digest, safe_repr, validate_json_value, validate_raw_text
from .parser import normalize
from .registry import SchemaRegistry


class SchemaPipeline:
    def __init__(self, registry: SchemaRegistry | None = None, config: Config | None = None):
        self.registry = registry or SchemaRegistry()
        self.config = config or Config()

    def process(self, record, source_hint: str | None = None, raw_text: str | None = None,
                schema_id: str | None = None, schema_version: str | None = None) -> dict:
        source = source_hint
        spec = None
        safe_record = None
        try:
            try:
                validate_json_value(record)
                canonical_json(record)
            except (ValueError, TypeError, RecursionError) as exc:
                raise RecordError("invalid_record", str(exc)) from exc
            safe_record = record
            if not isinstance(record, dict):
                raise RecordError("invalid_record", "each event must be a JSON object")
            validate_raw_text(raw_text)
            if schema_version and not schema_id:
                raise RecordError("invalid_schema_pin", "schema_version requires schema_id")
            source = classify(record, source_hint)
            if schema_id:
                spec = self.registry.get_schema(schema_id, schema_version)
                if source is not None and spec["source"] != source:
                    raise RecordError("source_mismatch", "pinned parser and source hint/detection disagree")
                if spec["source"] == "custom-json":
                    from .fields import leaf_paths
                    if leaf_paths(record) != spec["signature"]:
                        raise RecordError("signature_mismatch", "record fields differ from the approved sample")
                source = spec["source"]
            else:
                spec = self.registry.select(source, record)
            if spec is None:
                raise RecordError("unknown_format", "no approved parser; infer and validate a candidate first")
            index = self.config.routes.get(spec["source"])
            if index is None:
                raise RecordError("missing_route", "no output index configured for this source")
            event = normalize(record, spec, self.config, raw_text)
            doc_id = digest({"source": spec["source"], "schema_id": spec["id"],
                             "schema_version": spec["version"], "schema_hash": digest(spec),
                             "ecs_version": self.config.ecs_version,
                             "naive_timezone": self.config.naive_timezone,
                             "record": record})
            return {"status": "accepted", "source": spec["source"], "index": index,
                    "document_id": doc_id, "schema_id": spec["id"],
                    "schema_version": spec["version"], "event": event}
        except (RecordError, SchemaError) as exc:
            issue = exc.as_dict() if isinstance(exc, RecordError) else {
                "code": "schema_error", "field": None, "message": str(exc)}
            if raw_text is None and safe_record is None:
                raw_text = safe_repr(record)
            else:
                try:
                    validate_raw_text(raw_text)
                except RecordError:
                    raw_text = safe_repr(raw_text)
            # Preserve the input text even when the input could not be decoded.
            return {"status": "quarantined", "source": source if source in SOURCES else None,
                    "schema_id": spec["id"] if spec else None,
                    "schema_version": spec["version"] if spec else None,
                    "errors": [issue], "raw_record": deepcopy(safe_record), "raw_text": raw_text}
