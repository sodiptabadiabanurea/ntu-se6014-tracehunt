"""Immutable versioned parser definitions and a local approved registry."""

from copy import deepcopy
import json
from pathlib import Path
import re

from .errors import SchemaError
from .fields import canonical_json, digest, leaf_paths, validate_json_value, validate_record
from .io import decode

# Each supported destination has exactly one conversion contract.
FIELD_TYPES = {
    "@timestamp": "timestamp", "event.code": "keyword", "event.id": "keyword",
    "host.name": "keyword", "user.name": "keyword", "user.domain": "keyword",
    "source.ip": "ip", "destination.ip": "ip",
    "source.port": "port", "destination.port": "port",
    "process.executable": "keyword", "process.command_line": "text",
    "process.pid": "integer", "process.entity_id": "keyword",
    "process.parent.executable": "keyword", "process.parent.pid": "integer",
    "process.parent.entity_id": "keyword", "dns.question.name": "keyword",
    "http.request.method": "keyword", "http.response.status_code": "integer",
    "url.original": "text", "url.domain": "keyword", "user_agent.original": "text",
    "network.transport": "keyword", "winlog.logon.type": "integer",
    "winlog.event_data.Status": "keyword", "winlog.record_id": "keyword",
}


def validate_definition(spec: dict) -> None:
    if not isinstance(spec, dict):
        raise SchemaError("schema must be an object")
    try:
        validate_json_value(spec)
        canonical_json(spec)
    except (ValueError, TypeError, RecursionError) as exc:
        raise SchemaError(f"schema must contain valid JSON values: {exc}") from exc
    for key in ("id", "version", "source", "dataset", "mappings", "required"):
        if key not in spec:
            raise SchemaError(f"schema is missing {key}")
    if not isinstance(spec["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", spec["id"]):
        raise SchemaError("schema id must be a lowercase identifier")
    if not isinstance(spec["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spec["version"]):
        raise SchemaError("schema version must have three numeric components")
    try:
        tuple(map(int, spec["version"].split(".")))
    except ValueError as exc:
        raise SchemaError("schema version components exceed the supported numeric length") from exc
    if spec["source"] not in ("windows-security", "sysmon", "zeek", "custom-json"):
        raise SchemaError("schema source is not supported")
    if not isinstance(spec["dataset"], str) or not re.fullmatch(r"[a-z][a-z0-9_.-]+", spec["dataset"]):
        raise SchemaError("dataset must be a lowercase name")
    if not isinstance(spec["mappings"], list) or not spec["mappings"]:
        raise SchemaError("mappings must be a non-empty list")
    targets = set()
    for mapping in spec["mappings"]:
        if not isinstance(mapping, dict):
            raise SchemaError("each mapping must be an object")
        target = mapping.get("target")
        if not isinstance(target, str) or target not in FIELD_TYPES or target in targets:
            raise SchemaError(f"unsupported or duplicate mapping target: {target}")
        targets.add(target)
        if mapping.get("type") != FIELD_TYPES[target]:
            raise SchemaError(f"incorrect conversion type for {target}")
        sources = mapping.get("sources")
        if not isinstance(sources, list) or not sources or not all(
            isinstance(s, str) and s and len(s) <= 256 for s in sources
        ):
            raise SchemaError(f"invalid source paths for {target}")
    required = spec["required"]
    if not isinstance(required, list) or not all(isinstance(s, str) for s in required):
        raise SchemaError("required must be a list of field paths")
    if "@timestamp" not in required or not set(required).issubset(targets):
        raise SchemaError("required fields must include @timestamp and have mappings")
    if spec["source"] == "custom-json":
        signature = spec.get("signature")
        if not isinstance(signature, list) or not signature or not all(isinstance(s, str) for s in signature):
            raise SchemaError("custom parsers require a non-empty field signature")
        if signature != sorted(set(signature)):
            raise SchemaError("signature must contain sorted unique field paths")


class SchemaRegistry:
    """Definitions are copied on read; (id, version) cannot be overwritten."""

    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory) if directory else None
        self._definitions: dict[tuple[str, str], dict] = {}
        builtin = Path(__file__).parent / "schemas"
        for path in sorted(builtin.glob("*.json")):
            self._insert(self._read_definition(path))
        if self.directory and self.directory.exists():
            if not self.directory.is_dir():
                raise SchemaError("registry must be a directory")
            for path in sorted(self.directory.glob("*.json")):
                self._insert(self._read_definition(path))

    @staticmethod
    def _read_definition(path):
        try:
            return decode(path.read_text(encoding="utf-8-sig"))
        except (ValueError, TypeError, RecursionError) as exc:
            raise SchemaError(f"invalid schema file {path.name}: {exc}") from exc

    def _insert(self, spec: dict):
        validate_definition(spec)
        key = (spec["id"], spec["version"])
        if key in self._definitions:
            if self._definitions[key] != spec:
                raise SchemaError(f"schema version is immutable: {key}")
            return
        self._definitions[key] = deepcopy(spec)

    def list_schemas(self) -> list[dict]:
        return [deepcopy(spec) for _, spec in sorted(self._definitions.items())]

    def get_schema(self, schema_id: str, version: str | None = None) -> dict:
        candidates = [s for (sid, ver), s in self._definitions.items()
                      if sid == schema_id and (version is None or version == ver)]
        if not candidates:
            raise SchemaError(f"schema not found: {schema_id} {version or ''}".strip())
        return deepcopy(max(candidates, key=lambda s: tuple(map(int, s["version"].split(".")))))

    def select(self, source: str | None, record: dict) -> dict | None:
        validate_record(record)
        signature = leaf_paths(record)
        candidates = [s for s in self._definitions.values()
                      if (source in (None, "custom-json") and s["source"] == "custom-json"
                          and s["signature"] == signature)
                      or (source not in (None, "custom-json") and s["source"] == source)]
        if not candidates:
            return None
        # Different definitions for an identical shape need an explicit decision.
        if len({s["id"] for s in candidates}) > 1:
            raise SchemaError("ambiguous parser selection; pin a schema id and version")
        return deepcopy(max(candidates, key=lambda s: tuple(map(int, s["version"].split(".")))))

    def approve(self, spec: dict, samples: list[dict], config=None,
                expected_events: list[dict] | None = None) -> dict:
        """Validate every supplied sample before activating a custom definition."""
        from .parser import normalize
        from .config import Config
        validate_definition(spec)
        if spec["source"] != "custom-json":
            raise SchemaError("approval is for custom candidates; bundled parsers are shipped in code")
        if not samples or not all(isinstance(s, dict) for s in samples):
            raise SchemaError("approval requires non-empty JSON object samples")
        for sample in samples:
            validate_record(sample)
        if any(leaf_paths(s) != spec["signature"] for s in samples):
            raise SchemaError("sample field signature differs from the candidate")
        events = [normalize(s, spec, config or Config()) for s in samples]
        if expected_events is not None and events != expected_events:
            raise SchemaError("normalized events do not match the golden expected events")
        key = (spec["id"], spec["version"])
        if key in self._definitions and self._definitions[key] != spec:
            raise SchemaError(f"schema version is immutable: {key}")
        # No registry file is written until all samples have passed.
        if self.directory:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / f"{spec['id']}-{spec['version']}.json"
            text = json.dumps(spec, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
            if path.exists():
                if self._read_definition(path) != spec:
                    raise SchemaError("an approved schema version cannot be replaced")
            else:
                with path.open("x", encoding="utf-8") as stream:
                    stream.write(text)
        self._insert(spec)
        return {"status": "approved", "schema_id": spec["id"], "schema_version": spec["version"],
                "schema_hash": digest(spec), "validated_samples": len(events)}
