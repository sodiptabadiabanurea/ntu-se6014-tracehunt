"""Helpers for both nested JSON and literal dotted field names."""

import hashlib
import json
import math
import reprlib

from .errors import RecordError

MISSING = object()
MAX_JSON_DEPTH = 64


def validate_json_value(value) -> None:
    """Reject unsafe input before recursive mapping, copying, or hashing.

    Walk iteratively so deep or cyclic Python input becomes a record failure,
    rather than exhausting the call stack. Shared, non-cyclic objects are valid.
    """
    pending = [(value, 0, False)]
    active = set()
    while pending:
        current, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(current))
            continue
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        if isinstance(current, (dict, list)):
            if id(current) in active:
                raise ValueError("JSON values must not contain cycles")
            active.add(id(current))
            pending.append((current, depth, True))
            if isinstance(current, dict):
                for key, child in current.items():
                    if not isinstance(key, str):
                        raise ValueError("JSON object keys must be strings")
                    key.encode("utf-8")
                    pending.append((child, depth + 1, False))
            else:
                pending.extend((child, depth + 1, False) for child in current)
        elif isinstance(current, str):
            current.encode("utf-8")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("JSON numbers must be finite")
        elif current is not None and not isinstance(current, (int, bool)):
            raise ValueError("event must contain only JSON-compatible values")


def safe_repr(value) -> str:
    """Keep invalid API input describable even when Python cannot render it."""
    for render in (repr, reprlib.repr):
        try:
            return render(value).encode("utf-8", errors="backslashreplace").decode("utf-8")
        except Exception:
            # Rendering unsupported input is best-effort and must not abort a batch.
            continue
    return "<input representation unavailable>"


def validate_raw_text(raw_text) -> None:
    if raw_text is None:
        return
    if not isinstance(raw_text, str):
        raise RecordError("invalid_field", "raw_text must be a Unicode string", "event.original")
    try:
        raw_text.encode("utf-8")
    except UnicodeError as exc:
        raise RecordError("invalid_field", "raw_text contains invalid Unicode", "event.original") from exc


def validate_record(record, raw_text=None) -> None:
    if not isinstance(record, dict):
        raise RecordError("invalid_record", "each event must be a JSON object")
    try:
        validate_json_value(record)
        canonical_json(record)
    except (ValueError, TypeError, RecursionError) as exc:
        raise RecordError("invalid_record", str(exc)) from exc
    validate_raw_text(raw_text)
    leaf_paths(record)


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def get_field(record: dict, path: str, default=MISSING):
    current = record
    parts = path.split(".")
    position = 0
    while position < len(parts):
        if not isinstance(current, dict):
            return default
        # Prefer the longest literal key, then descend into its nested object.
        # This supports mixtures such as {"winlog.event_data": {"Image": ...}}.
        for end in range(len(parts), position, -1):
            key = ".".join(parts[position:end])
            if key in current:
                current = current[key]
                position = end
                break
        else:
            return default
    return current


def set_field(record: dict, path: str, value) -> None:
    parts = path.split(".")
    current = record
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        if not isinstance(current[part], dict):
            raise ValueError(f"field path conflicts with a scalar: {path}")
        current = current[part]
    current[parts[-1]] = value


def leaf_paths(record: dict, prefix: str = "") -> list[str]:
    values = {}

    def visit(current, parent):
        for key, value in current.items():
            path = f"{parent}.{key}" if parent else key
            if isinstance(value, dict) and value:
                visit(value, path)
            else:
                if path in values and canonical_json(values[path]) != canonical_json(value):
                    raise RecordError("ambiguous_field", "nested and dotted field values disagree", path)
                values[path] = value

    visit(record, prefix)
    return sorted(values)
