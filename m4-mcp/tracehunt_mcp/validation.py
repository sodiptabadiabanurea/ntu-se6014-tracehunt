"""Input validation for every MCP tool.

Typed parameters only: no raw query DSL is ever accepted from the agent.
Every rejection states what was wrong and what is allowed, so the calling
agent can correct itself.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .config import Config
from .errors import ToolInputError

ALLOWED_FILTER_OPS = ("eq", "match", "exists")
ALLOWED_SORT = ("asc", "desc")
ALLOWED_AGG_KINDS = ("terms", "date_histogram")
ALLOWED_HISTOGRAM_UNITS = ("minute", "hour", "day")


def validate_index(cfg: Config, index: str) -> str:
    if not isinstance(index, str) or index not in cfg.indices:
        raise ToolInputError(
            f"index {index!r} is not allowed. Allowed indices: {', '.join(cfg.indices)}"
        )
    return index


def parse_time(value: str, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError(f"{field_name} must be an ISO-8601 timestamp string, e.g. 2026-10-01T14:00:00+07:00")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ToolInputError(f"{field_name} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_window(cfg: Config, start_raw: str, end_raw: str) -> tuple[datetime, datetime]:
    start = parse_time(start_raw, "start")
    end = parse_time(end_raw, "end")
    if end <= start:
        raise ToolInputError("end must be strictly after start")
    limit = timedelta(hours=cfg.max_window_hours)
    if end - start > limit:
        raise ToolInputError(
            f"time window {end - start} exceeds the maximum of {cfg.max_window_hours} hours"
        )
    return start, end


def validate_size(cfg: Config, size: int | None) -> int:
    if size is None:
        return cfg.default_size
    if not isinstance(size, int) or isinstance(size, bool):
        raise ToolInputError("size must be an integer")
    if size < 1 or size > cfg.max_size:
        raise ToolInputError(f"size must be between 1 and {cfg.max_size}, got {size}")
    return size


def validate_sort(cfg: Config, sort: str | None) -> str:
    if sort is None:
        return "asc"
    if sort not in ALLOWED_SORT:
        raise ToolInputError(f"sort must be one of {ALLOWED_SORT}, got {sort!r}")
    return sort


def validate_filters(cfg: Config, filters: list[dict] | None) -> list[dict]:
    """Filters are typed: [{field, op, value}]. op is allowlisted."""
    if filters is None:
        return []
    if not isinstance(filters, list):
        raise ToolInputError("filters must be a list of {field, op, value} objects")
    if len(filters) > 10:
        raise ToolInputError("at most 10 filters are allowed per call")
    out: list[dict] = []
    for i, f in enumerate(filters):
        if not isinstance(f, dict):
            raise ToolInputError(f"filters[{i}] must be an object with field, op, value")
        field_name = f.get("field")
        op = f.get("op", "eq")
        value = f.get("value")
        if not isinstance(field_name, str) or not field_name or " " in field_name:
            raise ToolInputError(f"filters[{i}].field must be a non-empty field name")
        if op not in ALLOWED_FILTER_OPS:
            raise ToolInputError(
                f"filters[{i}].op {op!r} is not allowed. Allowed ops: {', '.join(ALLOWED_FILTER_OPS)}"
            )
        if op != "exists" and value is None:
            raise ToolInputError(f"filters[{i}].value is required for op {op!r}")
        if op == "eq" and isinstance(value, str) and len(value) > 512:
            raise ToolInputError(f"filters[{i}].value is too long (max 512 chars)")
        out.append({"field": field_name, "op": op, "value": value})
    return out


def validate_field_name(value: str, field_name: str = "field") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError(f"{field_name} must be a non-empty string")
    if " " in value or len(value) > 256:
        raise ToolInputError(f"{field_name} must not contain spaces and must be at most 256 chars")
    return value.strip()


def validate_agg(cfg: Config, kind: str, field_name: str, interval: str | None) -> dict:
    if kind not in ALLOWED_AGG_KINDS:
        raise ToolInputError(f"kind must be one of {ALLOWED_AGG_KINDS}, got {kind!r}")
    validate_field_name(field_name, "field")
    agg: dict = {"kind": kind, "field": field_name}
    if kind == "date_histogram":
        if not interval:
            raise ToolInputError("interval is required for date_histogram, e.g. 5m, 1h, 1d")
        unit = interval[-1] if interval else ""
        number = interval[:-1] if interval else ""
        unit_names = {"m": "minute", "h": "hour", "d": "day"}
        if unit not in unit_names or not number.isdigit() or int(number) < 1:
            raise ToolInputError(
                "interval must look like 5m, 1h or 1d (minute, hour or day granularity)"
            )
        if unit_names[unit] not in ALLOWED_HISTOGRAM_UNITS:
            raise ToolInputError("interval unit must be minute, hour or day")
        agg["interval"] = f"{number}{unit}"
    return agg


def validate_doc_ids(ids: list[str]) -> list[str]:
    if not isinstance(ids, list) or not ids:
        raise ToolInputError("doc_ids must be a non-empty list of document id strings")
    if len(ids) > 50:
        raise ToolInputError("at most 50 doc_ids can be fetched in one call")
    out: list[str] = []
    for i, doc_id in enumerate(ids):
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ToolInputError(f"doc_ids[{i}] must be a non-empty string")
        if len(doc_id) > 512:
            raise ToolInputError(f"doc_ids[{i}] is too long (max 512 chars)")
        out.append(doc_id.strip())
    return out


def validate_seq_steps(cfg: Config, steps: list[dict]) -> list[dict]:
    if not isinstance(steps, list) or len(steps) < 2:
        raise ToolInputError("steps must be a list of at least 2 step objects")
    if len(steps) > cfg.max_seq_steps:
        raise ToolInputError(f"at most {cfg.max_seq_steps} steps are allowed per sequence")
    out: list[dict] = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ToolInputError(f"steps[{i}] must be an object with name and filters")
        name = step.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ToolInputError(f"steps[{i}].name must be a non-empty string")
        filters = validate_filters(cfg, step.get("filters"))
        out.append({"name": name.strip(), "filters": filters})
    return out


def validate_entity_field(value: str) -> str:
    return validate_field_name(value, "entity_field")
