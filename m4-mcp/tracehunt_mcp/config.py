"""Environment-driven configuration for the TraceHunt MCP server.

All behavioural limits live here so the hunt workflow (M5) and the
reviewers can see the guardrails in one place. Values are read from
environment variables with the TRACEHUNT_ prefix.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,127}$")


def _env_str(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _default_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"run-{stamp}-{secrets.token_hex(3)}"


@dataclass(frozen=True)
class Config:
    es_url: str
    es_username: str | None
    es_password: str | None
    es_ca_cert: str | None
    indices: tuple[str, ...]
    ledger_path: str
    run_id: str
    default_size: int
    max_size: int
    max_window_hours: int
    request_timeout_s: int
    max_scan: int
    max_doc_ids: int
    max_seq_steps: int
    max_agg_buckets: int

    @classmethod
    def from_env(cls) -> "Config":
        indices_raw = _env_str("TRACEHUNT_INDICES", "windows-security,sysmon,zeek")
        indices = tuple(part.strip() for part in (indices_raw or "").split(",") if part.strip())
        if not indices:
            raise ValueError("TRACEHUNT_INDICES must list at least one index")
        for name in indices:
            if not _INDEX_RE.match(name):
                raise ValueError(f"invalid index name in TRACEHUNT_INDICES: {name!r}")

        default_size = _env_int("TRACEHUNT_DEFAULT_SIZE", 50)
        max_size = _env_int("TRACEHUNT_MAX_SIZE", 500)
        return cls(
            es_url=(_env_str("TRACEHUNT_ES_URL", "http://localhost:9200") or "").rstrip("/"),
            es_username=_env_str("TRACEHUNT_ES_USERNAME"),
            es_password=_env_str("TRACEHUNT_ES_PASSWORD"),
            es_ca_cert=_env_str("TRACEHUNT_ES_CA_CERT"),
            indices=indices,
            ledger_path=_env_str("TRACEHUNT_LEDGER_PATH", "evidence/ledger.jsonl") or "evidence/ledger.jsonl",
            run_id=_env_str("TRACEHUNT_RUN_ID") or _default_run_id(),
            default_size=min(default_size, max_size),
            max_size=max_size,
            max_window_hours=_env_int("TRACEHUNT_MAX_WINDOW_HOURS", 72),
            request_timeout_s=_env_int("TRACEHUNT_REQUEST_TIMEOUT_S", 10),
            max_scan=_env_int("TRACEHUNT_MAX_SCAN", 2000),
            max_doc_ids=_env_int("TRACEHUNT_MAX_DOC_IDS", 100),
            max_seq_steps=_env_int("TRACEHUNT_MAX_SEQ_STEPS", 5),
            max_agg_buckets=_env_int("TRACEHUNT_MAX_AGG_BUCKETS", 100),
        )
