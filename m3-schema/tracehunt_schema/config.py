"""Schema configuration for ECS version, timestamp handling, and output routes."""

from dataclasses import dataclass, field
from pathlib import Path
import re

from .errors import SchemaError
from .io import decode


@dataclass(frozen=True)
class Config:
    ecs_version: str = "8.11.0"
    naive_timezone: str | None = None
    routes: dict[str, str] = field(default_factory=lambda: {
        "windows-security": "windows-security",
        "sysmon": "sysmon",
        "zeek": "zeek",
        "custom-json": "custom-json",
    })

    def __post_init__(self):
        if not isinstance(self.ecs_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.ecs_version):
            raise SchemaError("ecs_version must be a three-part version")
        if self.naive_timezone is not None and (not isinstance(self.naive_timezone, str) or not re.fullmatch(
            r"[+-](?:0[0-9]|1[0-3]):[0-5][0-9]|[+-]14:00", self.naive_timezone
        )):
            raise SchemaError("naive_timezone must be null or an offset such as +08:00")
        if not isinstance(self.routes, dict) or not self.routes:
            raise SchemaError("routes must be a non-empty object")
        for source, index in self.routes.items():
            if not isinstance(source, str) or not isinstance(index, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9_-]{0,127}", index
            ):
                raise SchemaError("routes must map source names to concrete lowercase indices")

    @classmethod
    def load(cls, path: str | Path | None = None):
        if path is None:
            return cls()
        try:
            value = decode(Path(path).read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise SchemaError("configuration must be a JSON object")
            return cls(**value)
        except (ValueError, TypeError, RecursionError) as exc:
            raise SchemaError(f"invalid configuration: {exc}") from exc
