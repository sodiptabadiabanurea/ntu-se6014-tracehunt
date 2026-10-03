"""Apply declarative ECS mappings, conversions, and source-specific checks."""

from datetime import datetime, timedelta, timezone
import ipaddress
import math
import ntpath
import re
from urllib.parse import urlsplit

from .config import Config
from .errors import RecordError
from .fields import MISSING, canonical_json, digest, get_field, set_field, validate_record


def timestamp(value, naive_timezone: str | None = None) -> str:
    if isinstance(value, bool):
        raise ValueError("boolean values are not timestamps")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("timestamp must be finite")
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        # Zeek can encode epoch seconds as a JSON number or numeric string.
        try:
            epoch = float(text)
        except ValueError:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        else:
            if not math.isfinite(epoch):
                raise ValueError("timestamp must be finite")
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        if dt.tzinfo is None:
            if naive_timezone is None:
                raise ValueError("timestamp has no timezone; configure naive_timezone explicitly")
            sign = -1 if naive_timezone[0] == "-" else 1
            hours, minutes = map(int, naive_timezone[1:].split(":"))
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes)))
    else:
        raise ValueError("timestamp must be an ISO-8601 string or epoch seconds")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def convert(value, kind: str, config: Config):
    if kind == "timestamp":
        return timestamp(value, config.naive_timezone)
    if kind in ("keyword", "text"):
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("expected a string or integer identifier")
        text = str(value).strip() if kind == "keyword" else str(value)
        if kind == "keyword" and not text:
            raise ValueError("identifier must not be empty or whitespace-only")
        return text
    if kind == "ip":
        if not isinstance(value, str):
            raise ValueError("IP address must be a string")
        return str(ipaddress.ip_address(value))
    if kind in ("integer", "port"):
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("expected an integer or integer string")
        number = int(value)
        maximum = 65535 if kind == "port" else 2**63 - 1
        if not 0 <= number <= maximum:
            raise ValueError("integer is outside the allowed range")
        return number
    raise ValueError(f"unsupported conversion: {kind}")


def windows_event_code(value) -> str:
    """Canonical decimal codes preserve source-specific validation rules."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Windows event code must be a non-negative decimal integer")
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError("Windows event code must contain only decimal digits")
    return str(int(text))


def http_host_domain(value, config: Config) -> str:
    """Extract the ECS URL domain from an HTTP Host authority, without its port."""
    if not isinstance(value, str):
        raise ValueError("HTTP Host must be a string")
    authority = convert(value, "keyword", config)
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in authority) or any(
        character in authority for character in "/\\?#@"
    ):
        raise ValueError("HTTP Host must not contain controls, whitespace, or URI delimiters")
    parsed = urlsplit("//" + authority)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or (
        parsed.path or parsed.query or parsed.fragment
    ):
        raise ValueError("HTTP Host must contain only a host and optional port")
    # Accessing port validates its syntax and range; connection ports stay separate.
    parsed.port
    return f"[{parsed.hostname}]" if authority.startswith("[") else parsed.hostname


def normalize(record: dict, spec: dict, config: Config,
              raw_text: str | None = None) -> dict:
    validate_record(record, raw_text)
    event = {}
    for mapping in spec["mappings"]:
        value = MISSING
        selected_source = None
        for source in mapping["sources"]:
            candidate = get_field(record, source)
            if mapping["target"] == "host.name" and source == "host" and isinstance(candidate, dict):
                # An ECS host object is not the legacy scalar computer-name alias.
                continue
            if candidate is not MISSING and candidate is not None and candidate not in ("", "-"):
                value = candidate
                selected_source = source
                break
        if value is MISSING:
            continue
        try:
            if mapping["target"] == "@timestamp" and selected_source in ("winlog.event_data.UtcTime", "UtcTime"):
                # Sysmon's UtcTime is explicitly UTC even without an offset.
                converted = timestamp(value, "+00:00")
            elif mapping["target"] == "event.code" and spec["source"] in ("windows-security", "sysmon"):
                converted = windows_event_code(value)
            else:
                converted = convert(value, mapping["type"], config)
            set_field(event, mapping["target"], converted)
        except (ValueError, TypeError, OverflowError, OSError) as exc:
            raise RecordError("invalid_field", str(exc), mapping["target"]) from exc

    for required in spec["required"]:
        value = get_field(event, required)
        if value is MISSING or value == "":
            raise RecordError("missing_field", "required field is missing", required)

    source = spec["source"]
    if source == "custom-json" and not any(
        get_field(event, m["target"]) is not MISSING
        for m in spec["mappings"] if m["target"] != "@timestamp"
    ):
        raise RecordError("missing_field", "custom events need at least one mapped event field")
    code = get_field(event, "event.code", None)
    if source == "windows-security" and code in ("4624", "4625"):
        if get_field(event, "user.name") is MISSING:
            raise RecordError("missing_field", "logon events need a target account", "user.name")
        set_field(event, "event.outcome", "success" if code == "4624" else "failure")
    if source == "sysmon" and code == "1" and get_field(event, "process.executable") is MISSING:
        raise RecordError("missing_field", "process creation needs an executable", "process.executable")

    for path in ("process.executable", "process.parent.executable"):
        executable = get_field(event, path)
        if executable is not MISSING:
            name = ntpath.basename(executable)
            if name in ("", ".", "..") or "\x00" in executable:
                raise RecordError("invalid_field", "executable path must contain a filename", path)
            set_field(event, path.replace("executable", "name"), name)
    user = get_field(event, "user.name")
    if isinstance(user, str) and "\\" in user:
        domain, account = (part.strip() for part in user.split("\\", 1))
        if not account:
            raise RecordError("invalid_field", "domain-qualified username has no account", "user.name")
        set_field(event, "user.name", account)
        if get_field(event, "user.domain") is MISSING and domain:
            set_field(event, "user.domain", domain)

    dataset = spec["dataset"]
    if source == "zeek":
        existing = str(get_field(record, "event.dataset", ""))
        log_type = record.get("log_type")
        if log_type is not None and not isinstance(log_type, str):
            raise RecordError("invalid_field", "Zeek log_type must be a string", "log_type")
        if not log_type and existing.startswith("zeek."):
            log_type = existing.split(".", 1)[1]
        if not log_type:
            log_type = "dns" if get_field(event, "dns.question.name") is not MISSING else (
                "http" if get_field(event, "http.request.method") is not MISSING else "conn")
        if log_type not in ("conn", "dns", "http"):
            raise RecordError("unsupported_format", "supported Zeek logs are conn, dns, and http", "log_type")
        dataset = f"zeek.{log_type}"
        # Zeek HTTP's bare host is the request authority. Explicit ECS host.name
        # remains computer metadata, including when host is a nested object.
        http_host = record.get("host", MISSING)
        if log_type == "http" and get_field(event, "url.domain") is MISSING and (
            http_host is not MISSING and http_host is not None
            and http_host not in ("", "-") and not isinstance(http_host, dict)
        ):
            try:
                set_field(event, "url.domain", http_host_domain(http_host, config))
            except (ValueError, TypeError) as exc:
                raise RecordError("invalid_field", str(exc), "url.domain") from exc
    set_field(event, "event.dataset", dataset)
    set_field(event, "event.module", {"windows-security": "windows", "sysmon": "sysmon",
                                     "zeek": "zeek", "custom-json": "custom"}[source])
    set_field(event, "event.kind", "event")
    set_field(event, "ecs.version", config.ecs_version)
    set_field(event, "event.original", raw_text if raw_text is not None else canonical_json(record))
    set_field(event, "tracehunt.source_type", source)
    set_field(event, "tracehunt.source_hash", digest(record))
    set_field(event, "tracehunt.schema.id", spec["id"])
    set_field(event, "tracehunt.schema.version", spec["version"])
    set_field(event, "tracehunt.schema.hash", digest(spec))
    return event
