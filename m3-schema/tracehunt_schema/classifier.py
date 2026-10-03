"""Conservative source detection; connector-provided source hints take priority."""

from .fields import get_field, MISSING
from .errors import RecordError

SOURCES = ("windows-security", "sysmon", "zeek", "custom-json")


def metadata_text(record: dict, field: str) -> str:
    value = get_field(record, field, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RecordError("invalid_field", "source metadata must be a string", field)
    return value.strip()


def classify(record: dict, source_hint: str | None = None) -> str | None:
    if source_hint is not None:
        if source_hint not in SOURCES:
            raise RecordError("invalid_source", f"source must be one of {SOURCES}")
        return source_hint

    provider = metadata_text(record, "winlog.provider_name")
    provider += " " + metadata_text(record, "event.provider")
    channel = metadata_text(record, "winlog.channel").lower()
    dataset = metadata_text(record, "event.dataset").lower()
    if "sysmon" in provider.lower() or "sysmon" in channel or dataset.startswith("sysmon"):
        return "sysmon"
    if channel == "security" or "security-auditing" in provider.lower() or dataset == "windows.security":
        return "windows-security"
    if dataset.startswith("zeek.") or record.get("log_type") in ("conn", "dns", "http"):
        return "zeek"
    if get_field(record, "id.orig_h") is not MISSING and get_field(record, "id.resp_h") is not MISSING:
        return "zeek"
    if "log_type" in record and any(get_field(record, field) is not MISSING for field in (
        "source.ip", "src_ip"
    )) and any(get_field(record, field) is not MISSING for field in ("destination.ip", "dst_ip")):
        return "zeek"
    # Distinctive source fields still identify malformed known records. They
    # must fail the bundled parser instead of onboarding as a custom format.
    if any(get_field(record, field) is not MISSING for field in ("UtcTime", "winlog.event_data.UtcTime")) and any(
        get_field(record, field) is not MISSING for field in ("Image", "winlog.event_data.Image", "process.executable")
    ):
        return "sysmon"
    if any(get_field(record, field) is not MISSING for field in (
        "winlog.event_data.TargetUserName", "TargetUserName", "winlog.event_data.LogonType", "LogonType", "logon_type"
    )):
        return "windows-security"

    event_code = MISSING
    for field in ("event.code", "winlog.event_id", "event_id", "EventID"):
        candidate = get_field(record, field)
        if candidate is not MISSING and candidate is not None and candidate not in ("", "-"):
            event_code = candidate
            break
    try:
        code = int(event_code)
    except (TypeError, ValueError, OverflowError):
        return None
    if 4600 <= code <= 4999:
        return "windows-security"
    if 1 <= code <= 29 and any(get_field(record, field) is not MISSING for field in (
        "process.executable", "winlog.event_data.Image", "process_name", "Image",
        "process.command_line", "winlog.event_data.CommandLine", "command_line", "CommandLine"
    )):
        return "sysmon"
    return None
