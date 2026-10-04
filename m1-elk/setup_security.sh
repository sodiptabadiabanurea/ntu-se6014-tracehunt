#!/bin/sh
set -eu

python3 - <<'PY'
import base64
import json
import os
import urllib.error
import urllib.request

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200").rstrip("/")
required = (
    "ELASTIC_PASSWORD",
    "KIBANA_SYSTEM_PASSWORD",
    "LOGSTASH_WRITER_PASSWORD",
    "TRACEHUNT_RO_PASSWORD",
)
missing = [name for name in required if not os.environ.get(name)]
if missing:
    raise SystemExit("missing required environment variables: " + ", ".join(missing))

ELASTIC_PASSWORD = os.environ["ELASTIC_PASSWORD"]
KIBANA_SYSTEM_PASSWORD = os.environ["KIBANA_SYSTEM_PASSWORD"]
LOGSTASH_WRITER_PASSWORD = os.environ["LOGSTASH_WRITER_PASSWORD"]
TRACEHUNT_RO_PASSWORD = os.environ["TRACEHUNT_RO_PASSWORD"]


def api(method, path, payload=None, *, user="elastic", password=ELASTIC_PASSWORD, expected=(200, 201)):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(ES_URL + path, data=data, method=method)
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    request.add_header("Authorization", f"Basic {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace")
    if status not in expected:
        raise RuntimeError(f"{method} {path} returned HTTP {status}: {body[:500]}")
    return json.loads(body) if body else {}


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


print("[security-setup] verifying Elasticsearch admin authentication")
api("GET", "/")

print("[security-setup] configuring Kibana system password")
api("POST", "/_security/user/kibana_system/_password", {"password": KIBANA_SYSTEM_PASSWORD})

print("[security-setup] configuring least-privilege Logstash writer")
api(
    "PUT",
    "/_security/role/tracehunt_logstash_writer",
    {
        "cluster": ["monitor"],
        "indices": [
            {
                "names": ["tracehunt-raw-*"],
                "privileges": ["write", "create", "create_index"],
            }
        ],
        "run_as": [],
    },
)
api(
    "PUT",
    "/_security/user/logstash_writer",
    {
        "password": LOGSTASH_WRITER_PASSWORD,
        "roles": ["tracehunt_logstash_writer"],
        "full_name": "TraceHunt Logstash writer",
    },
)

print("[security-setup] installing the exact M4 read-only role contract")
readonly_role = load_json("/setup/readonly_role.json")
api("PUT", "/_security/role/tracehunt_mcp_readonly", readonly_role)
api(
    "PUT",
    "/_security/user/tracehunt_ro",
    {
        "password": TRACEHUNT_RO_PASSWORD,
        "roles": ["tracehunt_mcp_readonly"],
        "full_name": "TraceHunt MCP read-only user",
    },
)

print("[security-setup] installing normalized and raw index templates")
api("PUT", "/_index_template/tracehunt_normalized", load_json("/setup/index_template.json"))
api("PUT", "/_index_template/tracehunt_raw", load_json("/setup/raw_index_template.json"))

print("[security-setup] verifying resources")
for endpoint in (
    "/_security/role/tracehunt_logstash_writer",
    "/_security/user/logstash_writer",
    "/_security/role/tracehunt_mcp_readonly",
    "/_security/user/tracehunt_ro",
    "/_index_template/tracehunt_normalized",
    "/_index_template/tracehunt_raw",
):
    api("GET", endpoint)

print("[security-setup] verifying M4 least-privilege boundary")
privileges = api(
    "POST",
    "/_security/user/_has_privileges",
    {
        "cluster": ["monitor"],
        "index": [
            {
                "names": ["windows-security", "sysmon", "zeek"],
                "privileges": ["read", "view_index_metadata", "write"],
            }
        ],
    },
    user="tracehunt_ro",
    password=TRACEHUNT_RO_PASSWORD,
)

if privileges.get("cluster", {}).get("monitor") is not False:
    raise RuntimeError("tracehunt_ro unexpectedly has cluster monitor permission")

index_privileges = privileges.get("index", {})
for index_name in ("windows-security", "sysmon", "zeek"):
    values = index_privileges.get(index_name, {})
    if values.get("read") is not True or values.get("view_index_metadata") is not True:
        raise RuntimeError(f"tracehunt_ro is missing read privileges for {index_name}")
    if values.get("write") is not False:
        raise RuntimeError(f"tracehunt_ro unexpectedly has write privilege for {index_name}")

print("[security-setup] success")
PY
