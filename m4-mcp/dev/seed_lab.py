#!/usr/bin/env python3
"""Seed the M4 dev Elasticsearch with lab scenario events.

Creates three indices (windows-security, sysmon, zeek) and indexes the
lab story: repeated failed logons for lab-user on WS-01, one successful
remote logon, an encoded PowerShell execution, and an outbound HTTP
connection, plus benign decoy traffic before and after.

Usage: python seed_lab.py [es_url]   (default http://localhost:19200)
"""

from __future__ import annotations

import base64
import json
import sys
import urllib.request

ES = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:19200"

MAPPINGS = {
    "windows-security": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "host": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "logon_type": {"type": "integer"},
                "ip_address": {"type": "ip"},
                "status": {"type": "keyword"},
            }
        }
    },
    "sysmon": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event_id": {"type": "integer"},
                "host": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "process_name": {"type": "keyword"},
                "parent_process_name": {"type": "keyword"},
                "command_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
            }
        }
    },
    "zeek": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "log_type": {"type": "keyword"},
                "host": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "dst_port": {"type": "integer"},
                "query": {"type": "keyword"},
                "uri": {"type": "keyword"},
                "method": {"type": "keyword"},
                "user_agent": {"type": "keyword"},
            }
        }
    },
}


def http(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        ES + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def b64(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def main() -> None:
    # Recreate indices
    for name, spec in MAPPINGS.items():
        try:
            http("DELETE", f"/{name}")
        except Exception:
            pass
        http("PUT", f"/{name}", spec)

    encoded = b64("Invoke-WebRequest -Uri http://10.10.10.50:8080/checkin")

    ws_docs = []
    # Decoy benign logon before the window (13:40)
    ws_docs.append({"@timestamp": "2026-09-30T13:40:00+07:00", "event_id": 4624, "host": "WS-02",
                    "user_name": "office-user", "logon_type": 2, "ip_address": "10.10.10.21", "status": "0x0"})
    # Attack window 14:00-14:30: 8 failed logons for lab-user on WS-01
    for i in range(8):
        ws_docs.append({"@timestamp": f"2026-09-30T14:0{i}:00+07:00", "event_id": 4625, "host": "WS-01",
                        "user_name": "lab-user", "logon_type": 3, "ip_address": "10.10.10.99", "status": "0xC000006A"})
    # One success right after the failures
    ws_docs.append({"@timestamp": "2026-09-30T14:09:00+07:00", "event_id": 4624, "host": "WS-01",
                    "user_name": "lab-user", "logon_type": 3, "ip_address": "10.10.10.99", "status": "0x0"})
    # Decoy failed logon from another user after the window (15:10)
    ws_docs.append({"@timestamp": "2026-09-30T15:10:00+07:00", "event_id": 4625, "host": "WS-03",
                    "user_name": "intern", "logon_type": 3, "ip_address": "10.10.10.5", "status": "0xC000006A"})

    sysmon_docs = [
        # Benign decoy process before the window
        {"@timestamp": "2026-09-30T13:45:00+07:00", "event_id": 1, "host": "WS-02", "user_name": "office-user",
         "process_name": "C:\\Windows\\System32\\notepad.exe", "parent_process_name": "C:\\Windows\\explorer.exe",
         "command_line": "notepad.exe notes.txt"},
        # Encoded PowerShell by lab-user on WS-01 inside the window
        {"@timestamp": "2026-09-30T14:12:00+07:00", "event_id": 1, "host": "WS-01", "user_name": "lab-user",
         "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "parent_process_name": "C:\\Windows\\System32\\cmd.exe",
         "command_line": f"powershell.exe -NoProfile -EncodedCommand {encoded}"},
    ]

    zeek_docs = [
        # Benign decoy DNS before the window
        {"@timestamp": "2026-09-30T13:50:00+07:00", "log_type": "dns", "host": "WS-02", "user_name": "office-user",
         "src_ip": "10.10.10.21", "dst_ip": "10.10.10.2", "dst_port": 53, "query": "example.com"},
        # Attack host: DNS lookup then HTTP check-in to the team server
        {"@timestamp": "2026-09-30T14:13:00+07:00", "log_type": "dns", "host": "WS-01", "user_name": "lab-user",
         "src_ip": "10.10.10.99", "dst_ip": "10.10.10.2", "dst_port": 53, "query": "lab-server.team"},
        {"@timestamp": "2026-09-30T14:14:00+07:00", "log_type": "http", "host": "WS-01", "user_name": "lab-user",
         "src_ip": "10.10.10.99", "dst_ip": "10.10.10.50", "dst_port": 8080,
         "uri": "/checkin", "method": "GET", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        # Decoy HTTP after the window
        {"@timestamp": "2026-09-30T15:30:00+07:00", "log_type": "http", "host": "WS-03", "user_name": "intern",
         "src_ip": "10.10.10.5", "dst_ip": "10.10.10.60", "dst_port": 80,
         "uri": "/index.html", "method": "GET", "user_agent": "curl/8.0"},
    ]

    total = 0
    for index, docs in [("windows-security", ws_docs), ("sysmon", sysmon_docs), ("zeek", zeek_docs)]:
        lines = []
        for doc in docs:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(doc))
        payload = ("\n".join(lines) + "\n").encode()
        req = urllib.request.Request(
            ES + "/_bulk",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-ndjson"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode())
        errors = result.get("errors")
        total += len(docs)
        print(f"{index}: indexed {len(docs)} docs, bulk errors={errors}")
        if errors:
            for item in result.get("items", []):
                if item.get("index", {}).get("error"):
                    print("  ", item["index"]["error"])

    http("POST", "/_refresh")
    counts = {name: http("GET", f"/{name}/_count")["count"] for name in MAPPINGS}
    print("counts:", counts)
    print(f"seeded {total} documents")


if __name__ == "__main__":
    main()
