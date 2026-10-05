"""Regression coverage for the M3 pull-request review findings."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline
from tracehunt_schema.classifier import classify
from tracehunt_schema.fields import canonical_json, get_field
from tracehunt_schema.io import load_samples


def flat_sysmon():
    return {"EventID": 1, "UtcTime": "2026-09-30 07:12:00.000",
            "Computer": "WS-01", "User": "LAB\\lab-user",
            "Image": "C:\\Program Files\\Lab\\tool.exe",
            "CommandLine": '"C:\\Program Files\\Lab\\tool.exe" --demo'}


def zeek_http():
    return {"ts": 1790752440.25, "uid": "HTTP-REVIEW-1",
            "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2",
            "method": "GET", "host": "beacon.example", "uri": "/checkin"}


class ReviewMappingTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = SchemaPipeline()

    def test_http_host_is_a_url_domain_not_a_computer_name(self):
        record = zeek_http()
        result = self.pipeline.process(record)
        self.assertEqual(result["status"], "accepted")
        event = result["event"]
        self.assertNotIn("host", event)
        self.assertEqual(get_field(event, "url.domain"), "beacon.example")
        self.assertEqual(get_field(event, "event.dataset"), "zeek.http")
        self.assertEqual(json.loads(get_field(event, "event.original")), record)

    def test_http_host_ports_and_ipv6_do_not_pollute_url_domain(self):
        for header, domain in (("beacon.example:8080", "beacon.example"),
                               ("[2001:db8::1]:8080", "[2001:db8::1]")):
            with self.subTest(header=header):
                result = self.pipeline.process(dict(zeek_http(), host=header))
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(get_field(result["event"], "url.domain"), domain)
                self.assertNotIn("host", result["event"])

    def test_invalid_http_host_authorities_are_quarantined(self):
        for header in (" \t ", "beacon.example:bad", "user@beacon.example",
                       "beacon.example/path", "[2001:db8::1"):
            with self.subTest(header=header):
                record = dict(zeek_http(), host=header)
                result = self.pipeline.process(record)
                self.assertEqual(result["status"], "quarantined")
                self.assertEqual(result["errors"][0]["field"], "url.domain")
                self.assertEqual(result["raw_record"], record)

    def test_explicit_ecs_computer_metadata_is_retained_for_zeek(self):
        for metadata in ({"host.name": "SENSOR-01"}, {"host": {"name": "SENSOR-01"}}):
            with self.subTest(metadata=metadata):
                result = self.pipeline.process(dict(zeek_http(), **metadata))
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(get_field(result["event"], "host.name"), "SENSOR-01")
                if isinstance(metadata.get("host"), dict):
                    self.assertNotIn("domain", result["event"]["url"])
                else:
                    self.assertEqual(get_field(result["event"], "url.domain"), "beacon.example")

    def test_zeek_connection_does_not_infer_a_computer_from_bare_host(self):
        record = dict(zeek_http(), log_type="conn")
        del record["method"]
        del record["uri"]
        result = self.pipeline.process(record)
        self.assertEqual(result["status"], "accepted")
        self.assertNotIn("host", result["event"])
        self.assertNotIn("url", result["event"])

    def test_flat_sysmon_is_selected_without_a_hint(self):
        record = flat_sysmon()
        self.assertEqual(classify(record), "sysmon")
        result = self.pipeline.process(record)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["schema_id"], "sysmon")
        self.assertEqual(get_field(result["event"], "process.name"), "tool.exe")
        self.assertEqual(get_field(result["event"], "user.name"), "lab-user")
        self.assertEqual(get_field(result["event"], "user.domain"), "LAB")

    def test_flat_sysmon_code_and_process_aliases_are_detected(self):
        for code_field in ("EventID", "event_id", "winlog.event_id", "event.code"):
            for process_field in ("Image", "CommandLine", "process.executable", "command_line"):
                with self.subTest(code_field=code_field, process_field=process_field):
                    self.assertEqual(classify({code_field: "1", process_field: "tool.exe"}), "sysmon")
        self.assertEqual(classify({"EventID": 4625, "TargetUserName": "lab-user"}), "windows-security")
        self.assertIsNone(classify({"EventID": 1, "unrelated": "value"}))
        self.assertEqual(classify(flat_sysmon(), "custom-json"), "custom-json")

    def test_whitespace_only_usernames_are_quarantined(self):
        windows = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        for record in (dict(windows, user_name=" \t "), dict(flat_sysmon(), User=" \t "),
                       dict(flat_sysmon(), User="LAB\\   ")):
            with self.subTest(record=record):
                result = self.pipeline.process(record, source_hint="sysmon" if "Image" in record else None)
                self.assertEqual(result["status"], "quarantined")
                self.assertEqual(result["errors"][0]["field"], "user.name")
                self.assertEqual(result["raw_record"], record)

    def test_whitespace_only_executable_and_parent_paths_are_quarantined(self):
        for field, target in (("Image", "process.executable"), ("ParentImage", "process.parent.executable")):
            with self.subTest(field=field):
                record = dict(flat_sysmon(), **{field: " \t "})
                result = self.pipeline.process(record, source_hint="sysmon")
                self.assertEqual(result["status"], "quarantined")
                self.assertEqual(result["errors"][0]["field"], target)

    def test_valid_paths_and_command_lines_keep_internal_spaces(self):
        record = flat_sysmon()
        result = self.pipeline.process(record, source_hint="sysmon")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(get_field(result["event"], "process.executable"), record["Image"])
        self.assertEqual(get_field(result["event"], "process.command_line"), record["CommandLine"])


class ReviewBatchTests(unittest.TestCase):
    def good(self):
        return load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]

    def assert_continues(self, bad):
        good = self.good()
        batch = SchemaAgent(frozen=True).process_batch([good, bad, deepcopy(good)])
        self.assertEqual(batch["summary"], {"processed": 3, "accepted": 2,
                                           "quarantined": 1, "created_schemas": 0})
        self.assertEqual([row["status"] for row in batch["results"]],
                         ["accepted", "quarantined", "accepted"])
        canonical_json(batch).encode("utf-8")
        self.assertEqual(batch["results"][0]["document_id"], batch["results"][2]["document_id"])
        return batch["results"][1]

    def test_unpaired_unicode_surrogates_are_quarantined(self):
        for extra in ({"note": "\ud800"}, {"\udfff": "bad field name"}):
            with self.subTest(extra=repr(extra)):
                failure = self.assert_continues(dict(self.good(), **extra))
                self.assertEqual(failure["errors"][0]["code"], "invalid_record")
                self.assertIsNone(failure["raw_record"])
                self.assertIn("\\ud", failure["raw_text"])

    def test_excessively_nested_values_are_quarantined(self):
        nested = "value"
        for _ in range(1200):
            nested = {"child": nested}
        failure = self.assert_continues(dict(self.good(), nested=nested))
        self.assertIsNone(failure["raw_record"])
        self.assertTrue(failure["raw_text"])

    def test_non_object_non_finite_and_cyclic_values_are_serializable_failures(self):
        cycle = {}
        cycle["loop"] = cycle
        for bad in ([float("nan")], float("inf"), cycle, {"blob": b"bad"}):
            with self.subTest(bad=type(bad).__name__):
                failure = self.assert_continues(bad)
                self.assertEqual(failure["errors"][0]["code"], "invalid_record")
                self.assertIsNone(failure["raw_record"])

    def test_valid_unicode_and_shared_objects_remain_supported(self):
        record = self.good()
        record["user_name"] = "Zoë"
        shared = {"note": "café"}
        record.update(first=shared, second=shared)
        result = SchemaPipeline().process(record)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(get_field(result["event"], "user.name"), "Zoë")
        self.assertEqual(json.loads(get_field(result["event"], "event.original")), record)
        canonical_json(result).encode("utf-8")

    def test_flat_sysmon_reuses_builtin_parser_without_generation(self):
        batch = SchemaAgent().process_batch([flat_sysmon()])
        self.assertEqual(batch["summary"], {"processed": 1, "accepted": 1,
                                           "quarantined": 0, "created_schemas": 0})
        self.assertEqual(batch["decisions"][0]["decision"], "reuse")

    def test_blank_known_fields_do_not_stop_later_records_or_generate_parsers(self):
        batch = SchemaAgent().process_batch([dict(flat_sysmon(), Image="   "), flat_sysmon()])
        self.assertEqual(batch["summary"], {"processed": 2, "accepted": 1,
                                           "quarantined": 1, "created_schemas": 0})
        self.assertEqual(batch["results"][0]["errors"][0]["field"], "process.executable")
        self.assertEqual(batch["results"][1]["status"], "accepted")


class ReviewCliTests(unittest.TestCase):
    def test_normalize_and_onboard_continue_after_encoding_and_depth_errors(self):
        good = (ROOT / "fixtures/known-mixed.ndjson").read_bytes().splitlines()[0]
        invalid_utf8 = b'{"note":"\xff"}'
        invalid_unicode = b'{"note":"\\ud800"}'
        deep = b'{"nested":' + b'[' * 200 + b'0' + b']' * 200 + b'}'
        invalid_lines = [invalid_utf8, invalid_unicode, deep, b'{"note":1e309}', b'not JSON', b'[]']
        for command in ("normalize", "onboard"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                source = path / "mixed.ndjson"
                source.write_bytes(b'\xef\xbb\xbf' + b'\n'.join([good, *invalid_lines, good]) + b'\n')
                args = [command, "--input", str(source), "--output", str(path / "accepted.jsonl"),
                        "--quarantine", str(path / "quarantine.jsonl"),
                        "--events-output", str(path / "events.ndjson"),
                        "--bulk-output", str(path / "bulk.ndjson")]
                if command == "onboard":
                    args += ["--audit", str(path / "audit.jsonl"), "--registry", str(path / "registry"),
                             "--batch-size", "2", "--frozen"]
                result = subprocess.run([sys.executable, "-m", "tracehunt_schema", *args],
                                        cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
                self.assertEqual(result.returncode, 2, result.stderr)
                summary = json.loads(result.stdout)
                self.assertEqual((summary["processed"], summary["accepted"], summary["quarantined"]), (8, 2, 6))
                rows = [json.loads(line) for line in (path / "quarantine.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual([row["line_number"] for row in rows], list(range(2, 8)))
                self.assertEqual(base64.b64decode(rows[0]["raw_bytes_base64"]), invalid_utf8)
                self.assertEqual(rows[0]["errors"][0]["code"], "invalid_encoding")
                self.assertEqual(rows[1]["raw_text"], invalid_unicode.decode("utf-8"))
                self.assertEqual(len((path / "accepted.jsonl").read_text(encoding="utf-8").splitlines()), 2)
                self.assertEqual(len((path / "events.ndjson").read_text(encoding="utf-8").splitlines()), 2)
                self.assertEqual(len((path / "bulk.ndjson").read_text(encoding="utf-8").splitlines()), 4)
                if command == "onboard":
                    audits = [json.loads(line) for line in (path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
                    self.assertEqual(sorted(number for row in audits for number in row["line_numbers"]), list(range(1, 9)))


if __name__ == "__main__":
    unittest.main()
