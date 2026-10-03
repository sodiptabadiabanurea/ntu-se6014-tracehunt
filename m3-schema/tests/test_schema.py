"""Offline behavioural tests for mapping, quality controls, and parser approval."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaPipeline, SchemaRegistry
from tracehunt_schema.classifier import classify
from tracehunt_schema.config import Config
from tracehunt_schema.errors import RecordError, SchemaError
from tracehunt_schema.fields import canonical_json, digest, get_field
from tracehunt_schema.inference import infer_candidate
from tracehunt_schema.io import load_samples
from tracehunt_schema.parser import timestamp


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = SchemaPipeline()
        self.samples = load_samples(ROOT / "fixtures/known-mixed.ndjson")

    def test_lab_logon_golden_fields(self):
        record = self.samples[0]
        result = self.pipeline.process(record)
        self.assertEqual(result["status"], "accepted")
        event = result["event"]
        self.assertEqual(event["@timestamp"], "2026-09-30T07:00:00.000000Z")
        self.assertEqual(event["event"]["code"], "4625")
        self.assertEqual(event["event"]["outcome"], "failure")
        self.assertEqual(event["event"]["dataset"], "windows.security")
        self.assertEqual(event["host"], {"name": "WS-01"})
        self.assertEqual(event["user"], {"name": "lab-user"})
        self.assertEqual(event["source"], {"ip": "10.10.10.99"})
        self.assertEqual(json.loads(event["event"]["original"]), record)
        self.assertEqual(event["tracehunt"]["schema"]["version"], "1.0.0")

    def test_success_and_failure_remain_distinct(self):
        event = self.pipeline.process(self.samples[1])["event"]
        self.assertEqual(event["event"]["outcome"], "success")
        self.assertEqual(event["event"]["code"], "4624")

    def test_process_path_is_not_confused_with_process_name(self):
        result = self.pipeline.process(self.samples[2])
        self.assertEqual(result["status"], "accepted")
        process = result["event"]["process"]
        self.assertEqual(process["name"], "powershell.exe")
        self.assertEqual(process["executable"], self.samples[2]["process_name"])
        self.assertEqual(process["parent"]["name"], "cmd.exe")
        self.assertEqual(process["command_line"], self.samples[2]["command_line"])

    def test_winlogbeat_and_sysmon_utc_time(self):
        samples = load_samples(ROOT / "fixtures/winlogbeat.ndjson")
        ws = self.pipeline.process(samples[0])
        self.assertEqual(ws["status"], "accepted")
        self.assertEqual(ws["event"]["user"], {"name": "lab-user", "domain": "LAB"})
        self.assertEqual(ws["event"]["source"]["port"], 49152)
        ps = self.pipeline.process(samples[1])
        self.assertEqual(ps["status"], "accepted")
        self.assertEqual(ps["event"]["@timestamp"], "2026-09-30T07:12:00.000000Z")
        self.assertEqual(ps["event"]["user"], {"name": "lab-user", "domain": "LAB"})
        self.assertEqual(ps["event"]["process"]["pid"], 2048)

    def test_zeek_dotted_fields_and_epoch_time(self):
        sample = load_samples(ROOT / "fixtures/zeek.ndjson")[0]
        result = self.pipeline.process(sample)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["event"]["@timestamp"], timestamp(sample["ts"]))
        self.assertEqual(result["event"]["source"]["ip"], "10.10.10.99")
        self.assertEqual(result["event"]["destination"]["port"], 8080)
        self.assertEqual(result["event"]["event"]["dataset"], "zeek.conn")
        self.assertNotIn("user", result["event"])
        self.assertNotIn("host", result["event"])

    def test_dns_and_http_are_separate_datasets(self):
        dns = self.pipeline.process(self.samples[3])["event"]
        http = self.pipeline.process(self.samples[4])["event"]
        self.assertEqual(dns["event"]["dataset"], "zeek.dns")
        self.assertEqual(dns["dns"]["question"]["name"], "lab-server.team")
        self.assertEqual(http["event"]["dataset"], "zeek.http")
        self.assertEqual(http["http"]["request"]["method"], "GET")
        self.assertEqual(http["url"]["original"], "/checkin")

    def test_dotted_ecs_input_is_supported(self):
        sample = {"@timestamp": "2026-09-30T07:00:00Z", "event.code": "4625",
                  "host.name": "WS-01", "user.name": "lab-user", "source.ip": "::1"}
        result = self.pipeline.process(sample)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["event"]["source"]["ip"], "::1")

    def test_input_is_not_mutated_and_document_ids_are_repeatable(self):
        original = deepcopy(self.samples[0])
        a = self.pipeline.process(original)
        b = self.pipeline.process(dict(reversed(list(original.items()))))
        self.assertEqual(original, self.samples[0])
        self.assertEqual(a["document_id"], b["document_id"])
        self.assertEqual(a["event"], b["event"])
        changed = deepcopy(original)
        changed["user_name"] = "another-user"
        self.assertNotEqual(a["document_id"], self.pipeline.process(changed)["document_id"])

    def test_route_configuration_does_not_change_field_mapping(self):
        cfg = replace(Config(), routes={"windows-security": "tracehunt-windows"})
        result = SchemaPipeline(config=cfg).process(self.samples[0])
        self.assertEqual(result["index"], "tracehunt-windows")
        self.assertEqual(result["event"]["user"]["name"], "lab-user")

    def test_original_wire_text_is_preserved(self):
        text = json.dumps(self.samples[0], indent=1)
        result = self.pipeline.process(self.samples[0], raw_text=text)
        self.assertEqual(result["event"]["event"]["original"], text)


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = SchemaPipeline()
        self.sample = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]

    def assert_failure(self, record, code, field=None, **kwargs):
        result = self.pipeline.process(record, **kwargs)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["errors"][0]["code"], code)
        if field:
            self.assertEqual(result["errors"][0]["field"], field)
        self.assertNotIn("event", result)
        return result

    def test_invalid_ip_retains_raw_record(self):
        sample = dict(self.sample, ip_address="300.1.2.3")
        failure = self.assert_failure(sample, "invalid_field", "source.ip")
        self.assertEqual(failure["raw_record"], sample)

    def test_logon_requires_account(self):
        sample = deepcopy(self.sample)
        del sample["user_name"]
        self.assert_failure(sample, "missing_field", "user.name")

    def test_invalid_time_and_naive_time_are_visible(self):
        for value in ("not-a-date", "2026-09-30T14:00:00", True):
            with self.subTest(value=value):
                self.assert_failure(dict(self.sample, **{"@timestamp": value}), "invalid_field", "@timestamp")

    def test_explicit_offset_for_naive_time(self):
        cfg = Config(naive_timezone="+08:00")
        result = SchemaPipeline(config=cfg).process(dict(self.sample, **{"@timestamp": "2026-09-30T14:00:00"}))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["event"]["@timestamp"], "2026-09-30T06:00:00.000000Z")

    def test_invalid_ports_and_boolean_codes(self):
        zeek = {"ts": 1790752440, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"}
        for port in (65536, -1, 1.5, True):
            with self.subTest(port=port):
                self.assert_failure(dict(zeek, **{"id.resp_p": port}), "invalid_field", "destination.port")
        self.assert_failure(dict(self.sample, event_id=True), "invalid_field", "event.code", source_hint="windows-security")

    def test_process_creation_requires_executable(self):
        sample = {"@timestamp": "2026-09-30T07:12:00Z", "event_id": 1,
                  "host": "WS-01", "command_line": "powershell.exe"}
        self.assert_failure(sample, "missing_field", "process.executable")

    def test_unknown_format_is_not_automatically_activated(self):
        sample = load_samples(ROOT / "fixtures/custom-unknown.ndjson")[0]
        self.assert_failure(sample, "unknown_format")
        self.assertEqual(len(self.pipeline.registry.list_schemas()), 3)

    def test_non_json_values_cannot_break_quarantine_serialization(self):
        result = self.assert_failure(dict(self.sample, bad=float("nan")), "invalid_record")
        canonical_json(result)
        self.assertIsNone(result["raw_record"])
        self.assertIn("nan", result["raw_text"])

    def test_non_object_input_is_quarantined(self):
        for value in (None, 123, "EVTX is not JSON", []):
            with self.subTest(value=value):
                self.assert_failure(value, "invalid_record")

    def test_source_hint_and_parser_pin_are_checked(self):
        self.assert_failure(self.sample, "invalid_source", source_hint="arbitrary")
        self.assert_failure(self.sample, "invalid_schema_pin", schema_version="1.0.0")
        self.assert_failure(self.sample, "source_mismatch", schema_id="sysmon")


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "registry"
        self.registry = SchemaRegistry(self.path)
        self.samples = load_samples(ROOT / "fixtures/custom-unknown.ndjson")

    def test_candidate_validation_approval_and_reuse(self):
        candidate = infer_candidate(self.samples)
        self.assertTrue(candidate["validation"]["passed"])
        self.assertEqual(candidate["status"], "candidate")
        self.assertEqual(candidate["unmapped_fields"], ["note"])
        self.assertEqual(len(self.registry.list_schemas()), 3)
        result = self.registry.approve(candidate["schema"], self.samples)
        self.assertEqual(result["validated_samples"], 2)
        loaded = SchemaRegistry(self.path)
        accepted = SchemaPipeline(loaded).process(self.samples[0])
        self.assertEqual(accepted["status"], "accepted")
        self.assertEqual(accepted["event"]["destination"]["port"], 8080)
        self.assertEqual(accepted["event"]["host"]["name"], "WS-01")
        self.assertIn("note", accepted["event"]["event"]["original"])

    def test_failed_validation_never_registers_parser(self):
        samples = deepcopy(self.samples)
        samples[1]["target_ip"] = "invalid-ip"
        candidate = infer_candidate(samples)
        self.assertFalse(candidate["validation"]["passed"])
        with self.assertRaises(RecordError):
            self.registry.approve(candidate["schema"], samples)
        self.assertEqual(len(self.registry.list_schemas()), 3)
        self.assertFalse(self.path.exists())

    def test_golden_semantic_mismatch_blocks_approval(self):
        candidate = infer_candidate(self.samples)
        with self.assertRaisesRegex(SchemaError, "golden"):
            self.registry.approve(candidate["schema"], self.samples, expected_events=[{}, {}])
        self.assertFalse(self.path.exists())

    def test_approved_versions_are_immutable_and_pinnable(self):
        spec = infer_candidate(self.samples)["schema"]
        self.registry.approve(spec, self.samples)
        changed = deepcopy(spec)
        changed["dataset"] = "custom.changed"
        with self.assertRaisesRegex(SchemaError, "immutable"):
            self.registry.approve(changed, self.samples)
        changed["version"] = "1.1.0"
        self.registry.approve(changed, self.samples)
        self.assertEqual(self.registry.get_schema("custom-json")["version"], "1.1.0")
        pinned = SchemaPipeline(self.registry).process(self.samples[0], schema_id="custom-json", schema_version="1.0.0")
        self.assertEqual(pinned["schema_version"], "1.0.0")

    def test_registry_readers_cannot_mutate_approved_definitions(self):
        spec = self.registry.get_schema("sysmon")
        spec["version"] = "99.0.0"
        self.assertEqual(self.registry.get_schema("sysmon")["version"], "1.0.0")

    def test_unsupported_generated_code_or_targets_are_rejected(self):
        spec = infer_candidate(self.samples)["schema"]
        spec["mappings"][0]["target"] = "__import__('os').system('anything')"
        with self.assertRaises(SchemaError):
            self.registry.approve(spec, self.samples)
        self.assertFalse(self.path.exists())

    def test_changed_custom_shape_is_quarantined(self):
        spec = infer_candidate(self.samples)["schema"]
        self.registry.approve(spec, self.samples)
        changed = dict(self.samples[0], extra="new-field")
        self.assertEqual(SchemaPipeline(self.registry).process(changed)["status"], "quarantined")

    def test_ambiguous_aliases_are_not_guessed(self):
        samples = [dict(self.samples[0], timestamp="2026-09-30T07:00:00Z")]
        with self.assertRaisesRegex(SchemaError, "ambiguous"):
            infer_candidate(samples)

    def test_different_custom_shapes_need_separate_candidates(self):
        samples = deepcopy(self.samples)
        del samples[1]["note"]
        with self.assertRaisesRegex(SchemaError, "consistent"):
            infer_candidate(samples)

    def test_candidate_requires_a_timestamp_and_event_content(self):
        for samples in ([], [{"unknown": "field"}], [{"event_time": "2026-09-30T07:00:00Z"}]):
            with self.subTest(samples=samples), self.assertRaises(SchemaError):
                infer_candidate(samples)


class MappingTemplateTests(unittest.TestCase):
    def test_proposed_template_covers_all_emitted_fields_and_entity_types(self):
        from tracehunt_schema.fields import leaf_paths
        template = json.loads((ROOT / "es/index-template.example.json").read_text(encoding="utf-8"))
        props = template["template"]["mappings"]["properties"]

        def mapping(path):
            current = props
            parts = path.split(".")
            for i, part in enumerate(parts):
                self.assertIn(part, current, path)
                if i == len(parts) - 1:
                    return current[part]
                current = current[part]["properties"]

        pipeline = SchemaPipeline()
        for fixture in ("known-mixed.ndjson", "winlogbeat.ndjson", "zeek.ndjson", "sysmon-flat.ndjson"):
            for sample in load_samples(ROOT / "fixtures" / fixture):
                result = pipeline.process(sample)
                self.assertEqual(result["status"], "accepted")
                for path in leaf_paths(result["event"]):
                    mapping(path)
        self.assertEqual(mapping("user.name")["type"], "keyword")
        self.assertEqual(mapping("event.code")["type"], "keyword")
        self.assertEqual(mapping("destination.ip")["type"], "ip")
        self.assertEqual(mapping("url.domain")["type"], "keyword")
        self.assertFalse(mapping("event.original")["index"])


if __name__ == "__main__":
    unittest.main()
