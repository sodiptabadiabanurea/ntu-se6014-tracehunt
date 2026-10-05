"""Whole-module regression checks for field, registry, and batch boundaries."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline, SchemaRegistry
from tracehunt_schema.config import Config
from tracehunt_schema.errors import RecordError, SchemaError
from tracehunt_schema.fields import canonical_json, digest, leaf_paths
from tracehunt_schema.generators import OllamaGenerator
from tracehunt_schema.inference import infer_candidate
from tracehunt_schema.io import load_samples
from tracehunt_schema.registry import validate_definition


class FieldBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = SchemaPipeline()
        self.windows = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        self.sysmon = load_samples(ROOT / "fixtures/sysmon-flat.ndjson")[0]

    def assert_field_failure(self, record, field, **kwargs):
        result = self.pipeline.process(record, **kwargs)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["errors"][0]["field"], field)
        self.assertEqual(result["raw_record"], record)
        return result

    def test_padded_event_codes_keep_logon_and_process_requirements(self):
        for code, outcome in (("004624", "success"), ("04625", "failure")):
            with self.subTest(code=code):
                result = self.pipeline.process(dict(self.windows, event_id=code))
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(result["event"]["event"]["code"], str(int(code)))
                self.assertEqual(result["event"]["event"]["outcome"], outcome)
                missing = dict(self.windows, event_id=code)
                del missing["user_name"]
                self.assert_field_failure(missing, "user.name")
        missing = dict(self.sysmon, EventID="0001")
        del missing["Image"]
        self.assert_field_failure(missing, "process.executable")

    def test_non_decimal_windows_event_codes_are_not_python_integer_syntax(self):
        for code in ("4_625", "-4625", "+4625", "4625.0", "٤٦٢٥"):
            with self.subTest(code=code):
                self.assert_field_failure(dict(self.windows, event_id=code), "event.code",
                                          source_hint="windows-security")

    def test_executable_paths_need_a_filename(self):
        for field, target in (("Image", "process.executable"), ("ParentImage", "process.parent.executable")):
            for value in ("C:\\Windows\\", "C:\\", "/", ".", "..", "tool\x00.exe"):
                with self.subTest(field=field, value=value):
                    self.assert_field_failure(dict(self.sysmon, **{field: value}), target)

    def test_integer_fields_fit_the_elasticsearch_long_mapping(self):
        for field, target in (("ProcessId", "process.pid"), ("ParentProcessId", "process.parent.pid")):
            for value in (2**63, str(2**63)):
                with self.subTest(field=field, value=value):
                    self.assert_field_failure(dict(self.sysmon, **{field: value}), target)
            result = self.pipeline.process(dict(self.sysmon, **{field: 2**63 - 1}))
            self.assertEqual(result["status"], "accepted")

    def test_ecs_host_object_does_not_hide_flat_computer_alias(self):
        for base, hint in ((self.sysmon, None), (self.windows, "windows-security")):
            with self.subTest(hint=hint):
                record = dict(base, host={"ip": ["10.0.0.1"]}, Computer="WS-01")
                result = self.pipeline.process(record, source_hint=hint)
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(result["event"]["host"]["name"], "WS-01")

    def test_mixed_dotted_containers_are_read_by_the_builtin_parser(self):
        record = {"EventID": 1, "Computer": "WS-01", "winlog.event_data": {
            "UtcTime": "2026-09-30 07:12:00", "Image": "tool.exe", "User": "LAB\\lab-user"}}
        result = self.pipeline.process(record)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["event"]["user"]["name"], "lab-user")
        self.assertEqual(result["event"]["process"]["executable"], "tool.exe")

    def test_corrupt_source_markers_do_not_generate_replacement_custom_parsers(self):
        for record in (dict(self.windows, event_id="broken"), dict(self.sysmon, EventID="broken")):
            with self.subTest(source="sysmon" if "Image" in record else "windows-security"):
                batch = SchemaAgent().process_batch([record])
                self.assertEqual(batch["summary"]["quarantined"], 1)
                self.assertEqual(batch["summary"]["created_schemas"], 0)
                self.assertEqual(batch["results"][0]["errors"][0]["field"], "event.code")
                self.assertEqual(batch["decisions"][0]["decision"], "reuse")
        for field in ("event.provider", "winlog.provider_name", "winlog.channel", "event.dataset"):
            with self.subTest(metadata_field=field):
                record = dict(self.windows, **{field: {"name": "Microsoft-Windows-Sysmon"}})
                self.assert_field_failure(record, field)
                batch = SchemaAgent().process_batch([record, self.windows])
                self.assertEqual(batch["summary"]["accepted"], 1)
                self.assertEqual(batch["summary"]["quarantined"], 1)
                self.assertEqual(batch["summary"]["created_schemas"], 0)

    def test_zeek_log_type_wrong_types_are_not_treated_as_absent(self):
        record = load_samples(ROOT / "fixtures/known-mixed.ndjson")[-1]
        for value in (False, 0, [], {}):
            with self.subTest(value_type=type(value).__name__):
                self.assert_field_failure(dict(record, log_type=value), "log_type")
                batch = SchemaAgent().process_batch([dict(record, log_type=value)])
                self.assertEqual(batch["summary"]["quarantined"], 1)
                self.assertEqual(batch["summary"]["created_schemas"], 0)

    def test_http_host_rejects_uri_delimiters_and_control_characters(self):
        record = load_samples(ROOT / "fixtures/zeek.ndjson")[-1]
        for host in ("beacon.example#", "beacon.example?", "beacon\\evil.example",
                     "beacon\x00.example", "beacon\x7f.example", 123):
            with self.subTest(host=repr(host)):
                self.assert_field_failure(dict(record, host=host), "url.domain")

    def test_conflicting_nested_and_dotted_values_are_quarantined(self):
        record = dict(self.windows, **{"user.name": "alice", "user": {"name": "bob"}})
        self.assert_field_failure(record, "user.name")
        batch = SchemaAgent(frozen=True).process_batch([record, self.windows])
        self.assertEqual(batch["summary"]["accepted"], 1)
        self.assertEqual(batch["summary"]["quarantined"], 1)

    def test_equal_dotted_and_nested_values_share_one_field_signature(self):
        record = {"event_time": "2026-09-30T07:00:00Z", "user.name": "alice", "user": {"name": "alice"}}
        self.assertEqual(leaf_paths(record), ["event_time", "user.name"])
        batch = SchemaAgent().process_batch([record])
        self.assertEqual(batch["summary"]["accepted"], 1)
        self.assertEqual(batch["results"][0]["event"]["user"]["name"], "alice")

    def test_unrepresentable_integer_does_not_stop_a_batch(self):
        bad = dict(self.windows, note=10**5000)
        batch = SchemaAgent(frozen=True).process_batch([bad, self.windows])
        self.assertEqual(batch["summary"]["quarantined"], 1)
        self.assertEqual(batch["summary"]["accepted"], 1)
        canonical_json(batch).encode("utf-8")
        self.assertTrue(batch["results"][0]["raw_text"])

    def test_invalid_wire_text_is_a_serializable_record_failure(self):
        for text in ("\ud800", b"bytes instead of text", {"text": "wrong type"}):
            with self.subTest(text_type=type(text).__name__):
                batch = SchemaAgent(frozen=True).process_batch([self.windows, self.windows], raw_texts=[text, None])
                self.assertEqual([row["status"] for row in batch["results"]], ["quarantined", "accepted"])
                self.assertEqual(batch["results"][0]["errors"][0]["field"], "event.original")
                self.assertEqual(batch["results"][0]["raw_record"], self.windows)
                canonical_json(batch).encode("utf-8")


class RegistryBoundaryTests(unittest.TestCase):
    def samples(self):
        return load_samples(ROOT / "fixtures/custom-unknown.ndjson")

    def test_non_json_parser_metadata_is_rejected_before_registration(self):
        for value in (float("nan"), "\ud800", b"not JSON"):
            with self.subTest(value_type=type(value).__name__):
                spec = infer_candidate(self.samples())["schema"]
                spec["description"] = value
                with tempfile.TemporaryDirectory() as folder:
                    registry = SchemaRegistry(Path(folder) / "registry")
                    with self.assertRaises(SchemaError):
                        registry.approve(spec, self.samples())
                    self.assertFalse(registry.directory.exists())

    def test_duplicate_registry_keys_are_not_silently_replaced(self):
        spec = SchemaRegistry().get_schema("sysmon")
        text = json.dumps(spec)
        text = '{"id":"different",' + text[1:]
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "parser.json").write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "duplicate"):
                SchemaRegistry(folder)

    def test_version_components_are_validated_before_numeric_sorting(self):
        spec = SchemaRegistry().get_schema("sysmon")
        for version in ("9" * 5000 + ".0.0", "١.٠.٠"):
            with self.subTest(version_length=len(version)):
                spec["version"] = version
                with self.assertRaises(SchemaError):
                    validate_definition(spec)

    def test_unmapped_invalid_approval_input_is_still_rejected(self):
        samples = self.samples()
        spec = infer_candidate(samples)["schema"]
        samples[1]["note"] = float("nan")
        with tempfile.TemporaryDirectory() as folder:
            registry = SchemaRegistry(Path(folder) / "registry")
            with self.assertRaises(RecordError):
                registry.approve(spec, samples)
            self.assertFalse(registry.directory.exists())

    def test_bom_config_and_registry_files_are_supported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            cfg = path / "config.json"
            cfg.write_text('{"naive_timezone":"+08:00"}', encoding="utf-8-sig")
            self.assertEqual(Config.load(cfg).naive_timezone, "+08:00")
            registry = path / "registry"
            registry.mkdir()
            spec = SchemaRegistry().get_schema("sysmon")
            (registry / "sysmon.json").write_text(json.dumps(spec), encoding="utf-8-sig")
            self.assertEqual(SchemaRegistry(registry).get_schema("sysmon"), spec)

    def test_registration_conflict_quarantines_one_group_and_preserves_other_groups(self):
        samples = self.samples()
        generated_id = "custom-" + digest(leaf_paths(samples[0]))[:16]
        registry = SchemaRegistry()
        old = [{"event_time": "2026-09-30T07:00:00Z", "account": "old-user"}]
        registry.approve(infer_candidate(old, schema_id=generated_id)["schema"], old)
        known = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        batch = SchemaAgent(registry).process_batch([samples[0], known])
        self.assertEqual([row["status"] for row in batch["results"]], ["quarantined", "accepted"])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(batch["results"][0]["errors"][0]["code"], "schema_error")
        self.assertEqual(registry.get_schema(generated_id)["signature"], leaf_paths(old[0]))


class ModelBoundaryTests(unittest.TestCase):
    def test_deep_model_json_is_bounded_and_does_not_abort_other_sources(self):
        depth = sys.getrecursionlimit() + 100
        generator = OllamaGenerator("offline-mock", transport=lambda _: {
            "done": True, "message": {"content": "[" * depth + "0" + "]" * depth}})
        known = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        unknown = {"event_time": "2026-09-30T07:00:00Z", "account": "lab-user"}
        batch = SchemaAgent(generator=generator).process_batch([unknown, known])
        self.assertEqual([row["status"] for row in batch["results"]], ["quarantined", "accepted"])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(len(batch["decisions"][0]["attempts"]), 2)


class FileBoundaryTests(unittest.TestCase):
    def run_cli(self, command, path, quarantine, *extra):
        args = [command, "--input", str(path / "input.ndjson"), "--output", str(path / "accepted.jsonl"),
                "--quarantine", str(quarantine)]
        if command == "onboard":
            args += ["--audit", str(path / "audit.jsonl"), "--registry", str(path / "registry")]
        return subprocess.run([sys.executable, "-m", "tracehunt_schema", *args, *map(str, extra)],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=10)

    def test_hardlinked_input_and_quarantine_are_rejected_before_output(self):
        for command in ("normalize", "onboard"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                original = (ROOT / "fixtures/known-mixed.ndjson").read_bytes().splitlines()[0] + b"\n"
                source = path / "input.ndjson"
                source.write_bytes(original)
                quarantine = path / "alias.jsonl"
                try:
                    os.link(source, quarantine)
                except OSError as exc:
                    self.skipTest(f"hard links unavailable: {exc}")
                result = self.run_cli(command, path, quarantine)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse((path / "accepted.jsonl").exists())

    def test_quarantine_cannot_append_to_the_config_file(self):
        for command in ("normalize", "onboard"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                (path / "input.ndjson").write_text("not JSON\n", encoding="utf-8")
                cfg = path / "config.json"
                original = b'{"naive_timezone":"+08:00"}\n'
                cfg.write_bytes(original)
                result = self.run_cli(command, path, cfg, "--config", cfg)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(cfg.read_bytes(), original)
                self.assertFalse((path / "accepted.jsonl").exists())

    def test_outputs_cannot_corrupt_the_parser_registry(self):
        for command in ("normalize", "onboard"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                (path / "input.ndjson").write_text("not JSON\n", encoding="utf-8")
                registry = path / "registry"
                registry.mkdir()
                definition = registry / "sysmon.json"
                original = json.dumps(SchemaRegistry().get_schema("sysmon")).encode("utf-8")
                definition.write_bytes(original)
                result = self.run_cli(command, path, definition, "--registry", registry)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(definition.read_bytes(), original)
                self.assertFalse((path / "accepted.jsonl").exists())
                alias = path / "registry-alias.jsonl"
                try:
                    os.link(definition, alias)
                except OSError as exc:
                    self.skipTest(f"hard links unavailable: {exc}")
                result = self.run_cli(command, path, alias, "--registry", registry)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(definition.read_bytes(), original)
                self.assertFalse((path / "accepted.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
