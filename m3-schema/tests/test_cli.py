"""Exercise the public CLI with real files and subprocess exit codes."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "tracehunt_schema", *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8")

    def lines(self, path):
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]

    def test_known_batch_has_event_and_bulk_exports(self):
        accepted = self.path / "accepted.jsonl"
        events = self.path / "events.ndjson"
        bulk = self.path / "bulk.ndjson"
        result = self.run_cli("normalize", "--input", ROOT / "fixtures/known-mixed.ndjson",
                              "--output", accepted, "--quarantine", self.path / "quarantine.jsonl",
                              "--events-output", events, "--bulk-output", bulk)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"processed": 5, "accepted": 5, "quarantined": 0})
        accepted_rows = self.lines(accepted)
        self.assertEqual(self.lines(events), [row["event"] for row in accepted_rows])
        bulk_rows = self.lines(bulk)
        self.assertEqual(len(bulk_rows), 10)
        self.assertEqual(bulk_rows[0], {"index": {"_index": "windows-security", "_id": accepted_rows[0]["document_id"]}})
        self.assertEqual(bulk_rows[1], accepted_rows[0]["event"])

    def test_malformed_records_do_not_stop_good_records_or_disappear(self):
        source = self.path / "mixed.ndjson"
        good = (ROOT / "fixtures/known-mixed.ndjson").read_text(encoding="utf-8").splitlines()[0]
        source.write_text(good + "\n" + (ROOT / "fixtures/invalid.ndjson").read_text(encoding="utf-8")
                          + good + "\n", encoding="utf-8")
        quarantine = self.path / "quarantine.jsonl"
        result = self.run_cli("normalize", "--input", source, "--output", self.path / "accepted.jsonl",
                              "--quarantine", quarantine)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"processed": 9, "accepted": 2, "quarantined": 7})
        failures = self.lines(quarantine)
        self.assertEqual(len(failures), 7)
        self.assertEqual(failures[5]["raw_text"], "not valid JSON")
        self.assertEqual(failures[5]["line_number"], 7)
        self.assertTrue(all(row["errors"] for row in failures))

    def test_non_finite_json_and_duplicate_keys_are_quarantined(self):
        source = self.path / "bad.ndjson"
        source.write_text('{"x":NaN}\n{"x":1,"x":2}\n', encoding="utf-8")
        quarantine = self.path / "quarantine.jsonl"
        result = self.run_cli("normalize", "--input", source, "--output", self.path / "accepted.jsonl",
                              "--quarantine", quarantine)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(len(self.lines(quarantine)), 2)
        self.assertTrue(all(row["errors"][0]["code"] == "invalid_json" for row in self.lines(quarantine)))

    def test_unknown_candidate_must_be_approved_before_reuse(self):
        samples = ROOT / "fixtures/custom-unknown.ndjson"
        registry = self.path / "registry"
        candidate = self.path / "candidate.json"
        before = self.run_cli("normalize", "--input", samples, "--output", self.path / "before.jsonl",
                              "--quarantine", self.path / "quarantine.jsonl", "--registry", registry)
        self.assertEqual(before.returncode, 2, before.stderr)
        inferred = self.run_cli("infer", "--samples", samples, "--output", candidate)
        self.assertEqual(inferred.returncode, 0, inferred.stderr)
        approved = self.run_cli("approve", "--candidate", candidate, "--samples", samples, "--registry", registry)
        self.assertEqual(approved.returncode, 0, approved.stderr)
        after = self.run_cli("normalize", "--input", samples, "--output", self.path / "after.jsonl",
                             "--quarantine", self.path / "quarantine.jsonl", "--registry", registry)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(len(self.lines(self.path / "after.jsonl")), 2)
        # Old failures remain visible after a successful retry.
        self.assertEqual(len(self.lines(self.path / "quarantine.jsonl")), 2)

    def test_changed_approval_samples_are_rejected(self):
        candidate = self.path / "candidate.json"
        samples = ROOT / "fixtures/custom-unknown.ndjson"
        self.assertEqual(self.run_cli("infer", "--samples", samples, "--output", candidate).returncode, 0)
        changed = self.path / "changed.ndjson"
        changed.write_text(samples.read_text(encoding="utf-8").replace("office-user", "changed-user"), encoding="utf-8")
        result = self.run_cli("approve", "--candidate", candidate, "--samples", changed,
                              "--registry", self.path / "registry")
        self.assertEqual(result.returncode, 1)
        self.assertIn("samples changed", result.stderr)
        self.assertFalse((self.path / "registry").exists())

    def test_existing_output_or_input_output_collision_is_rejected(self):
        source = self.path / "source.ndjson"
        source.write_text('{"keep":"this"}\n', encoding="utf-8")
        before = source.read_bytes()
        result = self.run_cli("normalize", "--input", source, "--output", source,
                              "--quarantine", self.path / "quarantine.jsonl")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(source.read_bytes(), before)
        output = self.path / "existing.jsonl"
        output.write_text("existing output", encoding="utf-8")
        result = self.run_cli("normalize", "--input", source, "--output", output,
                              "--quarantine", self.path / "quarantine.jsonl")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output.read_text(encoding="utf-8"), "existing output")

    def test_schema_inspection_and_version_pin_errors(self):
        result = self.run_cli("schemas", "--schema-id", "sysmon", "--schema-version", "1.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["source"], "sysmon")
        result = self.run_cli("schemas", "--schema-version", "1.0.0")
        self.assertEqual(result.returncode, 1)

    def onboarding(self, input_path, name="agent", *extra):
        return self.run_cli("onboard", "--input", input_path,
                            "--output", self.path / f"{name}.jsonl",
                            "--quarantine", self.path / "quarantine.jsonl",
                            "--audit", self.path / f"{name}-audit.jsonl",
                            "--registry", self.path / "registry", *extra)

    def test_agent_cli_creates_parser_and_reuses_it_in_next_run(self):
        samples = ROOT / "fixtures/custom-unknown.ndjson"
        result = self.onboarding(samples)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["created_schemas"], 1)
        audit = self.lines(self.path / "agent-audit.jsonl")
        self.assertEqual(audit[0]["decision"], "created")
        self.assertEqual(audit[0]["line_numbers"], [1, 2])
        reused = self.onboarding(samples, "reused")
        self.assertEqual(reused.returncode, 0, reused.stderr)
        self.assertEqual(json.loads(reused.stdout)["created_schemas"], 0)
        self.assertEqual(self.lines(self.path / "agent.jsonl"), self.lines(self.path / "reused.jsonl"))

    def test_agent_cli_preserves_malformed_lines_and_good_records(self):
        source = self.path / "mixed.ndjson"
        source.write_text('not valid JSON\n' + (ROOT / "fixtures/custom-unknown.ndjson").read_text(encoding="utf-8"), encoding="utf-8")
        result = self.onboarding(source)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"processed": 3, "accepted": 2, "quarantined": 1, "created_schemas": 1})
        self.assertEqual(self.lines(self.path / "quarantine.jsonl")[0]["line_number"], 1)
        self.assertEqual(self.lines(self.path / "agent-audit.jsonl")[0]["line_numbers"], [2, 3])

    def test_agent_cli_review_and_frozen_modes_do_not_register(self):
        samples = ROOT / "fixtures/custom-unknown.ndjson"
        result = self.onboarding(samples, "review", "--review-only")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.lines(self.path / "review-audit.jsonl")[0]["decision"], "review_required")
        self.assertFalse((self.path / "registry").exists())
        frozen = self.onboarding(samples, "frozen", "--frozen")
        self.assertEqual(frozen.returncode, 2, frozen.stderr)
        self.assertEqual(json.loads(frozen.stdout)["created_schemas"], 0)

    def test_agent_cli_small_batches_reuse_registry_and_export_documents(self):
        result = self.onboarding(ROOT / "fixtures/custom-unknown.ndjson", "agent", "--batch-size", "1",
                                 "--events-output", self.path / "events.ndjson", "--bulk-output", self.path / "bulk.ndjson")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["created_schemas"], 1)
        self.assertEqual([d["decision"] for d in self.lines(self.path / "agent-audit.jsonl")], ["created", "reuse"])
        self.assertEqual(len(self.lines(self.path / "events.ndjson")), 2)
        self.assertEqual(len(self.lines(self.path / "bulk.ndjson")), 4)

    def test_agent_cli_invalid_model_configuration_fails_before_output(self):
        result = self.onboarding(ROOT / "fixtures/custom-unknown.ndjson", "agent", "--generator", "ollama", "--model", "")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.path / "agent.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
