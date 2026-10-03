"""Schema-agent behaviour and model adapter contracts, without network requests."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaRegistry
from tracehunt_schema.errors import SchemaError
from tracehunt_schema.fields import canonical_json, get_field
from tracehunt_schema.generators import AliasGenerator, OllamaGenerator
from tracehunt_schema.io import load_samples


class CountingGenerator(AliasGenerator):
    def __init__(self):
        super().__init__()
        self.calls = []

    def propose(self, samples, context):
        self.calls.append(deepcopy(context))
        return super().propose(samples, context)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "registry"
        self.registry = SchemaRegistry(self.path)
        self.samples = load_samples(ROOT / "fixtures/custom-unknown.ndjson")

    def test_known_formats_reuse_parsers_without_generation(self):
        generator = CountingGenerator()
        batch = SchemaAgent(self.registry, generator=generator).process_batch(load_samples(ROOT / "fixtures/known-mixed.ndjson"))
        self.assertEqual(batch["summary"], {"processed": 5, "accepted": 5, "quarantined": 0, "created_schemas": 0})
        self.assertEqual(generator.calls, [])
        self.assertTrue(all(d["decision"] == "reuse" for d in batch["decisions"]))

    def test_unknown_format_is_created_and_reused_after_restart(self):
        generator = CountingGenerator()
        before = SchemaAgent(self.registry, generator=generator).process_batch(self.samples)
        self.assertEqual(before["summary"]["created_schemas"], 1)
        self.assertEqual(before["summary"]["accepted"], 2)
        decision = before["decisions"][0]
        self.assertEqual(decision["states"], ["inspect", "classify", "select", "propose", "validate", "register", "apply"])
        self.assertEqual(decision["candidate"]["unmapped_fields"], ["note"])
        after = SchemaAgent(SchemaRegistry(self.path), generator=generator).process_batch(self.samples)
        self.assertEqual(after["decisions"][0]["decision"], "reuse")
        self.assertEqual(len(generator.calls), 1)
        self.assertEqual(before["results"], after["results"])

    def test_known_invalid_record_does_not_trigger_candidate_generation(self):
        generator = CountingGenerator()
        known = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        known["ip_address"] = "invalid"
        batch = SchemaAgent(self.registry, generator=generator).process_batch([known])
        self.assertEqual(generator.calls, [])
        self.assertEqual(batch["results"][0]["errors"][0]["field"], "source.ip")
        self.assertEqual(batch["summary"]["created_schemas"], 0)

    def test_invalid_candidate_never_registers_even_outside_prompt_sample(self):
        samples = deepcopy(self.samples)
        samples[1]["target_ip"] = "invalid"
        batch = SchemaAgent(self.registry, max_samples=1).process_batch(samples)
        self.assertEqual(batch["summary"]["quarantined"], 2)
        self.assertEqual(batch["decisions"][0]["attempts"][0]["errors"][0]["position"], 1)
        self.assertFalse(self.path.exists())

    def test_review_only_saves_candidate_but_does_not_activate(self):
        batch = SchemaAgent(self.registry, review_only=True).process_batch(self.samples)
        self.assertEqual(batch["decisions"][0]["decision"], "review_required")
        self.assertIn("candidate", batch["decisions"][0])
        self.assertEqual(batch["results"][0]["errors"][0]["code"], "review_required")
        self.assertFalse(self.path.exists())

    def test_frozen_mode_never_generates_and_can_reuse_registered_custom_parser(self):
        generator = CountingGenerator()
        frozen = SchemaAgent(self.registry, generator=generator, frozen=True).process_batch(self.samples)
        self.assertEqual(frozen["summary"]["quarantined"], 2)
        self.assertEqual(generator.calls, [])
        SchemaAgent(self.registry).process_batch(self.samples)
        frozen = SchemaAgent(self.registry, generator=generator, frozen=True).process_batch(self.samples)
        self.assertEqual(frozen["summary"]["accepted"], 2)
        self.assertEqual(generator.calls, [])

    def test_mixed_sources_and_failures_keep_original_order_and_input(self):
        known = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        records = [self.samples[0], known, ["not an event"], self.samples[1]]
        original = deepcopy(records)
        result = SchemaAgent(self.registry).process_batch(records)
        self.assertEqual(records, original)
        self.assertEqual([r["status"] for r in result["results"]], ["accepted", "accepted", "quarantined", "accepted"])
        self.assertEqual(get_field(result["results"][3]["event"], "user.name"), "office-user")

    def test_field_signature_groups_get_distinct_parser_ids(self):
        changed = dict(self.samples[1], additional_note="new shape")
        batch = SchemaAgent(self.registry).process_batch([self.samples[0], changed])
        self.assertEqual(batch["summary"]["created_schemas"], 2)
        self.assertNotEqual(batch["results"][0]["schema_id"], batch["results"][1]["schema_id"])

    def test_missing_route_prevents_generation_and_registration(self):
        from tracehunt_schema.config import Config
        generator = CountingGenerator()
        batch = SchemaAgent(self.registry, Config(routes={"sysmon": "sysmon"}), generator).process_batch(self.samples)
        self.assertEqual(batch["results"][0]["errors"][0]["code"], "missing_route")
        self.assertEqual(generator.calls, [])
        self.assertFalse(self.path.exists())

    def test_absent_source_paths_are_rejected_and_repair_receives_feedback(self):
        class RepairGenerator(CountingGenerator):
            def propose(self, samples, context):
                proposal = super().propose(samples, context)
                if len(self.calls) == 1:
                    proposal["mappings"][1]["sources"] = ["hallucinated_host"]
                return proposal
        generator = RepairGenerator()
        batch = SchemaAgent(self.registry, generator=generator).process_batch(self.samples)
        self.assertEqual(batch["summary"]["accepted"], 2)
        self.assertIn("repair", batch["decisions"][0]["states"])
        self.assertEqual(len(generator.calls), 2)
        self.assertIn("absent source paths", generator.calls[1]["previous_errors"][0]["message"])

    def test_retry_limit_and_unmapped_timestamp_do_not_activate_parser(self):
        sample = {"unrecognized_time": "2026-09-30T07:00:00Z", "account": "lab-user"}
        batch = SchemaAgent(self.registry, max_attempts=2).process_batch([sample])
        self.assertEqual(len(batch["decisions"][0]["attempts"]), 2)
        self.assertEqual(batch["results"][0]["errors"][0]["code"], "candidate_failed")
        self.assertFalse(self.path.exists())

    def test_non_json_values_remain_serializable_in_failure(self):
        batch = SchemaAgent(self.registry).process_batch([{"value": float("nan")}])
        canonical_json(batch)
        self.assertEqual(batch["results"][0]["status"], "quarantined")

    def test_invalid_limits_and_raw_text_lengths_are_rejected(self):
        for kwargs in ({"max_attempts": 0}, {"max_attempts": 4}, {"max_samples": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SchemaError):
                SchemaAgent(self.registry, **kwargs)
        with self.assertRaises(SchemaError):
            SchemaAgent(self.registry).process_batch(self.samples, raw_texts=["one"])


class ModelAdapterTests(unittest.TestCase):
    def samples(self):
        return [{"observed_at": "2026-09-30T07:00:00Z", "account_name": "lab-user"}]

    def proposal(self):
        return {"required": ["@timestamp", "user.name"], "mappings": [
            {"target": "@timestamp", "sources": ["observed_at"], "type": "timestamp"},
            {"target": "user.name", "sources": ["account_name"], "type": "keyword"},
        ]}

    def context(self):
        return {"schema_id": "custom-test", "version": "1.0.0",
                "signature": ["account_name", "observed_at"], "previous_errors": []}

    def test_structured_model_request_and_non_alias_fields(self):
        requests = []
        def transport(payload):
            requests.append(payload)
            return {"done": True, "message": {"content": json.dumps(self.proposal())}}
        generator = OllamaGenerator("configured-test-model", transport=transport)
        batch = SchemaAgent(generator=generator).process_batch(self.samples())
        self.assertEqual(batch["summary"]["accepted"], 1)
        self.assertEqual(get_field(batch["results"][0]["event"], "user.name"), "lab-user")
        self.assertFalse(requests[0]["stream"])
        self.assertEqual(requests[0]["format"]["type"], "object")
        self.assertEqual(requests[0]["options"]["temperature"], 0)
        self.assertEqual(json.loads(requests[0]["messages"][1]["content"])["samples"], self.samples())

    def test_wrong_model_target_type_is_rejected_by_code(self):
        proposal = self.proposal()
        proposal["mappings"][0]["type"] = "text"
        generator = OllamaGenerator("configured-test-model", transport=lambda _: {
            "done": True, "message": {"content": json.dumps(proposal)}})
        registry = SchemaRegistry()
        batch = SchemaAgent(registry, generator=generator).process_batch(self.samples())
        self.assertEqual(batch["summary"]["accepted"], 0)
        self.assertEqual(len(registry.list_schemas()), 3)

    def test_bad_model_json_and_incomplete_response_are_errors(self):
        for response in ({"done": False}, {"done": True, "message": {"content": "not JSON"}},
                         {"done": True, "message": {"content": "[]"}}):
            with self.subTest(response=response), self.assertRaises(SchemaError):
                OllamaGenerator("configured-test-model", transport=lambda _: response).propose(self.samples(), self.context())

    def test_model_connection_failure_is_quarantined_after_bounded_attempts(self):
        def unavailable(_):
            raise OSError("test model service unavailable")
        generator = OllamaGenerator("configured-test-model", transport=unavailable)
        batch = SchemaAgent(generator=generator).process_batch(self.samples())
        self.assertEqual(batch["summary"]["quarantined"], 1)
        self.assertEqual(len(batch["decisions"][0]["attempts"]), 2)
        self.assertIn("service unavailable", batch["decisions"][0]["attempts"][0]["errors"][0]["message"])

    def test_generator_configuration_and_prompt_limits(self):
        for kwargs in ({"model": ""}, {"model": "test", "endpoint": "file:///tmp/model"},
                       {"model": "test", "timeout_s": 120}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SchemaError):
                OllamaGenerator(**kwargs)
        with self.assertRaisesRegex(SchemaError, "256 KiB"):
            OllamaGenerator("test", transport=lambda _: {}).propose(
                [{"observed_at": "2026-09-30T07:00:00Z", "account_name": "x" * 300_000}], self.context())


if __name__ == "__main__":
    unittest.main()
