"""Bounded schema onboarding: inspect, select, propose, validate, register, apply."""

from copy import deepcopy

from .classifier import classify
from .config import Config
from .errors import RecordError, SchemaError
from .fields import digest, leaf_paths, validate_record
from .generators import AliasGenerator, CandidateGenerator
from .parser import normalize
from .pipeline import SchemaPipeline
from .registry import SchemaRegistry, validate_definition


class SchemaAgent:
    """Coordinate one batch and retain an auditable decision for each format.

    Known-parser failures never trigger a new parser. Generated candidates must
    validate every record in their field-signature group before activation.
    """

    def __init__(self, registry: SchemaRegistry | None = None, config: Config | None = None,
                 generator: CandidateGenerator | None = None, max_attempts: int = 2,
                 max_samples: int = 16, review_only: bool = False, frozen: bool = False):
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 3:
            raise SchemaError("max_attempts must be an integer between 1 and 3")
        if not isinstance(max_samples, int) or isinstance(max_samples, bool) or not 1 <= max_samples <= 64:
            raise SchemaError("max_samples must be an integer between 1 and 64")
        self.registry = registry or SchemaRegistry()
        self.config = config or Config()
        self.generator = generator or AliasGenerator(self.config)
        self.pipeline = SchemaPipeline(self.registry, self.config)
        self.max_attempts = max_attempts
        self.max_samples = max_samples
        self.review_only = review_only
        self.frozen = frozen

    def process_batch(self, records: list, source_hint: str | None = None,
                      raw_texts: list[str | None] | None = None) -> dict:
        if raw_texts is None:
            raw_texts = [None] * len(records)
        if len(raw_texts) != len(records):
            raise SchemaError("raw_texts must have one entry per input record")
        results: list = [None] * len(records)
        groups = {}
        decisions = []
        for position, record in enumerate(records):
            try:
                validate_record(record, raw_texts[position])
                source = classify(record, source_hint)
                signature = leaf_paths(record)
                groups.setdefault((source, tuple(signature)), []).append(position)
            except (RecordError, ValueError, TypeError, RecursionError):
                results[position] = self.pipeline.process(record, source_hint, raw_texts[position])
                decisions.append({"decision": "quarantine", "positions": [position],
                                  "states": ["inspect", "quarantine"], "errors": results[position]["errors"]})

        for (source, signature_tuple), positions in groups.items():
            signature = list(signature_tuple)
            decision = {"source": source, "signature": signature, "positions": positions,
                        "states": ["inspect", "classify", "select"], "attempts": []}
            decisions.append(decision)
            samples = [records[p] for p in positions]
            try:
                spec = self.registry.select(source, samples[0])
            except SchemaError as exc:
                self._fail_group(decision, results, records, raw_texts, "schema_error", str(exc))
                continue
            if spec is not None:
                decision.update(decision="reuse", schema_id=spec["id"], schema_version=spec["version"])
                decision["states"].append("apply")
                for p in positions:
                    results[p] = self.pipeline.process(records[p], source_hint, raw_texts[p],
                                                       spec["id"], spec["version"])
                decision["accepted"] = sum(results[p]["status"] == "accepted" for p in positions)
                decision["quarantined"] = len(positions) - decision["accepted"]
                continue
            if self.frozen:
                self._fail_group(decision, results, records, raw_texts, "unknown_format",
                                 "frozen mode requires a pre-registered parser")
                continue
            if source not in (None, "custom-json"):
                self._fail_group(decision, results, records, raw_texts, "unknown_format",
                                 "known source has no registered parser")
                continue
            if "custom-json" not in self.config.routes:
                self._fail_group(decision, results, records, raw_texts, "missing_route",
                                 "no output index configured for custom-json")
                continue

            schema_id = "custom-" + digest(signature)[:16]
            feedback = []
            for attempt in range(1, self.max_attempts + 1):
                decision["states"].append("propose" if attempt == 1 else "repair")
                context = {"schema_id": schema_id, "version": "1.0.0", "signature": signature,
                           "attempt": attempt, "previous_errors": deepcopy(feedback)}
                feedback = []
                try:
                    proposal = self.generator.propose(deepcopy(samples[:self.max_samples]), context)
                    spec = {"id": schema_id, "version": "1.0.0", "source": "custom-json",
                            "dataset": "custom.json", "signature": signature,
                            "description": f"Generated by {self.generator.name}; validated before activation.",
                            "mappings": proposal["mappings"], "required": proposal["required"]}
                    decision["states"].append("validate")
                    validate_definition(spec)
                    targets = [m["target"] for m in spec["mappings"]]
                    if len(targets) < 2:
                        raise SchemaError("candidate needs a timestamp and another event field")
                    for mapping in spec["mappings"]:
                        if any(path not in signature for path in mapping["sources"]):
                            raise SchemaError(f"candidate refers to absent source paths for {mapping['target']}")
                    feedback = []
                    for p in positions:
                        try:
                            normalize(records[p], spec, self.config)
                        except RecordError as exc:
                            feedback.append({"position": p, **exc.as_dict()})
                    if feedback:
                        raise SchemaError("candidate failed record validation")
                    used = {path for m in spec["mappings"] for path in m["sources"]}
                    decision["candidate"] = {"status": "candidate", "schema": deepcopy(spec),
                                             "sample_hash": digest(samples),
                                             "unmapped_fields": sorted(set(signature) - used)}
                    decision["attempts"].append({"attempt": attempt, "status": "passed", "errors": []})
                    break
                except (SchemaError, RecordError, KeyError, TypeError, ValueError) as exc:
                    if not feedback:
                        feedback = [{"code": "candidate_error", "message": str(exc)}]
                    decision["attempts"].append({"attempt": attempt, "status": "failed",
                                                 "errors": deepcopy(feedback)})
            else:
                self._fail_group(decision, results, records, raw_texts, "candidate_failed",
                                 "no candidate passed the bounded validation attempts")
                continue

            decision["generator"] = self.generator.name
            decision["validated_records"] = len(samples)
            decision["semantic_verification"] = "field types and required values; no external ground truth"
            if self.review_only:
                decision["decision"] = "review_required"
                self._fail_group(decision, results, records, raw_texts, "review_required",
                                 "candidate passed validation but review-only mode prevents activation",
                                 preserve_decision=True)
                continue
            decision["states"].append("register")
            # I/O failures propagate, rather than claiming durable registration succeeded.
            try:
                self.registry.approve(spec, samples, self.config)
            except (SchemaError, RecordError) as exc:
                self._fail_group(decision, results, records, raw_texts, "schema_error", str(exc))
                continue
            decision.update(decision="created", schema_id=spec["id"], schema_version=spec["version"])
            decision["states"].append("apply")
            for p in positions:
                results[p] = self.pipeline.process(records[p], "custom-json", raw_texts[p],
                                                   spec["id"], spec["version"])

        accepted = sum(r["status"] == "accepted" for r in results)
        return {"results": results, "decisions": decisions,
                "summary": {"processed": len(records), "accepted": accepted,
                            "quarantined": len(records) - accepted,
                            "created_schemas": sum(d["decision"] == "created" for d in decisions)}}

    @staticmethod
    def _fail_group(decision, results, records, raw_texts, code, message, preserve_decision=False):
        if not preserve_decision:
            decision["decision"] = "quarantine"
        decision["states"].append("quarantine")
        for p in decision["positions"]:
            results[p] = {"status": "quarantined", "source": decision["source"],
                          "schema_id": None, "schema_version": None,
                          "raw_record": deepcopy(records[p]), "raw_text": raw_texts[p],
                          "errors": [{"code": code, "field": None, "message": message}]}
