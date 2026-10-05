"""Offline commands for normalization, candidate review, and registry inspection."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys

from .config import Config
from .errors import RecordError, SchemaError
from .fields import canonical_json, digest
from .inference import infer_candidate
from .io import QuarantineWriter, decode, load_samples, open_new_output, read_ndjson, write_line
from .pipeline import SchemaPipeline
from .registry import SchemaRegistry
from .agent import SchemaAgent
from .generators import OllamaGenerator


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TraceHunt schema and data-quality tools")
    commands = parser.add_subparsers(dest="command", required=True)
    process = commands.add_parser("normalize", help="Validate NDJSON; separate accepted events and quarantine")
    process.add_argument("--input", required=True)
    process.add_argument("--output", required=True, help="Accepted result envelopes (new file)")
    process.add_argument("--quarantine", required=True, help="Append-only failure JSONL")
    process.add_argument("--events-output", help="Plain ECS events, suitable as Logstash JSON input")
    process.add_argument("--bulk-output", help="Elasticsearch bulk request file; no requests are sent")
    process.add_argument("--source", choices=("windows-security", "sysmon", "zeek", "custom-json"))
    process.add_argument("--schema-id", help="Pin a parser id; defaults to source/shape selection")
    process.add_argument("--schema-version", help="Pin a parser version (requires --schema-id)")
    process.add_argument("--registry", help="Directory containing approved custom definitions")
    process.add_argument("--config", help="Routing and timestamp configuration JSON")

    onboard = commands.add_parser("onboard", help="Automatically select or create, validate, and register parsers")
    onboard.add_argument("--input", required=True)
    onboard.add_argument("--output", required=True)
    onboard.add_argument("--quarantine", required=True)
    onboard.add_argument("--audit", required=True, help="New JSONL decision log, including candidates and validation errors")
    onboard.add_argument("--registry", required=True, help="Approved parser directory")
    onboard.add_argument("--events-output")
    onboard.add_argument("--bulk-output")
    onboard.add_argument("--source", choices=("windows-security", "sysmon", "zeek", "custom-json"))
    onboard.add_argument("--config")
    onboard.add_argument("--generator", choices=("rules", "ollama"), default="rules")
    onboard.add_argument("--model", default=os.environ.get("TRACEHUNT_SCHEMA_MODEL"))
    onboard.add_argument("--model-endpoint", default=os.environ.get("TRACEHUNT_SCHEMA_MODEL_ENDPOINT", "http://localhost:11434/api/chat"))
    onboard.add_argument("--model-timeout", type=float, default=30)
    onboard.add_argument("--max-attempts", type=int, default=2)
    onboard.add_argument("--max-samples", type=int, default=16)
    onboard.add_argument("--batch-size", type=int, default=128)
    onboard.add_argument("--review-only", action="store_true", help="Save validated candidates without activating them")
    onboard.add_argument("--frozen", action="store_true", help="Use registered parsers only; disable generation")

    infer = commands.add_parser("infer", help="Propose and test a candidate without activating it")
    infer.add_argument("--samples", required=True)
    infer.add_argument("--output", required=True)
    infer.add_argument("--schema-id", default="custom-json")
    infer.add_argument("--schema-version", default="1.0.0")
    infer.add_argument("--config")

    approve = commands.add_parser("approve", help="Revalidate reviewed candidate samples, then register")
    approve.add_argument("--candidate", required=True)
    approve.add_argument("--samples", required=True)
    approve.add_argument("--registry", required=True)
    approve.add_argument("--config")
    approve.add_argument("--expected-events", help="Optional golden ECS events for semantic comparison")

    schemas = commands.add_parser("schemas", help="List definitions or inspect one schema")
    schemas.add_argument("--registry")
    schemas.add_argument("--schema-id")
    schemas.add_argument("--schema-version")
    return parser


def decoding_failure(source, text, issue):
    result = {"status": "quarantined", "source": source, "schema_id": None,
              "schema_version": None, "raw_record": None, "raw_text": text,
              "errors": [issue.as_dict()]}
    if issue.raw_bytes_base64 is not None:
        result["raw_bytes_base64"] = issue.raw_bytes_base64
    return result


def validate_output_paths(input_name, output_names, config_name=None, registry_name=None):
    source = Path(input_name).resolve()
    outputs = [Path(name).resolve() for name in output_names if name]
    if not source.is_file():
        raise SchemaError("input file does not exist")

    def same_file(first, second):
        return first == second or (first.exists() and second.exists() and first.samefile(second))

    protected = [source]
    if config_name:
        protected.append(Path(config_name).resolve())
    registry_paths = [(Path(__file__).parent / "schemas").resolve()]
    if registry_name:
        registry_paths.append(Path(registry_name).resolve())
        if same_file(registry_paths[-1], source):
            raise SchemaError("registry must be a separate directory")
    for directory in registry_paths:
        protected.extend(directory.glob("*.json"))
    for position, output in enumerate(outputs):
        if any(same_file(output, item) for item in protected + outputs[:position]):
            raise SchemaError("input, config, and output files must be distinct, including hard links")
        if any(output.is_relative_to(directory) for directory in registry_paths):
            raise SchemaError("output files must be outside parser registry directories")
        if output.exists() and not output.is_file():
            raise SchemaError("output paths must refer to files")
    return source


def run_normalize(args) -> int:
    if args.schema_version and not args.schema_id:
        raise SchemaError("--schema-version requires --schema-id")
    pipeline = SchemaPipeline(SchemaRegistry(args.registry), Config.load(args.config))
    output_names = [args.output, args.quarantine, args.events_output, args.bulk_output]
    input_path = validate_output_paths(args.input, output_names, args.config, args.registry)
    for name in (args.output, args.events_output, args.bulk_output):
        if name and Path(name).exists():
            raise SchemaError(f"output already exists; use a new run directory: {name}")
    quarantine = QuarantineWriter(args.quarantine)
    counts = {"processed": 0, "accepted": 0, "quarantined": 0}
    with ExitStack() as stack:
        accepted = stack.enter_context(open_new_output(args.output))
        events = stack.enter_context(open_new_output(args.events_output)) if args.events_output else None
        bulk = stack.enter_context(open_new_output(args.bulk_output)) if args.bulk_output else None
        for number, text, record, issue in read_ndjson(args.input):
            counts["processed"] += 1
            if issue:
                result = decoding_failure(args.source, text, issue)
            else:
                result = pipeline.process(record, args.source, text, args.schema_id, args.schema_version)
            if result["status"] == "quarantined":
                counts["quarantined"] += 1
                result["input_file"] = str(input_path)
                result["line_number"] = number
                quarantine.append(result)
            else:
                counts["accepted"] += 1
                write_line(accepted, result)
                if events:
                    write_line(events, result["event"])
                if bulk:
                    write_line(bulk, {"index": {"_index": result["index"], "_id": result["document_id"]}})
                    write_line(bulk, result["event"])
    print(canonical_json(counts))
    return 2 if counts["quarantined"] else 0


def run_onboard(args) -> int:
    if not 1 <= args.batch_size <= 1024:
        raise SchemaError("--batch-size must be between 1 and 1024")
    cfg = Config.load(args.config)
    generator = OllamaGenerator(args.model, args.model_endpoint, args.model_timeout) if args.generator == "ollama" else None
    agent = SchemaAgent(SchemaRegistry(args.registry), cfg, generator, args.max_attempts,
                        args.max_samples, args.review_only, args.frozen)
    source = validate_output_paths(args.input, (args.output, args.quarantine, args.audit,
                                               args.events_output, args.bulk_output), args.config, args.registry)
    for name in (args.output, args.audit, args.events_output, args.bulk_output):
        if name and Path(name).exists():
            raise SchemaError(f"output already exists; use a new run directory: {name}")
    quarantine = QuarantineWriter(args.quarantine)
    counts = {"processed": 0, "accepted": 0, "quarantined": 0, "created_schemas": 0}
    with ExitStack() as stack:
        accepted = stack.enter_context(open_new_output(args.output))
        audit = stack.enter_context(open_new_output(args.audit))
        events = stack.enter_context(open_new_output(args.events_output)) if args.events_output else None
        bulk = stack.enter_context(open_new_output(args.bulk_output)) if args.bulk_output else None

        def flush(batch):
            valid = [row for row in batch if row[3] is None]
            processed = agent.process_batch([row[2] for row in valid], args.source,
                                            [row[1] for row in valid])
            counts["created_schemas"] += processed["summary"]["created_schemas"]
            for decision in processed["decisions"]:
                decision["input_file"] = str(source)
                decision["line_numbers"] = [valid[p][0] for p in decision["positions"]]
                write_line(audit, decision)
            results = iter(processed["results"])
            for number, text, record, issue in batch:
                counts["processed"] += 1
                if issue:
                    result = decoding_failure(args.source, text, issue)
                    write_line(audit, {"decision": "quarantine", "states": ["decode", "quarantine"],
                                       "input_file": str(source), "line_numbers": [number],
                                       "errors": [issue.as_dict()]})
                else:
                    result = next(results)
                if result["status"] == "quarantined":
                    counts["quarantined"] += 1
                    result.update(input_file=str(source), line_number=number)
                    quarantine.append(result)
                else:
                    counts["accepted"] += 1
                    write_line(accepted, result)
                    if events:
                        write_line(events, result["event"])
                    if bulk:
                        write_line(bulk, {"index": {"_index": result["index"], "_id": result["document_id"]}})
                        write_line(bulk, result["event"])
            # Keep decisions visible even if later input or output fails.
            audit.flush()
            os.fsync(audit.fileno())

        batch = []
        for row in read_ndjson(args.input):
            batch.append(row)
            if len(batch) >= args.batch_size:
                flush(batch)
                batch = []
        if batch:
            flush(batch)
    print(canonical_json(counts))
    return 2 if counts["quarantined"] else 0


def main(argv: list[str] | None = None) -> int:
    args = arguments().parse_args(argv)
    try:
        if args.command == "normalize":
            return run_normalize(args)
        if args.command == "onboard":
            return run_onboard(args)
        if args.command == "infer":
            candidate = infer_candidate(load_samples(args.samples), args.schema_id,
                                        args.schema_version, Config.load(args.config))
            with open_new_output(args.output) as stream:
                stream.write(json.dumps(candidate, indent=2, ensure_ascii=False) + "\n")
            print(canonical_json({"status": "candidate", "validation": candidate["validation"],
                                  "review_required": True}))
            return 0 if candidate["validation"]["passed"] else 2
        if args.command == "approve":
            candidate = decode(Path(args.candidate).read_text(encoding="utf-8-sig"))
            samples = load_samples(args.samples)
            if not isinstance(candidate, dict) or candidate.get("status") != "candidate":
                raise SchemaError("candidate file must contain an infer result")
            if candidate.get("sample_hash") != digest(samples):
                raise SchemaError("samples changed since inference; generate a new candidate")
            expected = load_samples(args.expected_events) if args.expected_events else None
            result = SchemaRegistry(args.registry).approve(candidate["schema"], samples,
                                                           Config.load(args.config), expected)
            print(canonical_json(result))
            return 0
        registry = SchemaRegistry(args.registry)
        if args.schema_version and not args.schema_id:
            raise SchemaError("--schema-version requires --schema-id")
        result = registry.get_schema(args.schema_id, args.schema_version) if args.schema_id else registry.list_schemas()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (SchemaError, RecordError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print(canonical_json({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 1
