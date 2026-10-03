# M3 v1.0.0 Review Updates

Compared with the original pull request containing 61 offline automated tests,
this revision corrects field semantics, strengthens validation, and keeps
malformed records from interrupting unrelated records.

## Changes

| Area | Before | After |
|---|---|---|
| Zeek HTTP Host | Bare `host` could populate the computer name | HTTP Host supplies `url.domain`; its port is removed and IPv6 brackets are retained. Computer metadata uses explicit `host.name`. Invalid authorities are quarantined. |
| Empty identifiers and paths | Whitespace-only usernames and executable paths could be accepted | Empty keyword values are rejected. Executable paths must contain a filename; internal spaces remain valid. |
| Windows event codes | Leading zeros could bypass logon/process requirements | Windows Security and Sysmon codes become canonical decimal strings. Account and executable requirements apply after canonicalization. |
| Numeric fields | Integers above the output mapping's range could be accepted | Integer fields use the non-negative signed 64-bit range; ports retain the 0-65535 range. |
| Source classification | Flat Sysmon aliases were missed; damaged known records could enter custom onboarding | Flat and mixed-field Sysmon records are detected. Distinctive source fields retain known validation paths, and malformed source metadata is rejected during automatic classification. |
| Field representation | Some mixtures of dotted keys and nested objects were not resolved; conflicting values could be silently selected | Mixed paths are resolved. Equal representations share a signature; conflicting values are quarantined. ECS host objects no longer hide a valid flat `Computer` alias. |
| Batch resilience | Some encoding, depth, Unicode, or Python API errors could stop a batch | Invalid records are isolated, and later valid records continue. Invalid UTF-8 lines retain original bytes in `raw_bytes_base64`; invalid API values have serializable failure representations. |
| Registry and model errors | Duplicate keys, unsafe parser metadata, numeric version errors, or registration conflicts had incomplete handling | Registry/configuration readers reject duplicate keys and accept UTF-8 BOMs. Definitions are checked before registration. Registration conflicts isolate the affected group; deeply nested model responses follow bounded failure handling. |
| Output files | Path checks missed file aliases and some configuration/registry collisions | Outputs cannot modify input, configuration, or parser definitions, including through hard links. Outputs must stay outside parser registry directories. |

## Validation

- Original tests: 61; added regression tests: 40; current total: **101 passed**.
- Mutation checks: **4,830 variations** through the pipeline and another 4,830
  through the frozen agent, with **zero unexpected failures**. These check
  resilience and serialization, rather than semantic correctness of every variant.
- Full offline demo: passed, including normalization, quarantine, candidate
  generation, approval, automatic registration, and frozen parser reuse.

Run from `m3-schema`:

```powershell
python -m unittest discover -s tests -v
python tests/mutation_check.py
.\run_demo.ps1
```

Generated verification artifacts remain under `output/`, which is excluded from
Git. Samples are synthetic, model responses are mocked, and real connector data,
live-model calls, and end-to-end Elasticsearch ingestion remain unverified.
