# TraceHunt project wiki

Last updated: 5 October 2026.

This folder is the versioned project wiki. The repository's GitHub Wiki feature is currently disabled, so durable project notes live under `docs/` and go through normal repository history.

## Review workflow

- Members work in their own role branch or fork.
- All implementation changes arrive through pull requests.
- The project lead reviews member PRs before merge.
- `main` is the integration source of truth.
- A member PR must not be merged without the project lead's explicit instruction.
- A PR is not considered done until the relevant tests and integration checks pass.

## Current role status

| Role | Scope | Status |
|---|---|---|
| M1 | ELK stack, integration, index templates, access control | **Complete. PR #12 merged to `main` at `23db5f407ea168b6fd35b86b3a27445ba46563b8` after final GitHub CI and Oracle VPS validation passed.** |
| M2 | Windows EVTX, Sysmon, and Zeek connectors | No merged implementation yet. |
| M3 | Schema agent, ECS mapping, parser registry, validation, quarantine | PR #7 is open. Current reviewed head `ebd77c7548e1c58224576b2eeda3ecb8e4466404` includes CI; its real five-event bulk export is compatible with merged M1. It still needs to sync with the latest `main` and later test real M2 connector output. **Do not merge yet without project-lead approval.** |
| M4 | MCP server, typed read-only tools, validation, evidence ledger | **Merged to `main` via PR #2.** |
| M5 | Hunt workflow state machine and verifier | No merged implementation yet. |
| M6 | Ground truth, repeatability experiment, decoy traffic, final experiment | No merged implementation yet. |

## M1 milestone

M1 was completed and merged on 5 October 2026.

- Pull request: #12
- Final PR head: `2e6fab7cffaff14fb063d7ed225bd1672770d444`
- Merge commit: `23db5f407ea168b6fd35b86b3a27445ba46563b8`
- Elasticsearch target: 8.12.0 with security enabled
- Logstash writer: least privilege on `tracehunt-raw-*`
- M4 account: `tracehunt_ro`, read-only on `windows-security`, `sysmon`, and `zeek`
- Host bind mounts fail closed if setup files are missing
- Security bootstrap validates mounted inputs and verifies created resources/privileges
- GitHub final-head push and pull-request integration runs both passed
- Independent Oracle ARM64 VPS validation passed on Docker 29.6.1 / Compose v5.3.1
- Real M3 fixture bulk export: 5 accepted / 0 quarantined; routes `windows-security` 2, `sysmon` 1, `zeek` 2
- Raw Logstash ingestion passed
- M4 read succeeded and write was denied
- Final validation cleanup left no background jobs

See [M1 completion review](./M1_REVIEW.md).

## M3 review status

M3 PR #7 currently points to:

`ebd77c7548e1c58224576b2eeda3ecb8e4466404`

Independent verification and integration evidence now include:

- 101/101 unit and regression tests from the earlier review.
- Mutation coverage from the earlier review with no unexpected mutation failures.
- A GitHub Actions CI workflow is present on the current PR head.
- M3's production-facing mapping contract remains compatible with merged M1.
- The current M3 bulk-export path normalized five known mixed fixture records with 5 accepted / 0 quarantined.
- Those five records were bulk-indexed successfully through merged-M1-compatible templates during final M1 VPS validation.
- The M4 read-only account could retrieve the resulting normalized documents.

Remaining M3 work belongs to the M3 author:

1. Sync PR #7 with the latest `main`, now including the completed M1 merge.
2. Re-run M3 CI after that sync and resolve any integration drift.
3. Once M2 is ready, test against real connector output rather than only synthetic fixtures.

See [M3 review](./M3_REVIEW.md).

## M4 milestone

M4 was merged on 4 October 2026.

- Pull request: #2
- Merge commit: `5fac4b6d262a1cf97db1107a597c9e6465e49a4c`
- Issue #1 closed as completed
- Elasticsearch target aligned with M1: Elasticsearch 8.12.0
- Python client: `elasticsearch>=8.12,<9`
- GitHub Actions covers unit tests, seeded Elasticsearch integration tests, and a real MCP stdio smoke test

See [M4 status and interface](./M4.md).

## Current integration order

1. Treat merged M1 on `main` as the shared ELK, index-template, and access-control source of truth.
2. Keep M3 PR #7 review-only until its author syncs the completed M1 merge and re-runs its checks.
3. Do not merge M3 unless the project lead explicitly asks for it.
4. Integrate M2 connector outputs against the merged M1 raw landing path, then validate those records through M3.
5. Keep M4 wired to the `tracehunt_ro` least-privilege contract from merged M1.
6. Continue M5/M6 work without silently changing the frozen M1/M3/M4 interfaces.
