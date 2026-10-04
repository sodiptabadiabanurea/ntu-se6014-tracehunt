# Member 1: ELK Infrastructure & Integration

This directory owns the shared TraceHunt Elasticsearch 8.12, Logstash, and Kibana stack plus the production index templates and access-control bootstrap.

## Security model

Security is enabled in Elasticsearch. No service uses a hard-coded password.

The stack creates these service identities during the one-shot `security-setup` phase:

- `logstash_writer`: writes only to `tracehunt-raw-*`; it cannot write to normalized hunt indices.
- `tracehunt_ro`: uses the exact M4 role contract from `m4-mcp/es/readonly_role.json`; it can only `read` and `view_index_metadata` on `windows-security`, `sysmon`, and `zeek`.
- `kibana_system`: the built-in Kibana service account.

All published ports are bound to `127.0.0.1`.

## M3/M4 integration contract

`index_template.json` is the M1 production copy of the field contract currently defined by M3 PR #7. It includes the normalized ECS fields and TraceHunt provenance fields used by M3. The M3 example template remains a schema proposal; M1 owns installation of the production template.

`raw_index_template.json` is intentionally separate. Raw Logstash landing events go to `tracehunt-raw-YYYY.MM.dd` and must not be forced through the normalized M3 mapping.

The MCP account is not given access to `tracehunt-raw-*` or `logstash-*`. M4's allowlist remains the security boundary.

## Quick start

1. Create the local environment file:

   ```bash
   cd m1-elk
   cp .env.example .env
   ```

2. Replace all four example passwords in `.env`.

3. Start the stack:

   ```bash
   docker compose up -d
   ```

   Elasticsearch starts first. The one-shot `security-setup` service then creates the required users, roles, and templates. Logstash and Kibana start only after that setup exits successfully.

4. Inspect the services:

   ```bash
   docker compose ps -a
   ```

   `tracehunt-security-setup` should show exit code 0. Elasticsearch, Logstash, and Kibana should remain running.

5. Run the integration health check.

   PowerShell 7:

   ```powershell
   $env:ELASTIC_PASSWORD = "<same value as .env>"
   $env:TRACEHUNT_RO_PASSWORD = "<same value as .env>"
   pwsh -File ./health_check.ps1
   ```

   The check proves authenticated Elasticsearch health, Logstash and Kibana reachability, raw TCP ingestion, acceptance of an M3-shaped normalized event, successful M4 read-only access, and HTTP 403 on an attempted M4 write.

## M4 client wiring

For the shared stack, M4 should use:

```text
TRACEHUNT_ES_URL=http://127.0.0.1:9200
TRACEHUNT_ES_USERNAME=tracehunt_ro
TRACEHUNT_ES_PASSWORD=<TRACEHUNT_RO_PASSWORD from .env>
TRACEHUNT_INDICES=windows-security,sysmon,zeek
```

Do not give the MCP server the `elastic` administrator credentials.

## Rebuild and reset

- Stop services, keep data: `docker compose down`
- Full reset including Elasticsearch data: `docker compose down -v`
- Re-run the complete bootstrap after a reset: `docker compose up -d`
- Inspect setup output: `docker compose logs security-setup`

If `ELASTIC_PASSWORD` is changed after an Elasticsearch data volume already exists, reset the volume or restore the password expected by that existing cluster.

## Verification in CI

`.github/workflows/m1-elk-tests.yml` performs a clean-stack integration run on every relevant pull request. It validates JSON and Compose configuration, boots the secured stack, executes the PowerShell health check, proves Logstash ingestion, checks the M3-shaped mapping, and proves the M4 account cannot write.

## Remediation ownership

After review of the earlier M1 implementation, the affected M1 integration work was rebuilt from the current `main` baseline rather than carrying forward the broken branch state.

The clean rebuild, security/authentication fixes, M3/M4 contract alignment, integration testing, and final verification are performed by **Sodipta Badia Banurea (Matric No. G2503577L)**.

The earlier M1 contribution is retained only as a reference for the intended scope; the replacement implementation is reviewed and tested independently before merge.
