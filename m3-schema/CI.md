# M3 Continuous Integration

The workflow is defined in [m3-schema.yml](../.github/workflows/m3-schema.yml).
It runs on pushes to `main` or `m3/**`, pull requests targeting `main`, and manual
dispatch after the workflow is available on the repository's default branch.

Each job runs the offline automated suite and field-mutation check on Windows
and Ubuntu with Python 3.11 and 3.12. No third-party test dependencies, live model,
or Elasticsearch service are needed. Mutation checks still run after a suite
failure if Python setup succeeded. A non-zero test exit code fails the job.

From `m3-schema`, reproduce the checks with:

```powershell
python -m unittest discover -s tests -v
python tests/mutation_check.py
```

In GitHub, open **Actions > M3 schema checks** and select the relevant commit.
Logs and the mutation summary are retained as separate report artifacts for
each operating-system/Python combination for 14 days. Pull-request workflows
from forks may require maintainer approval.

These checks verify synthetic fixtures and mocked model responses. Real
connector output and end-to-end Elasticsearch ingestion require separate
integration evidence; a green CI run does not establish those results.
