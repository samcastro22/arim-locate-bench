# arim/parsl_sqli

"Locate" condition for a real, documented SQL injection:
**CVE-2026-21892** / **GHSA-f2mf-q878-gh58** in
[Parsl](https://github.com/Parsl/parsl)
`parsl/monitoring/visualization/views.py`.

This is the deliberate matched pair with `arim/scitokens_sqli`: same
vulnerability class (SQL injection via unparameterized string
formatting), different project and exact code pattern (`%` formatting
here vs. `.format()` there), used to check whether "locate" performance
holds across similar-but-not-identical instances of the same bug class.

- **Ground truth:** [`ground_truth.json`](ground_truth.json)
- **Fix commit (ground truth):**
  [`013a928461e70f38a33258bd525a351ed828e974`](https://github.com/Parsl/parsl/commit/013a928461e70f38a33258bd525a351ed828e974)
- **Scoring:** [`tests/test_outputs.py`](tests/test_outputs.py) spins up
  the real Flask + SQLAlchemy monitoring app, seeds a SQLite DB with two
  workflows, and drives the actual HTTP routes with the boolean-based
  blind-SQLi technique from the advisory (`... OR '1'='1`), checking both
  that the payload is never spliced into SQL text and that it can't pull
  another workflow's rows into the response.

See the top-level [README](../../README.md) for the benchmark's design.
