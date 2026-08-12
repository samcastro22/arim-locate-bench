# arim/scitokens_sqli

"Locate" condition for a real, documented SQL injection: **CVE-2026-32714**
in [scitokens](https://github.com/scitokens/scitokens)
`src/scitokens/utils/keycache.py`.

- **Ground truth:** [`ground_truth.json`](ground_truth.json) — 5 real
  injection sites, all in the same file, all requiring a fix.
- **Fix commit (ground truth):**
  [`3dba108853f2f4a6c0f2325c03779bf083c41cf2`](https://github.com/scitokens/scitokens/commit/3dba108853f2f4a6c0f2325c03779bf083c41cf2)
- **Scoring:** [`tests/test_outputs.py`](tests/test_outputs.py), adapted
  from the real regression tests the maintainers shipped with the fix —
  boolean-injection (`x' OR '1'='1`), UNION-injection, and no-leak checks
  against the patched `KeyCache`.

See the top-level [README](../../README.md) for the benchmark's design.
