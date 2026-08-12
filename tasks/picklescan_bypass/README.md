# arim/picklescan_bypass

"Locate" condition for a real, documented detection-evasion bug:
**CVE-2025-1716** / **GHSA-655q-fx9r-782v** in
[picklescan](https://github.com/mmaitre314/picklescan)
`src/picklescan/scanner.py`.

This is the odd one out among the four tasks: the vulnerability isn't
unsafe code, it's an *incomplete denylist* in a security scanner itself.
`pip.main()` looks like an ordinary package-management call, not an
attack primitive, so it was never added to `_unsafe_globals` — a crafted
pickle whose `__reduce__` returns `(pip.main, (["install", <malicious
spec>, ...],))` scans clean and achieves RCE on `pickle.loads()`.

- **Ground truth:** [`ground_truth.json`](ground_truth.json)
- **Fix commit (ground truth):**
  [`78ce704227c51f070c0c5fb4b466d92c62a7aa3d`](https://github.com/mmaitre314/picklescan/commit/78ce704227c51f070c0c5fb4b466d92c62a7aa3d)
- **Scoring:** [`tests/test_outputs.py`](tests/test_outputs.py) reuses
  the real `tests/data/malicious16.pkl` payload from that fix commit,
  byte-for-byte (embedded as base64), and asserts `scan_pickle_bytes()`
  flags it `SafetyLevel.Dangerous`.

See the top-level [README](../../README.md) for the benchmark's design.
