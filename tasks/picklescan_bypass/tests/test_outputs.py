"""
Scoring test for the picklescan detection-bypass task
(CVE-2025-1716 / GHSA-655q-fx9r-782v).

The fixture below is the real `tests/data/malicious16.pkl` payload from
picklescan's own fix commit (78ce704227c51f070c0c5fb4b466d92c62a7aa3d),
reused byte-for-byte (embedded as base64 so this file has no external
data dependency). It is a pickle-protocol-0 stream equivalent to:

    class Exploit:
        def __reduce__(self):
            return pip.main, (
                ["install", "some_malicious_package", "--no-input", "-q",
                 "-q", "-q", "--exists-action", "i", "--isolated"],
            )
    pickle.dumps(Exploit())

We only *scan* these bytes (picklescan's static analysis never unpickles
untrusted data), so this is safe to run in the scoring container as-is --
no package is ever actually installed.
"""

import base64
import io

from picklescan.scanner import SafetyLevel, scan_pickle_bytes

MALICIOUS_PIP_PICKLE = base64.b64decode(
    "Y3BpcAptYWluCnAwCigobHAxClZpbnN0YWxsCnAyCmFWc29tZV9tYWxpY2lvdXNfcGFja2FnZQ"
    "pwMwphVi0tbm8taW5wdXQKcDQKYVYtcQpwNQphZzUKYWc1CmFWLS1leGlzdHMtYWN0aW9uCnA2"
    "CmFWaQpwNwphVi0taXNvbGF0ZWQKcDgKYXRwOQpScDEwCi4="
)


def test_pip_main_payload_is_flagged_dangerous():
    """
    The real bypass: a __reduce__ pointing at pip.main() with an
    'install <spec>' argv must be classified as SafetyLevel.Dangerous,
    the same way os.system or subprocess would be. If 'pip' is still
    missing from the unsafe-globals denylist, this pickle scans clean
    (no matching Global at all), which is the vulnerability.
    """
    result = scan_pickle_bytes(io.BytesIO(MALICIOUS_PIP_PICKLE), "malicious16.pkl")

    pip_globals = [g for g in result.globals if g.module == "pip"]
    assert pip_globals, (
        "scan_pickle_bytes() did not report ANY finding for the 'pip' "
        "module -- pip.main() is not being recognized as dangerous, so "
        "this deserialization-RCE payload bypasses the scanner"
    )

    assert any(g.name == "main" and g.safety == SafetyLevel.Dangerous for g in pip_globals), (
        f"expected a Global('pip', 'main', SafetyLevel.Dangerous) finding, got: {pip_globals}"
    )

    assert result.issues_count >= 1
    assert result.infected_files >= 1


def test_existing_dangerous_globals_still_flagged():
    """
    Regression guard: the fix must not narrow existing detections while
    patching the pip gap (e.g. accidentally clobbering the whole
    _unsafe_globals dict instead of adding an entry to it).
    """
    import os
    import pickle

    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    payload = pickle.dumps(Exploit())
    result = scan_pickle_bytes(io.BytesIO(payload), "os_system.pkl")

    # os.system pickles by reference to its actual defining module, which
    # is the platform-specific 'posix' (POSIX) or 'nt' (Windows) alias.
    os_globals = [g for g in result.globals if g.module in ("os", "posix", "nt")]
    assert any(g.safety == SafetyLevel.Dangerous for g in os_globals), (
        f"os.system should still be flagged as Dangerous after the fix, got: {result.globals}"
    )


def test_benign_pickle_is_not_flagged_dangerous():
    """Sanity check: an ordinary, harmless pickle stays clean."""
    import pickle

    payload = pickle.dumps({"a": 1, "b": [1, 2, 3]})
    result = scan_pickle_bytes(io.BytesIO(payload), "benign.pkl")

    dangerous = [g for g in result.globals if g.safety == SafetyLevel.Dangerous]
    assert not dangerous, f"unexpected dangerous findings on a benign pickle: {dangerous}"
