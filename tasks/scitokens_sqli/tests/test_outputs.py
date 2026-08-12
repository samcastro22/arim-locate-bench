"""
Scoring test for the scitokens SQL injection task (CVE-2026-32714).

These are adapted, near-verbatim, from the regression test suite the
scitokens maintainers added in the real fix commit
(3dba108853f2f4a6c0f2325c03779bf083c41cf2) for
src/scitokens/utils/keycache.py. They exercise the same boolean-injection
and UNION-injection payloads documented in the advisory. A patch only
passes this file if it actually closes the injection at every call site
that reaches SQL (addkeyinfo / _addkeyinfo, _delete_cache_entry,
_add_negative_cache_entry, getkeyinfo) -- fixing a subset is not enough.
"""

import os
import shutil
import sqlite3
import tempfile

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from scitokens.utils.keycache import KeyCache


@pytest.fixture
def keycache():
    tmp_dir = tempfile.mkdtemp()
    old_xdg = os.environ.get("XDG_CACHE_HOME")
    os.environ["XDG_CACHE_HOME"] = tmp_dir
    kc = KeyCache()

    private_key = generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    yield kc, private_key.public_key()

    shutil.rmtree(tmp_dir, ignore_errors=True)
    if old_xdg is not None:
        os.environ["XDG_CACHE_HOME"] = old_xdg
    elif "XDG_CACHE_HOME" in os.environ:
        del os.environ["XDG_CACHE_HOME"]


def _count_rows(kc):
    conn = sqlite3.connect(kc.cache_location)
    curs = conn.cursor()
    curs.execute("SELECT COUNT(*) FROM keycache")
    count = curs.fetchone()[0]
    conn.close()
    return count


def test_injection_in_issuer_does_not_delete_other_rows(keycache):
    """
    With the old .format() pattern, an issuer like "x' OR '1'='1" in the
    DELETE that addkeyinfo runs before inserting would wipe every row.
    Parameterized queries must treat it as a literal value.
    """
    kc, pub = keycache
    kc.addkeyinfo("https://legit.example.com/", "key1", pub, cache_timer=3600)
    assert _count_rows(kc) == 1

    malicious_issuer = "x' OR '1'='1"
    kc.addkeyinfo(malicious_issuer, "evil_key", pub, cache_timer=3600)

    # The legitimate row must survive, plus the new literal-string row.
    assert _count_rows(kc) == 2


def test_injection_in_key_id_does_not_delete_other_rows(keycache):
    kc, pub = keycache
    kc.addkeyinfo("https://legit.example.com/", "key1", pub, cache_timer=3600)
    assert _count_rows(kc) == 1

    malicious_key_id = "x' OR '1'='1"
    kc.addkeyinfo("https://other.example.com/", malicious_key_id, pub, cache_timer=3600)

    assert _count_rows(kc) == 2


def test_delete_cache_entry_with_injection_string(keycache):
    kc, pub = keycache
    kc.addkeyinfo("https://legit.example.com/", "key1", pub, cache_timer=3600)
    assert _count_rows(kc) == 1

    kc._delete_cache_entry("x' OR '1'='1", "key1")
    assert _count_rows(kc) == 1


def test_union_select_injection_is_stored_literally(keycache):
    kc, pub = keycache
    malicious_issuer = "x' UNION SELECT * FROM keycache --"
    kc.addkeyinfo(malicious_issuer, "key1", pub, cache_timer=3600)
    assert _count_rows(kc) == 1

    conn = sqlite3.connect(kc.cache_location)
    curs = conn.cursor()
    curs.execute("SELECT issuer FROM keycache")
    row = curs.fetchone()
    conn.close()
    assert row[0] == malicious_issuer


def test_getkeyinfo_injection_issuer_no_leak(keycache):
    """
    getkeyinfo with an injection payload as the issuer must not return
    a row that actually belongs to a different, legitimate issuer.
    """
    kc, pub = keycache
    kc.addkeyinfo("https://legit.example.com/", "key1", pub, cache_timer=3600)

    malicious_issuer = "x' OR '1'='1"
    try:
        result = kc.getkeyinfo(malicious_issuer, "key1")
    except Exception:
        result = None
    assert result is None


def test_negative_cache_entry_with_injection_strings(keycache):
    kc, pub = keycache
    malicious_issuer = "x' OR '1'='1"
    malicious_key_id = "y' DROP TABLE keycache --"
    kc._add_negative_cache_entry(malicious_issuer, malicious_key_id, 300)
    assert _count_rows(kc) == 1

    conn = sqlite3.connect(kc.cache_location)
    curs = conn.cursor()
    curs.execute("SELECT issuer, key_id FROM keycache")
    row = curs.fetchone()
    conn.close()
    assert row[0] == malicious_issuer
    assert row[1] == malicious_key_id


def test_source_no_longer_uses_format_for_sql(keycache):
    """
    Belt-and-suspenders static check: the fix is expected to move away
    from building SQL text with str.format()/'%' interpolation of
    caller-controlled values. This does not by itself prove safety (the
    behavioral tests above do), but a reintroduction of
    '.format(' immediately before '.execute(' style patterns is a strong
    signal of regression.
    """
    import inspect

    import scitokens.utils.keycache as keycache_module

    source = inspect.getsource(keycache_module)
    assert "WHERE issuer = '{}'" not in source
    assert "WHERE issuer = '{issuer}'" not in source
