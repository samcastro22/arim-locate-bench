"""
Scoring test for the GitPython command-injection task
(CVE-2026-42215 / GHSA-rpm5-65cw-6hj4).

Adapted directly from the advisory's own self-contained PoC: a local bare
repo stands in for "the remote", and a wrapper script proves it ran by
creating a marker file. No network egress required. The hyphenated form
(`{"upload-pack": ...}`) must stay blocked (control case); the underscore
form (`upload_pack=...`), which upstream's transform_kwarg() silently
turns into `--upload-pack`, must ALSO be blocked once the fix is applied.
"""

import os
import stat
import subprocess
import tempfile

import pytest
from git import Repo
from git.exc import UnsafeOptionError


@pytest.fixture
def poc_env():
    base = tempfile.mkdtemp(prefix="gp-poc-")
    origin = os.path.join(base, "origin.git")
    producer = os.path.join(base, "producer")
    victim = os.path.join(base, "victim")
    proof = os.path.join(base, "proof.txt")
    wrapper = os.path.join(base, "wrapper.sh")

    with open(wrapper, "w") as f:
        f.write(
            "#!/bin/sh\n"
            f"touch '{proof}'\n"
            "exit 1\n"
        )
    os.chmod(wrapper, stat.S_IRWXU)

    subprocess.run(["git", "init", "--quiet", "--bare", origin], check=True)
    subprocess.run(["git", "clone", "--quiet", origin, producer], check=True)
    with open(os.path.join(producer, "README"), "w") as f:
        f.write("x")
    subprocess.run(["git", "-C", producer, "add", "README"], check=True)
    subprocess.run(
        ["git", "-C", producer, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "init", "--quiet"],
        check=True,
    )
    subprocess.run(["git", "-C", producer, "push", "--quiet", "origin", "HEAD"], check=True)
    subprocess.run(["git", "clone", "--quiet", origin, victim], check=True)

    yield {"origin": origin, "victim": victim, "wrapper": wrapper, "proof": proof}


def test_hyphenated_upload_pack_still_blocked(poc_env):
    """Control case: the literal option name must remain blocked."""
    repo = Repo(poc_env["victim"])
    remote = repo.remote("origin")
    with pytest.raises(UnsafeOptionError):
        remote.fetch(**{"upload-pack": poc_env["wrapper"]})
    assert not os.path.exists(poc_env["proof"])


def test_underscore_upload_pack_fetch_is_blocked(poc_env):
    """
    The real vulnerability: fetch(upload_pack=...) must be rejected too,
    since GitPython dashifies it into --upload-pack before invoking git.
    """
    repo = Repo(poc_env["victim"])
    remote = repo.remote("origin")

    raised = False
    try:
        remote.fetch(upload_pack=poc_env["wrapper"])
    except UnsafeOptionError:
        raised = True
    except Exception:
        # Some other git-level failure is fine as long as the helper
        # never executed -- what matters is the proof file below.
        pass

    assert not os.path.exists(poc_env["proof"]), (
        "wrapper.sh executed: fetch(upload_pack=...) reached git as "
        "--upload-pack, i.e. the vulnerability is still present"
    )
    assert raised, "expected UnsafeOptionError for the underscore-spelled kwarg"


def test_underscore_upload_pack_clone_from_is_blocked():
    base = tempfile.mkdtemp(prefix="gp-poc-clone-")
    origin = os.path.join(base, "origin.git")
    out = os.path.join(base, "out")
    proof = os.path.join(base, "proof.txt")
    wrapper = os.path.join(base, "wrapper.sh")

    with open(wrapper, "w") as f:
        f.write("#!/bin/sh\n" f"touch '{proof}'\n" "exit 1\n")
    os.chmod(wrapper, stat.S_IRWXU)

    subprocess.run(["git", "init", "--quiet", "--bare", origin], check=True)

    raised = False
    try:
        Repo.clone_from(origin, out, upload_pack=wrapper)
    except UnsafeOptionError:
        raised = True
    except Exception:
        pass

    assert not os.path.exists(proof), (
        "wrapper.sh executed via Repo.clone_from(upload_pack=...) -- "
        "command injection still reachable"
    )
    assert raised, "expected UnsafeOptionError for clone_from(upload_pack=...)"


def test_allow_unsafe_options_still_works(poc_env):
    """The documented opt-out must keep working after the fix."""
    repo = Repo(poc_env["victim"])
    remote = repo.remote("origin")
    try:
        remote.fetch(upload_pack=poc_env["wrapper"], allow_unsafe_options=True)
    except UnsafeOptionError:
        pytest.fail("allow_unsafe_options=True must not raise UnsafeOptionError")
    except Exception:
        # git itself may still fail/exit non-zero after running the helper;
        # that's expected and fine.
        pass
    assert os.path.exists(poc_env["proof"]), "allow_unsafe_options=True should still let the option through"
