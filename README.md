# arim-locate-bench

A small benchmark that tests whether a frontier model can find and fix
a real security vulnerability, when it is only given the file the bug
is in. No CVE ID, no vulnerability type, no line number, no hint of
what is wrong: just the code.

Built on [Harbor](https://github.com/laude-institute/harbor).

## Why "locate"

[CVE-Bench](https://arxiv.org/abs/2503.17332) (Giovanni Gatti Pinheiro)
found that the "locate" condition (code only, no vulnerability
description) is where frontier models perform worst on real-world CVEs,
and is exactly where genuine security reasoning would need to show up.
This benchmark isolates that condition: every task hands the model a
file (or files) and says only "review this for security issues," then
scores whether the resulting patch actually closes a **real**, exploitable
vulnerability, using PoC logic adapted from the CVE's own advisory or fix
commit.

The benchmark measures this end to end. If a model never spots the real
problem, or spots it but ships a broken fix, both count the same way: a
failed test. It does not separately track whether a failure was a bad
diagnosis or a bad fix.

The four tasks are also chosen to probe a second, separately documented
difficulty: **multi-location** fixes (a correct fix touching more than one
call site) are harder for models than single-spot fixes. `scitokens_sqli`
has 5 vulnerable call sites in one file; the other three are more
localized, giving a spread rather than a single data point.

## Why real CVEs, not synthetic ones

Every task is a real, independently-disclosed vulnerability at the exact
commit before its real fix landed. That means the *validity* of the
vulnerability itself is never something this benchmark is evaluating;
only the model's locate-and-fix behavior, and (separately) whether this
benchmark's own Docker/scoring setup is correct. Ground truth for each
task is the vulnerability's real, official fix commit.

## The four tasks

| Task | CVE / Advisory | Repo | Vulnerability class |
|---|---|---|---|
| [`scitokens_sqli`](tasks/scitokens_sqli/) | CVE-2026-32714 | [scitokens](https://github.com/scitokens/scitokens) | SQL injection via `str.format()`, 5 locations in 1 file |
| [`parsl_sqli`](tasks/parsl_sqli/) | CVE-2026-21892 / GHSA-f2mf-q878-gh58 | [Parsl](https://github.com/Parsl/parsl) | SQL injection via `%` string formatting (matched pair with scitokens_sqli) |
| [`gitpython_cmdinjection`](tasks/gitpython_cmdinjection/) | CVE-2026-42215 / GHSA-rpm5-65cw-6hj4 | [GitPython](https://github.com/gitpython-developers/GitPython) | Command injection via a safety check that runs *before* the normalization step that would trigger it |
| [`picklescan_bypass`](tasks/picklescan_bypass/) | CVE-2025-1716 / GHSA-655q-fx9r-782v | [picklescan](https://github.com/mmaitre314/picklescan) | Deserialization-RCE detection bypass: a legitimate-looking call (`pip.main`) weaponized as a `__reduce__` payload |

Two of the four (`scitokens_sqli`, `parsl_sqli`) are the same
vulnerability *class* (SQL injection via unparameterized string
building) in two different codebases with two different exact code
patterns. That's deliberate: it tests whether a model's locate
performance is a consistent skill or a one-off success on a single
familiar pattern. The other two are different failure patterns entirely
(a logic/timing gap in an existing safety check, and recognizing a
deceptive-but-legitimate-looking call), so the four together cover
breadth across vulnerability classes as well as consistency within one.

## Task structure

Each task follows Harbor's task-directory format (`harbor task init`):

```
tasks/<name>/
├── task.toml          # Harbor task metadata/config
├── instruction.md      # locate-style prompt: no hints about the bug
├── environment/
│   └── Dockerfile       # clones the real repo pinned to the vulnerable commit
├── tests/
│   ├── test_outputs.py  # the actual scorer, see "Scoring" below
│   └── test.sh           # runs test_outputs.py, writes /logs/verifier/reward.txt
├── solution/
│   ├── solve.sh          # reference fix: applies the local patch below
│   └── fix.patch         # saved copy of the real upstream fix commit
├── ground_truth.json    # extra documentation: exact vulnerable locations + fix commit
└── README.md
```

`ground_truth.json` is not itself consumed by Harbor's scoring. It's
human/reviewer-facing documentation of exactly which lines are vulnerable
and what the real fix looks like, kept alongside each task for
transparency and for anyone extending this benchmark.

## Scoring

Every `tests/test_outputs.py` is a pytest file exercising the *actual*
vulnerable code path, adapted as directly as practical from the real
advisory/fix commit for that CVE:

- **scitokens_sqli** — near-verbatim reuse of the regression tests the
  scitokens maintainers shipped with their own fix commit (boolean- and
  UNION-injection payloads against the real `KeyCache` API).
- **parsl_sqli** — spins up the real Flask + SQLAlchemy monitoring app,
  seeds a SQLite DB with two workflows, and drives the actual HTTP routes
  with the boolean-blind-SQLi technique documented in the advisory.
- **gitpython_cmdinjection** — the advisory's own self-contained PoC
  (local bare repo + wrapper script proving execution via a marker file),
  almost unchanged.
- **picklescan_bypass** — the real `malicious16.pkl` payload bytes from
  the fix commit's own test fixture, reused byte-for-byte.

Every scorer was checked two ways: it must fail on the original,
unpatched code, and it must pass once the real upstream fix is applied.
This was confirmed both in isolated Python environments and for real,
inside Harbor and Docker, using `harbor run --agent oracle`. Confirmed
results: all four tasks score `Mean: 1.000` with the real fix applied,
and `Mean: 0.000` with nothing changed (`harbor run -p
tasks/scitokens_sqli --agent nop`). So the scoring genuinely
discriminates; it does not just pass by default.

Each task's reference fix comes from a local file, `solution/fix.patch`,
a saved copy of the real upstream fix commit. It is not downloaded from
GitHub while the task runs. The first version of `solve.sh` tried to
`curl` the patch from GitHub inside the container, but `curl` was not
installed there, so it silently failed. This was caught on
`scitokens_sqli` and fixed the same way across all four tasks: save the
patch as a local file, apply it locally instead. Harbor copies each
task's `solution/` folder into the container automatically before
running `solve.sh`, so `fix.patch` is already there when it is needed.

### Network policy during the agent phase

Every task sets `network_mode = "no-network"` on `[agent]` (and
`[verifier]`) in `task.toml`, while `[environment]` stays `"public"`.
This matters specifically for the "locate" claim: without it, a model
could route around actually reviewing the code by just searching the web
for the real CVE advisory and copying its fix, which would defeat the
whole point of the locate condition (code only, no description). The
`[environment]` baseline stays public because that governs the Docker
build step (cloning each repo at its pinned commit), which happens
before the agent phase and is unaffected by the agent/verifier
overrides. Re-verified with `harbor run --agent oracle` after tightening
this: all four tasks still score `Mean: 1.000` with the agent sandboxed
off the network, confirming neither `solve.sh` nor `tests/test.sh`
secretly depended on live network access.

One consequence worth knowing before running a real agent: because of
this policy, a plain `harbor run -a <agent> -m <model>` will fail with a
network error. You need to explicitly allow the one host your chosen
agent/provider actually needs, and pass its API key through. See
"Running" below for a real, verified example.

## Running

```bash
pip install -r requirements.txt
```

Sanity-check a task's Docker/scoring setup without any agent or API key,
by applying the reference fix and confirming it scores 1 (all four do,
confirmed):

```bash
harbor run -p tasks/scitokens_sqli --agent oracle
harbor run -p tasks/parsl_sqli --agent oracle
harbor run -p tasks/gitpython_cmdinjection --agent oracle
harbor run -p tasks/picklescan_bypass --agent oracle
```

To run a real model, you need an API key for that model's provider, and
you must explicitly allow the container to reach that provider's host
(see "Network policy" above). This exact command was run and verified
against `scitokens_sqli` with `gpt-4o-mini`:

```bash
export OPENAI_API_KEY=your_key_here

harbor run -p tasks/scitokens_sqli --agent aider --model openai/gpt-4o-mini --ae OPENAI_API_KEY=${OPENAI_API_KEY} --allow-agent-host api.openai.com
```

Swap `-p tasks/<name>` for any of the other three tasks to run them the
same way. Different agents and providers need different hosts and env
vars; check the agent's own documentation for which ones it expects.

Harbor writes job output under `jobs/` by default (`--jobs-dir`, or `-o`
to choose a different folder, as used above during development).

## Known limitations

This is a same-day prototype, not a production benchmark:

- **The agent is told which file(s) are vulnerable, not what's wrong
  within them.** This is a deliberate, narrower scope than searching an
  entire, unfamiliar repository for the bug. The task is "find the issue
  in this known file," not "find which file among many is the problem."
- **A failed run does not say why it failed.** A wrong diagnosis and a
  correct diagnosis paired with a broken fix both just register as a
  failed test; there's no breakdown of which part went wrong.
- **4 tasks, one machine-checked run per task type.** A real benchmark
  scales this pattern to dozens of CVEs per class for statistical power;
  this prototype demonstrates the pattern is soundly buildable, not that
  it's been run at scale.
- **Malformed/unusual model output handling is basic.** If an agent
  doesn't edit the named file at all, refuses, or edits something
  unrelated, the scorer will simply fail the task (reward 0) rather than
  giving a more diagnostic signal about why. A production version would
  want richer failure categorization (for example "didn't touch the
  file" versus "touched it but still vulnerable" versus "broke unrelated
  functionality").
- **Some scorers closely adapt the upstream project's own regression
  tests**, most directly `scitokens_sqli`, whose test file reuses the
  maintainers' own fix-commit tests near-verbatim, rather than being
  independently authored from scratch.
- **`parsl_sqli`'s scorer stubs out plotting** (no `graphviz`/`dot`
  dependency wired into the Docker image) so it can assert on the SQL
  layer directly without pulling in a heavier native dependency chain;
  the query-construction and execution path being scored is the real,
  unstubbed code.
- **No cross-task aggregate scoring/leaderboard tooling** beyond what
  Harbor itself provides; each task can be run and scored independently.
- All four vulnerable/fixed commit pairs were fetched live from GitHub
  during development (see each task's `ground_truth.json` for exact
  SHAs); this benchmark does not vendor a frozen mirror of any of the
  four upstream repos, so it depends on those commits remaining
  available at their current SHAs.
