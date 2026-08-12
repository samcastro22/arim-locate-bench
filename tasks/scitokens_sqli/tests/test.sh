#!/bin/bash
# Runs the real regression-style SQL injection tests against whatever the
# agent left in /app. Uses the interpreter already set up in the
# environment image (scitokens installed with `pip install -e .`) so the
# agent's in-place edits to keycache.py are picked up directly.
set -u

mkdir -p /logs/verifier

python3 -m pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
status=$?

if [ $status -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi

exit 0
