#!/bin/bash
# Reference solution: apply the real upstream fix commit
# 78ce704227c51f070c0c5fb4b466d92c62a7aa3d, restricted to scanner.py
# (the upstream commit also adds a new test fixture/test, which we
# don't need here since tests/test_outputs.py already covers it).
#
# fix.patch is a local copy of that commit's patch (Harbor uploads this
# task's solution/ directory to /solution in the container before
# running this script -- no network access needed at solve time).
set -eu

cd /app
git apply --include=src/picklescan/scanner.py /solution/fix.patch
