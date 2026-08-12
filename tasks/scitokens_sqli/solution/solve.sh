#!/bin/bash
# Reference solution: apply the real upstream fix commit
# 3dba108853f2f4a6c0f2325c03779bf083c41cf2, restricted to the
# keycache.py hunk (the upstream commit also adds new tests, which we
# don't need here since tests/test_outputs.py already covers it).
#
# fix.patch is a local copy of that commit's patch (Harbor uploads this
# task's solution/ directory to /solution in the container before
# running this script -- no network access needed at solve time).
set -eu

cd /app
git apply --include=src/scitokens/utils/keycache.py /solution/fix.patch
