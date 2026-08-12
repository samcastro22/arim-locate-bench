#!/bin/bash
# Reference solution: apply the real upstream fix commit
# 142195888e713542189533a52cdfc333f05c3af6, restricted to git/cmd.py
# (the upstream commit also updates test files, which we don't need
# here since tests/test_outputs.py already covers the behavior).
#
# fix.patch is a local copy of that commit's patch (Harbor uploads this
# task's solution/ directory to /solution in the container before
# running this script -- no network access needed at solve time).
set -eu

cd /app
git apply --include=git/cmd.py /solution/fix.patch
