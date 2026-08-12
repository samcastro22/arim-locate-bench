#!/bin/bash
# Reference solution: apply the real upstream fix commit
# 013a928461e70f38a33258bd525a351ed828e974, restricted to views.py
# (the upstream commit is already scoped to just that one file).
#
# fix.patch is a local copy of that commit's patch (Harbor uploads this
# task's solution/ directory to /solution in the container before
# running this script -- no network access needed at solve time).
set -eu

cd /app
git apply --include=parsl/monitoring/visualization/views.py /solution/fix.patch
