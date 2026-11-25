#!/bin/sh
set -eu

revision=$(git rev-parse HEAD)
test "$revision" = "$GITHUB_SHA"
python -m venv "$RUNNER_TEMP/hmt-ci"
"$RUNNER_TEMP/hmt-ci/bin/python" -m pip install 'uv==0.10.0'
uv="$RUNNER_TEMP/hmt-ci/bin/uv"
"$uv" sync --locked --python "$(command -v python)"
mkdir ci-proof
.venv/bin/python -m pytest --cov=hmt_devsecops --cov-branch \
  --cov-report=term-missing --cov-report=json:ci-proof/coverage.json --junitxml=ci-proof/tests.xml
.venv/bin/python tools/qualify_policy.py --output ci-proof/witness --revision "$revision"
"$uv" build --wheel --out-dir ci-proof/dist
