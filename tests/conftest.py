import json
from pathlib import Path

import pytest

from hmt_devsecops.policy import parse_config

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/hmt_policy.toml"
GRANTS = ("create", "read", "update", "verify", "evidence", "inventory",
          "terraform_plan", "ansible_check", "k3s_status", "tailscale_status")


@pytest.fixture
def make_policy(tmp_path):
    def make(*, allowed=GRANTS, principal="test", capacity=4, approval=False, executables=None, suffix="policy"):
        root = tmp_path / suffix
        workspace, secrets = root / "workspace", root / "secrets"
        workspace.mkdir(parents=True)
        secrets.mkdir()
        credentials = {"api_token": "api-token", "metrics_token": "metrics-token", "approval": "approval-token"}
        for name, text in credentials.items():
            path = secrets / name
            path.write_text(text, encoding="ascii")
            path.chmod(0o600)
        lines = ["version = 1", 'workspace = "workspace"', f"principal = {json.dumps(principal)}",
                 f"allowed = {json.dumps(allowed)}", "generation = 2"]
        if approval:
            lines.append('approval_file = "secrets/approval"')
        lines += ["[http]", f"max_inflight = {capacity}", 'api_token_file = "secrets/api_token"',
                  'metrics_token_file = "secrets/metrics_token"', "[executables]"]
        for tool, executable in (executables or {}).items():
            lines.append(f"{tool} = {json.dumps(executable)}")
        lines += ["[deployment]" + EXAMPLE.read_text(encoding="utf-8").split("[deployment]", 1)[1]]
        policy = root / "hmt_policy.toml"
        policy.write_text("\n".join(lines), encoding="utf-8")
        policy.chmod(0o600)
        return parse_config(policy)
    return make


@pytest.fixture
def config(make_policy):
    return make_policy()
