import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from hmt_devsecops.contracts import ToolRequest
from hmt_devsecops.operations import execute, run_bounded
from hmt_devsecops.policy import Denied, parse_config, scoped_path, authorize

@pytest.mark.parametrize("tool", ["inventory","evidence","terraform_plan","ansible_check","k3s_status","tailscale_status"])
def test_readonly_tool(tool, config):
    value=execute(ToolRequest(tool=tool), config)
    assert value.disposition in {"PASS","HOLD"}

def test_missing_grant(make_policy):
    config = make_policy(allowed=())
    assert execute(ToolRequest(tool="inventory"), config).reason == "GRANT_ABSENT"

def test_read_and_hash(config, tmp_path):
    (config.workspace / "hello.txt").write_text("hello")
    assert execute(ToolRequest(tool="read",args={"path":"hello.txt"}),config).payload["text"]=="hello"
    assert execute(ToolRequest(tool="verify",args={"path":"hello.txt"}),config).payload["sha256"]==hashlib.sha256(b"hello").hexdigest()

def test_path_escape(config):
    assert execute(ToolRequest(tool="read",args={"path":"../secret"}),config).reason=="PATH_OUTSIDE_WORKSPACE"

def test_invalid_file(config, tmp_path):
    assert execute(ToolRequest(tool="read",args={"path":"missing"}),config).disposition=="DENIED"
    (config.workspace/"huge").write_text("x"*16385)
    assert execute(ToolRequest(tool="read",args={"path":"huge"}),config).disposition=="DENIED"
    assert execute(ToolRequest(tool="verify",args={"path":"missing"}),config).disposition=="DENIED"

def test_proposal_denied(config):
    assert execute(ToolRequest(tool="create",args={"path":"proposal.json"}),config).reason=="EXPLICIT_APPROVAL_REQUIRED"

def test_proposal_approval(make_policy):
    config = make_policy(approval=True)
    q = ToolRequest(tool="create", args={"path":"proposal.json","approval":"approval-token","content":"safe"})
    result = execute(q, config)
    assert result.reason == "PROPOSAL_ONLY_NO_APPLY"
    assert execute(q, config).reason == "EXISTING_TARGET_IMMUTABLE"
    artifact = (config.workspace / "proposal.json").read_bytes()
    record = json.loads(artifact)
    assert record["kind"] == "change_proposal" and record["policy_sha256"] == config.sha256
    assert result.payload["sha256"] == hashlib.sha256(artifact).hexdigest()
    assert b"approval-token" not in artifact


def test_proposal_invalid(make_policy):
    config = make_policy(approval=True)
    for name in ["bad.txt", "../escape.json", "nope/new.json"]:
        assert execute(ToolRequest(tool="update", args={"path":name, "approval":"approval-token"}), config).disposition == "DENIED"


def test_config_validation(config):
    p = config.source
    raw = p.read_text()
    assert parse_config(p).sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    for invalid in (
        'workspace = "duplicate"\n' + raw,
        raw.replace("generation = 2", "generation = true"),
        raw.replace('"create"', '"oops"'),
        raw.replace('principal = "test"', 'principal = ""'),
        raw.replace('workspace = "workspace"', 'workspace = "absent"'),
        "x" * 32769,
        '{"workspace": "/"}',
    ):
        p.write_text(invalid)
        with pytest.raises(Denied):
            parse_config(p)


def test_config_symlink(tmp_path):
    p=tmp_path/"cfg.json";p.write_text("{}")
    (tmp_path/"alias").symlink_to(p)
    with pytest.raises(Denied): parse_config(tmp_path/"alias")

def test_config_permissions(tmp_path):
    p=tmp_path/"cfg.json";p.write_text("{}");p.chmod(0o666)
    with pytest.raises(Denied): parse_config(p)

def test_scope(tmp_path):
    assert scoped_path(tmp_path,".")==tmp_path
    with pytest.raises(Denied): scoped_path(tmp_path,"../x")

def test_external_missing(config, monkeypatch):
    monkeypatch.setenv("PATH", str(config.workspace))
    assert run_bounded("terraform_plan", config).reason == "EXECUTABLE_MISSING:terraform"


@pytest.mark.parametrize("returncode, outcome", [(0, "PASS"), (2, "HOLD")])
def test_external_completed(make_policy, returncode, outcome):
    from subprocess import CompletedProcess
    config = make_policy(executables={"ansible_check": sys.executable})
    with patch("hmt_devsecops.operations.subprocess.run", return_value=CompletedProcess([], returncode, "ok", "")) as runner:
        assert run_bounded("ansible_check", config).disposition == outcome
        assert runner.call_args.args[0] == (Path(sys.executable).resolve(), "--syntax-check", "site.yaml")
        assert runner.call_args.kwargs["cwd"] == config.workspace


def test_external_timeout(make_policy):
    import subprocess
    config = make_policy(executables={"terraform_plan": sys.executable})
    with patch("hmt_devsecops.operations.subprocess.run", side_effect=subprocess.TimeoutExpired("x", 1)):
        assert run_bounded("terraform_plan", config).reason == "COMMAND_TIMEOUT"


def test_report_escape(make_policy):
    result = execute(ToolRequest(tool="evidence"), make_policy(principal="<script>"))
    assert "<script>" not in result.payload["html"]


def test_cross_scope_hardlink_denied(config):
    import os
    os.link(config.source, config.workspace / "alias")
    assert execute(ToolRequest(tool="read", args={"path":"alias"}), config).disposition == "DENIED"


def test_invalid_args():
    from pydantic import ValidationError
    with pytest.raises(ValidationError): ToolRequest(tool="shell")
    with pytest.raises(ValidationError): ToolRequest(tool="read",request_id="*")
