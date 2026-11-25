import json

import pytest

from hmt_devsecops import cli, deployment
from hmt_devsecops.policy import Denied, parse_config


def test_render_effect_and_existing_output(config, tmp_path, monkeypatch, capsys):
    output = tmp_path / "compose.yaml"
    argv = ["hmt-devsecops-deploy", "render", "--policy", str(config.source), "--output", str(output)]
    monkeypatch.setattr("sys.argv", argv)
    assert deployment.main() == 0
    document = json.loads(output.read_text())
    assert document["services"]["devsecops"]["labels"]["org.hmt.policy.sha256"] == config.sha256
    assert config.sha256 in capsys.readouterr().out
    previous = output.read_bytes()
    with pytest.raises(SystemExit) as error:
        deployment.main()
    assert error.value.code == 2 and output.read_bytes() == previous


def test_serve_binds_expected_policy(config, monkeypatch):
    launches = []
    monkeypatch.setattr("uvicorn.run", lambda app, **options: launches.append(options))
    monkeypatch.setattr("sys.argv", [
        "hmt-devsecops-deploy", "serve", "--policy", str(config.source), "--expect-sha256", config.sha256,
    ])
    assert deployment.main() == 0
    assert launches == [{"host": "0.0.0.0", "port": 8080, "workers": 1}]


def test_deployment_rejects_host_only_path(config):
    raw = config.source.read_text()
    config.source.write_text(raw.replace('workspace = "workspace"', f'workspace = "{config.workspace}"'))
    with pytest.raises(Denied, match="COMPOSE_PATH_MUST_BE_RELATIVE"):
        deployment.compose_document(parse_config(config.source), config.source.parent)


def test_cli_proposal_reads_approval_file(make_policy):
    config = make_policy(approval=True)
    token_file = config.resolve_ref(config.policy.approval_file)
    args = ["create", "--policy", str(config.source), "--path", "candidate.json"]
    assert cli.main(args) == 2
    assert cli.main([*args, "--approval-file", str(token_file)]) == 0
    assert (config.workspace / "candidate.json").is_file()


def test_invalid_credential_mode_fails(config):
    token_file = config.resolve_ref(config.policy.http.api_token_file)
    token_file.chmod(0o644)
    with pytest.raises(Denied, match="CREDENTIAL_PERMISSIONS_INVALID"):
        deployment.compose_document(config, config.source.parent)
