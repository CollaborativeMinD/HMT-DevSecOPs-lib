import json
import tomllib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_skill_count_and_contract():
    files=list((ROOT/'skills').glob('*/SKILL.md'))
    assert len(files)==10
    for f in files:
        text=f.read_text()
        assert 'Expected output:' in text and 'AGENTS.md' in text and 'Runbook.md' in text

def test_client_configs():
    for path in (ROOT/'integrations').glob('*.json'):
        data=json.loads(path.read_text())
        assert 'hmt-devsecops' in (data.get('mcpServers') or data.get('servers'))
    assert 'hmt-devsecops-mcp' in (ROOT/'integrations/codex.config.toml').read_text()

def test_licenses_and_runbooks():
    assert (ROOT/'LICENSE').is_file()
    assert (ROOT/'Runbook.md').is_file()
    assert (ROOT/'AGENTS.md').is_file()

def test_terraform_no_apply():
    assert 'required_version' in (ROOT/'ops/terraform/main.tf').read_text()
    assert 'host_key_checking = True' in (ROOT/'ops/ansible/ansible.cfg').read_text()
