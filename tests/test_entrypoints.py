from __future__ import annotations
import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from hmt_devsecops import cli, stdio
from hmt_devsecops.policy import parse_config, Denied, scoped_path

class FakeStdin:
    def __init__(self, payload: bytes):
        self.buffer=io.BytesIO(payload)

def test_stdio_missing_config(monkeypatch):
    monkeypatch.delenv('HMT_DEVSECOPS_CONFIG',raising=False)
    assert stdio.main([])==2

def test_stdio_mixed_lines(tmp_path,config,monkeypatch,capsys):
    f=config.source
    monkeypatch.setenv('HMT_DEVSECOPS_CONFIG',str(f))
    messages=[b'not-json\n', b'[]\n', b'{"method":"notifications/initialized"}\n',b'{"id":1,"method":"tools/list"}\n', b'x'*65537+b'\n']
    monkeypatch.setattr(sys,'stdin',FakeStdin(b''.join(messages)))
    assert stdio.main([])==0
    result=[json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert len(result)==2
    assert result[0]['error']['code']==-32700
    assert len(result[1]['result']['tools'])==10

def test_stdio_eof(tmp_path,config,monkeypatch):
    f=config.source
    monkeypatch.setenv('HMT_DEVSECOPS_CONFIG',str(f))
    monkeypatch.setattr(sys,'stdin',FakeStdin(b''))
    assert stdio.main([])==0

def test_cli_inventory(tmp_path,config,monkeypatch,capsys):
    p=config.source
    monkeypatch.setenv('HMT_DEVSECOPS_CONFIG',str(p))
    monkeypatch.setattr(sys,'argv',['hmt-devsecops','inventory'])
    assert cli.main()==0
    assert 'INVENTORY_BOUNDED' in capsys.readouterr().out

def test_cli_denied(tmp_path,config,monkeypatch,capsys):
    p=config.source
    monkeypatch.setenv('HMT_DEVSECOPS_CONFIG',str(p))
    monkeypatch.setattr(sys,'argv',['hmt-devsecops','create','--path','test.json'])
    assert cli.main()==2
    assert 'EXPLICIT_APPROVAL_REQUIRED' in capsys.readouterr().out

def test_cli_direct_runner(tmp_path,config,monkeypatch,capsys):
    p=config.source
    monkeypatch.setenv('HMT_DEVSECOPS_CONFIG',str(p))
    monkeypatch.setattr(sys,'argv',['hmt-devsecops','evidence'])
    assert cli.main()==0

def test_scoped_symlink_resolves_out(tmp_path):
    (tmp_path/'link').symlink_to('/etc')
    with pytest.raises(Denied):scoped_path(tmp_path,'link/passwd')

@pytest.mark.parametrize("line", ("extra = 1", 'allowed = "read"', 'allowed = [42]', "generation = -1",
                                                   'generation = "1"', "principal = false"))
def test_policy_strict_schema(config, line):
    key = line.split(" = ", 1)[0]
    raw = config.source.read_text()
    kept = [entry for entry in raw.splitlines() if not entry.startswith(key + " = ")]
    config.source.write_text(line + "\n" + "\n".join(kept))
    with pytest.raises(Denied, match="POLICY_SCHEMA_INVALID"):
        parse_config(config.source)


def test_policy_file_is_directory(tmp_path):
    with pytest.raises(Denied):parse_config(tmp_path)

def test_ops_unicode_read_error(tmp_path,config):
    from hmt_devsecops.operations import execute
    from hmt_devsecops.contracts import ToolRequest
    (config.workspace/'binary.txt').write_bytes(b'\xff\xfe')
    assert execute(ToolRequest(tool='read',args={'path':'binary.txt'}),config).disposition=='DENIED'
