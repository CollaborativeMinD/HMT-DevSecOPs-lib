import json
import os
import subprocess
import sys
from fastapi.testclient import TestClient
from hmt_devsecops.stdio import respond, TOOLS
from hmt_devsecops.http import create_app


def test_discovery(config):
    r=respond({"id":1,"method":"tools/list"},config)
    assert len(r["result"]["tools"])==10
    assert set(t["name"] for t in r["result"]["tools"])==set(TOOLS)

def test_initialize(config):
    assert respond({"id":1,"method":"initialize"},config)["result"]["serverInfo"]["name"]=="hmt-devsecops-tools"

def test_unknown_method(config):
    assert respond({"id":1,"method":"bad"},config)["error"]["code"]==-32601

def test_unknown_tool(config):
    assert respond({"id":1,"method":"tools/call","params":{"name":"shell"}},config)["error"]["code"]==-32601

def test_tool_request(config):
    r=respond({"id":1,"method":"tools/call","params":{"name":"inventory","arguments":{}}},config)
    assert 'PASS' in r["result"]["content"][0]["text"]

def test_invalid_tool_request(config):
    r=respond({"id":1,"method":"tools/call","params":{"name":"inventory","arguments":{"args":[]}}},config)
    assert r["error"]["code"]==-32602

def test_http_health(config):
    with TestClient(create_app(config.source)) as client:
        assert client.get('/health/live').status_code == 200
        assert client.get('/health/ready').json() == {"status": "READY", "policy_sha256": config.sha256}
        assert client.post('/tools/call', json={"tool":"inventory"}).status_code == 401
        headers = {"Authorization":"Bearer api-token"}
        response = client.post('/tools/call', json={"tool":"inventory"}, headers=headers)
        assert response.status_code == 200 and response.json()["payload"]["policy_sha256"] == config.sha256
        assert client.post('/tools/call', json={"tool":"create"}, headers=headers).status_code == 403
        assert client.post('/tools/call', content=b'bad', headers=headers).status_code == 400
        assert client.post('/tools/call', content=b'x'*8193, headers=headers).status_code == 413


def test_http_policy_controls_actual_request_limit(config):
    with config.source.open('a', encoding='utf8') as stream:
        stream.write('\n[http.budget]\nrequest_bytes = 64\nretry_after_seconds = 3\n')
    with TestClient(create_app(config.source)) as client:
        assert client.get('/health/ready').status_code == 200
        assert client.post('/tools/call', content=b'x' * 65).status_code == 413


def test_http_not_ready(monkeypatch):
    monkeypatch.delenv("HMT_DEVSECOPS_CONFIG", raising=False)
    with TestClient(create_app()) as client:
        assert client.get('/health/ready').status_code == 503


def test_real_stdio(config,tmp_path):
    path=config.source
    env={**os.environ,'HMT_DEVSECOPS_CONFIG':str(path)}
    payload='\n'.join(json.dumps(v) for v in [{"jsonrpc":"2.0","id":1,"method":"initialize"},{"jsonrpc":"2.0","id":2,"method":"tools/list"},{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inventory"}}])+'\n'
    p=subprocess.run([sys.executable,'-m','hmt_devsecops.stdio'],input=payload,text=True,capture_output=True,env=env,timeout=7)
    assert p.returncode==0,p.stderr
    lines=[json.loads(x) for x in p.stdout.splitlines()]
    assert len(lines)==3
    assert len(lines[1]['result']['tools'])==10

def test_metrics_authenticated(config):
    with TestClient(create_app(config.source)) as client:
        assert client.get('/metrics').status_code == 401
        assert client.post('/tools/call', json={'tool':'inventory'}, headers={'Authorization':'Bearer api-token'}).status_code == 200
        metrics = client.get('/metrics', headers={'Authorization':'Bearer metrics-token'})
        assert metrics.status_code == 200
        assert b'hmt_devsecops_tool_calls_total' in metrics.content
        assert b'hmt_devsecops_tool_latency_seconds_bucket' in metrics.content


def test_http_length_malformed(config):
    with TestClient(create_app(config.source)) as client:
        response = client.post('/tools/call', content=b'{}', headers={'Authorization':'Bearer api-token','content-length':'oops'})
        assert response.status_code == 400


def test_chunked_body_is_bounded(config):
    def chunks():
        yield b'x' * 8192
        yield b'x'
    with TestClient(create_app(config.source)) as client:
        response = client.post('/tools/call', content=chunks(), headers={'Authorization':'Bearer api-token'})
        assert response.status_code == 413


def test_rendered_digest_blocks_stale_policy(config):
    with TestClient(create_app(config.source, '0' * 64)) as client:
        assert client.get('/health/ready').status_code == 503
        assert client.post('/tools/call', json={'tool':'inventory'}, headers={'Authorization':'Bearer api-token'}).status_code == 503
