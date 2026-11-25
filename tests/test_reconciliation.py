"""RRCA regression for the three acknowledged DevSecOps seams."""
from __future__ import annotations
import concurrent.futures
import json
import threading
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import hmt_devsecops.http as api
from hmt_devsecops.deployment import compose_document
from hmt_devsecops.policy import Denied, parse_config

ROOT = Path(__file__).resolve().parents[1]


def test_views_differ_with_identical_canonical_source():
    req = (ROOT / 'HMT_DevSecOps_Requirements_v1.0.0.html').read_text()
    close = (ROOT / 'HMT_DevSecOps_Closeout_v1.0.0.html').read_text()
    assert req != close
    assert 'Adversarial change-impact query' in req
    assert 'Gate and evidence register' in close
    assert 'Adversarial change-impact query' not in close
    assert 'Gate and evidence register' not in req
    import re
    pattern = r'<script id="canonical-graph" type="application/json">(.*?)</script>'
    graph = json.loads((ROOT / 'architecture/graph.json').read_text())
    assert json.loads(re.search(pattern, req, re.S).group(1)) == graph
    assert json.loads(re.search(pattern, close, re.S).group(1)) == graph


def test_credentials_wired_and_private(config):
    document = compose_document(config, ROOT)
    app, prom = (document["services"][name] for name in ("devsecops", "prometheus"))
    assert "environment" not in app and "environment" not in prom
    assert app["labels"]["org.hmt.policy.sha256"] == config.sha256
    assert app["command"][-2:] == ["--expect-sha256", config.sha256]
    assert app["build"]["args"]["PYTHON_IMAGE"] == config.policy.deployment.python_image
    app_token = next(m for m in app["volumes"] if m["target"].endswith("/metrics_token"))
    scrape_token = next(m for m in prom["volumes"] if isinstance(m, dict) and m["target"] == "/run/secrets/hmt_metrics_token")
    assert app_token["source"] == scrape_token["source"]
    assert app_token["read_only"] and scrape_token["read_only"]
    assert "metrics-token" not in json.dumps(document)
    assert "credentials_file: /run/secrets/hmt_metrics_token" in (ROOT / 'monitoring/prometheus.yml').read_text()


def test_concurrency_denial_has_no_execution(make_policy, monkeypatch):
    config = make_policy(capacity=1)
    monkeypatch.setenv('HMT_HTTP_MAX_INFLIGHT', '64')
    gate, entered = threading.Event(), threading.Event()
    calls = []
    def blocking_execute(*args):
        calls.append('entered')
        entered.set()
        assert gate.wait(4)
        from hmt_devsecops.contracts import ToolResult
        return ToolResult(disposition='PASS', reason='OK')
    monkeypatch.setattr(api, 'execute', blocking_execute)
    with TestClient(api.create_app(config.source)) as client:
        def invoke():
            return client.post('/tools/call', json={'tool': 'inventory'}, headers={'Authorization': 'Bearer api-token'})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            try:
                first = pool.submit(invoke)
                assert entered.wait(3)
                excess = invoke()
                assert excess.status_code == 429
                assert excess.json()['detail'] == 'HTTP_CAPACITY_EXCEEDED'
                assert excess.headers['retry-after'] == '1'
                assert len(calls) == 1
            finally:
                gate.set()
            assert first.result(timeout=4).status_code == 200
            assert invoke().status_code == 200
            assert len(calls) == 2


def test_metrics_separate_token(config, monkeypatch):
    monkeypatch.setenv('HMT_API_TOKEN', 'ambient-token')
    monkeypatch.setenv('HMT_METRICS_TOKEN', 'ambient-metrics')
    with TestClient(api.create_app(config.source)) as client:
        assert client.get('/metrics', headers={'Authorization': 'Bearer api-token'}).status_code == 401
        assert client.get('/metrics', headers={'Authorization': 'Bearer ambient-metrics'}).status_code == 401
        assert client.get('/metrics', headers={'Authorization': 'Bearer metrics-token'}).status_code == 200
        for token in ('metrics-token', 'ambient-token'):
            assert client.post('/tools/call', json={'tool': 'inventory'}, headers={'Authorization': 'Bearer ' + token}).status_code == 401


@pytest.mark.parametrize("value", ("0", "65", "-1", "inf", "1.0", "true", '""'))
def test_limit_rejects_invalid_values(config, value):
    raw = config.source.read_text()
    config.source.write_text(raw.replace("max_inflight = 4", "max_inflight = " + value))
    with pytest.raises(Denied, match="POLICY_SCHEMA_INVALID"):
        parse_config(config.source)


def test_conflicting_credentials_fail_closed(config):
    config.resolve_ref(config.policy.http.metrics_token_file).write_text("api-token")
    with TestClient(api.create_app(config.source)) as client:
        assert client.get('/health/ready').status_code == 503


def test_credentials_within_workspace_are_rejected(config):
    raw = config.source.read_text()
    config.source.write_text(raw.replace("secrets/api_token", "workspace/api_token"))
    with pytest.raises(Denied, match="AUTHORITY_FILES_INSIDE_WORKSPACE"):
        parse_config(config.source)
