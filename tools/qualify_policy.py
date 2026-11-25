"""Exercise policy admission and the existing tools in disposable real processes."""

import argparse
import hashlib
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def output(module: str, *args: str, env: dict, request: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", module, *args], env=env, text=True, capture_output=True, timeout=15,
        input=json.dumps(request) + "\n" if request is not None else None,
    )


def request_http(base: str, route: str, token: str | None = None, body: dict | None = None) -> tuple[int, bytes]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(base + route, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def witness(output_dir: Path, revision: str) -> None:
    with TemporaryDirectory(prefix="hmt-policy-proof-") as temp:
        root = Path(temp)
        workspace, secret_dir = root / "workspace", root / "secrets"
        workspace.mkdir()
        secret_dir.mkdir(mode=0o700)
        credentials = {name: secrets.token_urlsafe(32) for name in ("api_token", "metrics_token", "approval")}
        for name, value in credentials.items():
            path = secret_dir / name
            path.write_text(value, encoding="ascii")
            path.chmod(0o600)
        sample = (ROOT / "examples/hmt_policy.toml").read_text(encoding="utf-8")
        raw = sample.replace('allowed = ["read"', 'allowed = ["create", "read"', 1)
        raw = raw.replace("[http]", 'approval_file = "secrets/approval"\n\n[http]', 1)
        raw = raw.replace("max_inflight = 4", "max_inflight = 1", 1).encode()
        policy = root / "policy.toml"
        policy.write_bytes(raw)
        policy.chmod(0o600)
        policy_sha = digest(raw)
        bad_policy = root / "invalid_policy.toml"
        bad_policy.write_bytes(raw.replace(b"version = 1", b"version = 1\nundeclared = true"))
        bad_policy.chmod(0o600)
        env = {**os.environ, "HMT_DEVSECOPS_CONFIG": str(policy), "HMT_API_TOKEN": "legacy-env",
               "HMT_METRICS_TOKEN": "legacy-env", "HMT_HTTP_MAX_INFLIGHT": "64", "HMT_CHANGE_APPROVAL": "legacy-env"}
        invalid = output("hmt_devsecops.cli", "inventory", "--policy", str(bad_policy), env=env)
        assert invalid.returncode == 2 and "POLICY_SCHEMA_INVALID" in invalid.stderr
        assert not list(workspace.iterdir())

        compose = root / "compose.yaml"
        rendered = output("hmt_devsecops.deployment", "render", "--policy", str(policy),
                          "--output", str(compose), "--context", str(ROOT), env=env)
        assert rendered.returncode == 0 and policy_sha in rendered.stdout
        document_bytes = compose.read_bytes()
        document = json.loads(document_bytes)
        services = document["services"]
        assert services["devsecops"]["labels"]["org.hmt.policy.sha256"] == policy_sha
        assert services["devsecops"]["command"][-1] == policy_sha
        assert not any(value.encode() in document_bytes for value in credentials.values())

        cli = ["create", "--path", "review.json", "--content", "Synthetic proposal for human review."]
        denial = output("hmt_devsecops.cli", *cli, env=env)
        assert denial.returncode == 2 and json.loads(denial.stdout)["reason"] == "EXPLICIT_APPROVAL_REQUIRED"
        assert not (workspace / "review.json").exists()
        create = [*cli, "--approval-file", str(secret_dir / "approval")]
        response = output("hmt_devsecops.cli", *create, env=env)
        assert response.returncode == 0
        receipt = json.loads(response.stdout)
        artifact = (workspace / "review.json").read_bytes()
        artifact_sha = digest(artifact)
        assert receipt["payload"] == {"sha256": artifact_sha, "policy_sha256": policy_sha}
        assert json.loads(artifact)["policy_sha256"] == policy_sha
        replay = output("hmt_devsecops.cli", *create, env=env)
        assert replay.returncode == 2 and json.loads(replay.stdout)["reason"] == "EXISTING_TARGET_IMMUTABLE"
        assert (workspace / "review.json").read_bytes() == artifact

        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "verify", "arguments": {"args": {"path": "review.json"}}}}
        reply = output("hmt_devsecops.stdio", env=env, request=rpc)
        assert reply.returncode == 0
        rpc_receipt = json.loads(json.loads(reply.stdout)["result"]["content"][0]["text"])
        assert rpc_receipt["payload"] == receipt["payload"]

        with socket.socket() as port_probe:
            port_probe.bind(("127.0.0.1", 0))
            port = port_probe.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        with subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hmt_devsecops.http:app", "--host", "127.0.0.1", "--port", str(port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ) as service:
            try:
                for _ in range(40):
                    try:
                        ready_status, ready_body = request_http(base, "/health/ready")
                        if ready_status == 200:
                            break
                    except OSError:
                        pass
                    if service.poll() is not None:
                        raise RuntimeError("Uvicorn exited during qualification")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Uvicorn did not admit the witness policy")
                assert json.loads(ready_body)["policy_sha256"] == policy_sha
                job = {"tool": "verify", "args": {"path": "review.json"}}
                legacy, _ = request_http(base, "/tools/call", "legacy-env", job)
                assert legacy == 401
                status, body = request_http(base, "/tools/call", credentials["api_token"], job)
                http_receipt = json.loads(body)
                assert status == 200 and http_receipt["payload"] == receipt["payload"]
                denied_metrics, _ = request_http(base, "/metrics", credentials["api_token"])
                metrics, metrics_body = request_http(base, "/metrics", credentials["metrics_token"])
                assert denied_metrics == 401 and metrics == 200 and b'hmt_devsecops_tool_calls_total' in metrics_body
            finally:
                service.terminate()
                try:
                    service.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.wait()

        output_dir.mkdir(parents=True, exist_ok=False)
        members = {"witness_policy.toml": raw, "compose.yaml": document_bytes, "review.json": artifact}
        for name, data in members.items():
            (output_dir / name).write_bytes(data)
        report = {"status": "PASS", "revision": revision, "python": platform.python_version(),
                  "platform": platform.system(), "policy_sha256": policy_sha,
                  "admission_denial": "POLICY_SCHEMA_INVALID", "no_approval": "EXPLICIT_APPROVAL_REQUIRED",
                  "replay": "EXISTING_TARGET_IMMUTABLE", "legacy_http_token_status": legacy,
                  "http_metrics_status": metrics, "wrong_metrics_token_status": denied_metrics,
                  "artifact_sha256": artifact_sha, "receipts": {"cli": receipt, "stdio": rpc_receipt, "http": http_receipt},
                  "artifact_digests": {name: digest(data) for name, data in members.items()}}
        (output_dir / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    witness(args.output, args.revision)
