"""Exercise the admitted Prometheus image against HMT with disposable credentials."""
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen


def provision():
    from hmt_devsecops.deployment import compose_document
    from hmt_devsecops.policy import parse_config

    state = Path("/state")
    (state / "workspace").mkdir()
    (state / "secrets").mkdir()
    source = state / "policy.toml"
    shutil.copyfile("/app/examples/hmt_policy.toml", source)
    bound = parse_config(source)
    for ref in (bound.policy.http.api_token_file, bound.policy.http.metrics_token_file):
        path = bound.resolve_ref(ref)
        path.write_text(secrets.token_hex(32))
        path.chmod(0o440)
    metrics = state / "monitor"
    metrics.mkdir()
    shutil.copyfile("/app/monitoring/prometheus.yml", metrics / "prometheus.yml")
    os.link(bound.resolve_ref(bound.policy.http.metrics_token_file), metrics / "hmt_metrics_token")
    print(json.dumps(compose_document(bound, Path("/app"))))


def observe(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urlopen("http://prometheus:9090/api/v1/targets", timeout=3) as response:
                targets = json.load(response)["data"]["activeTargets"]
            if len(targets) == 1 and targets[0]["health"] == "up":
                with urlopen("http://localhost:8080/health/ready", timeout=3) as response:
                    ready = json.load(response)
                print(json.dumps({"target": targets[0]["scrapeUrl"], "health": "up",
                                  "policy_sha256": ready["policy_sha256"]}))
                return
        except (URLError, TimeoutError):
            pass
        time.sleep(1)
    raise TimeoutError("Prometheus did not complete the authenticated scrape")


def verify_monitor(run, root, cfg, platform, app, companion, folder, project):
    volume = project + "-credentials"
    run("docker", "volume", "create", volume)
    file = folder / "monitor-witness.json"
    compose = ["docker", "compose", "-p", project, "-f", str(file), "--profile", "monitoring"]
    try:
        raw = run("docker", "run", "--rm", "--network", "none", "--platform", platform,
                  "-v", volume + ":/state", "-e", "PYTHONPATH=/app/src", "--entrypoint", "python3.13",
                  app, "-m", "release.monitor_probe", "provision", timeout=cfg.witness_seconds)
        spec = json.loads(raw)
        spec["volumes"]["credentials"] = {"name": volume, "external": True}
        spec["networks"] = {"default": {"internal": True}}
        api = spec["services"]["devsecops"]
        api.pop("ports")
        api.pop("build")
        api.update(image=app, platform=platform, entrypoint=["python3.13"],
                   environment={"PYTHONPATH": "/app/src"}, volumes=["credentials:/run/hmt:ro"])
        api["command"] = api["command"][1:]
        monitor = spec["services"]["prometheus"]
        monitor.update(image=companion, platform=platform)
        monitor["volumes"][0] = {"type": "volume", "source": "credentials", "target": "/etc/prometheus",
                                 "read_only": True, "volume": {"subpath": "monitor"}}
        monitor["volumes"][1] = {"type": "volume", "source": "credentials", "target": "/run/secrets",
                                 "read_only": True, "volume": {"subpath": "monitor"}}
        file.write_text(json.dumps(spec), encoding="utf8")
        run(*compose, "up", "-d", timeout=cfg.witness_seconds)
        raw = run(*compose, "exec", "-T", "devsecops", "python3.13", "-m", "release.monitor_probe",
                  "observe", str(cfg.witness_seconds), timeout=cfg.witness_seconds)
        receipt = json.loads(raw)
        if receipt["policy_sha256"] != api["labels"]["org.hmt.policy.sha256"]:
            raise ValueError("Scrape and rendered policy differ")
        return receipt
    finally:
        try:
            if file.exists():
                run(*compose, "down", "--volumes", "--remove-orphans")
        finally:
            run("docker", "volume", "rm", volume)


if __name__ == "__main__":
    if sys.argv[1] == "provision":
        provision()
    elif sys.argv[1] == "observe":
        observe(int(sys.argv[2]))
