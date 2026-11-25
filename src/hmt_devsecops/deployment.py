"""Render the Compose transport from one admitted TOML policy."""

import argparse
import json
from pathlib import Path, PurePosixPath

from . import __version__
from .http import bind_http, create_app
from .policy import BoundPolicy, Denied, credential_refs, parse_config

CONTAINER_ROOT = PurePosixPath("/run/hmt")
API_PORT = 8080
METRICS_TARGET = "/run/secrets/hmt_metrics_token"


def _container_ref(ref: str) -> str:
    relative = PurePosixPath(ref)
    if relative.is_absolute() or ".." in relative.parts or "\\" in ref or ":" in ref or not relative.parts:
        raise Denied("COMPOSE_PATH_MUST_BE_RELATIVE")
    return str(CONTAINER_ROOT / relative)


def _mount(source: Path, target: str) -> dict:
    return {"type": "bind", "source": str(source).replace("$", "$$"), "target": target,
            "read_only": True, "bind": {"create_host_path": False}}


def compose_document(bound: BoundPolicy, context: Path) -> dict:
    declaration = bound.policy
    deploy, http = declaration.deployment, declaration.http
    if deploy is None or http is None:
        raise Denied("DEPLOYMENT_AND_HTTP_REQUIRED")
    bind_http(bound)
    workspace = _container_ref(declaration.workspace)
    policy_target = str(CONTAINER_ROOT / "policy.toml")
    mounts = [_mount(bound.source, policy_target), _mount(bound.workspace, workspace)]
    targets = {policy_target, workspace}
    for ref in credential_refs(declaration):
        target = _container_ref(ref)
        if target in targets:
            raise Denied("COMPOSE_MOUNT_COLLISION")
        targets.add(target)
        mounts.append(_mount(bound.resolve_ref(ref), target))
    sandbox = deploy.resources.sandbox()
    return {
        "services": {
            "devsecops": {
                **sandbox, "image": f"hmt-devsecops-tools:{__version__}", "user": "10001:10001", "cpus": deploy.resources.service_cpus,
                "build": {"context": str(context.resolve()).replace("$", "$$"),
                          "args": {"PYTHON_IMAGE": deploy.python_image, "UV_IMAGE": deploy.uv_image}},
                "ports": [f"127.0.0.1:{deploy.http_port}:{API_PORT}"], "volumes": mounts,
                "command": [".venv/bin/python", "-m", "hmt_devsecops.deployment", "serve",
                            "--policy", policy_target, "--expect-sha256", bound.sha256],
                "labels": {"org.hmt.policy.sha256": bound.sha256},
            },
            "prometheus": {
                **sandbox, "profiles": ["monitoring"], "image": deploy.prometheus_image,
                "user": "65534:65534", "group_add": ["10001"], "cpus": deploy.resources.monitoring_cpus,
                "command": ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus",
                            f"--storage.tsdb.retention.time={deploy.resources.monitoring_days}d"],
                "volumes": [_mount(context.resolve() / "monitoring/prometheus.yml", "/etc/prometheus/prometheus.yml"),
                            _mount(bound.resolve_ref(http.metrics_token_file), METRICS_TARGET),
                            "prometheus-data:/prometheus"],
            },
        },
        "volumes": {"prometheus-data": {}},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    render.add_argument("--policy", required=True, type=Path)
    render.add_argument("--output", required=True, type=Path)
    render.add_argument("--context", type=Path, default=Path("."))
    serve = commands.add_parser("serve")
    serve.add_argument("--policy", required=True, type=Path)
    serve.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "render":
            bound = parse_config(args.policy)
            document = compose_document(bound, args.context)
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(document, output, indent=2)
                output.write("\n")
            print(f"policy_sha256={bound.sha256}")
        else:
            import uvicorn

            uvicorn.run(create_app(args.policy, args.expect_sha256), host="0.0.0.0", port=API_PORT, workers=1)
    except (Denied, OSError) as error:
        parser.exit(2, (str(error) if isinstance(error, Denied) else "DEPLOYMENT_ARTIFACT_UNAVAILABLE") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
