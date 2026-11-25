from __future__ import annotations
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from .contracts import ToolRequest, ToolResult
from .policy import BoundPolicy, Denied, authorize, scoped_path

ALLOWED = {
    "terraform_plan": ("terraform", "plan", "-input=false", "-lock-timeout=5s", "-no-color"),
    "ansible_check": ("ansible-playbook", "--syntax-check", "site.yaml"),
    "k3s_status": ("kubectl", "get", "nodes", "-o", "wide"),
    "tailscale_status": ("tailscale", "status", "--json"),
}

def denied(reason: str) -> ToolResult:
    return ToolResult(disposition="DENIED", reason=reason)

def inspect(workspace: Path) -> dict[str, object]:
    paths = sorted(p.name for p in workspace.iterdir())[:64]
    return {"files": paths, "count_capped": len(paths) == 64}

def run_bounded(tool: str, bound: BoundPolicy) -> ToolResult:
    cmd = ALLOWED[tool]
    selected = getattr(bound.policy.executables, tool)
    executable = Path(selected).resolve() if selected else None
    if executable is None or not executable.is_file() or not os.access(executable, os.X_OK):
        return ToolResult(disposition="HOLD", reason="EXECUTABLE_MISSING:" + cmd[0])
    if executable.is_relative_to(bound.workspace) or executable.stat().st_mode & 0o022:
        return denied("EXECUTABLE_PATH_INVALID")
    try:
        proc = subprocess.run((executable, *cmd[1:]), cwd=bound.workspace, env={"PATH": os.defpath, "HOME": str(bound.workspace), "LANG": "C", "TF_IN_AUTOMATION": "1"}, capture_output=True, text=True, timeout=12, check=False)
    except subprocess.TimeoutExpired:
        return ToolResult(disposition="HOLD", reason="COMMAND_TIMEOUT")
    return ToolResult(disposition="PASS" if proc.returncode == 0 else "HOLD", reason="COMMAND_EXIT_" + str(proc.returncode), payload={"stdout": proc.stdout[:4096], "stderr": proc.stderr[:2048]})

def _artifact_bytes(path: Path, limit: int, reason: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Denied(reason) from None
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Denied(reason)
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Denied(reason)
    return data

def execute(request: ToolRequest, bound: BoundPolicy) -> ToolResult:
    result = _execute(request, bound)
    result.payload["policy_sha256"] = bound.sha256
    return result

def _execute(request: ToolRequest, bound: BoundPolicy) -> ToolResult:
    args = request.args
    try:
        authorize(bound, request.tool, args.get("approval", ""))
        base = bound.workspace
        if request.tool == "inventory":
            return ToolResult(disposition="PASS", reason="INVENTORY_BOUNDED", payload=inspect(base))
        if request.tool in ALLOWED:
            return run_bounded(request.tool, bound)
        if request.tool == "read":
            target = scoped_path(base, args.get("path", ""))
            data = _artifact_bytes(target, 16384, "FILE_MISSING_OR_TOO_LARGE")
            return ToolResult(disposition="PASS", reason="READ_ONLY", payload={"text": data.decode("utf-8")})
        if request.tool == "verify":
            target = scoped_path(base, args.get("path", ""))
            data = _artifact_bytes(target, 1048576, "VERIFY_TARGET_INVALID")
            return ToolResult(disposition="PASS", reason="HASH_WITNESS", payload={"sha256": hashlib.sha256(data).hexdigest()})
        if request.tool == "evidence":
            return ToolResult(disposition="PASS", reason="REPORT_VIEW_ONLY", payload={"html": "<!doctype html><html><head><meta charset='utf-8'><title>HMT Evidence</title></head><body><h1>HMT Evidence</h1><p>Read-only, non-authoritative report. Principal: " + bound.policy.principal.replace("&", "&amp;").replace("<", "&lt;") + "</p></body></html>"})
        if request.tool in {"create", "update"}:
            target = scoped_path(base, args.get("path", ""))
            if target.suffix != ".json" or not target.parent.is_dir():
                return denied("CHANGE_TARGET_INVALID")
            payload = {"kind": "change_proposal", "action": request.tool, "principal": bound.policy.principal, "generation": bound.policy.generation, "policy_sha256": bound.sha256, "request_id": request.request_id, "content": args.get("content", "")[:2048]}
            data = json.dumps(payload, sort_keys=True).encode()
            try:
                with target.open("xb") as f:
                    f.write(data)
            except FileExistsError:
                return denied("EXISTING_TARGET_IMMUTABLE")
            return ToolResult(disposition="PASS", reason="PROPOSAL_ONLY_NO_APPLY", payload={"sha256": hashlib.sha256(data).hexdigest()})
    except Denied as error:
        return denied(str(error))
    except (OSError, UnicodeError, ValueError, RuntimeError):
        return denied("ARTIFACT_UNAVAILABLE")
    return denied("UNSUPPORTED_OPERATION")
