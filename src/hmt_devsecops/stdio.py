from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .contracts import ToolRequest
from .operations import execute
from .policy import BoundPolicy, Denied, parse_config, policy_path
from . import __version__

TOOLS = ("create", "read", "update", "verify", "evidence", "inventory", "terraform_plan", "ansible_check", "k3s_status", "tailscale_status")

def respond(message: dict, config: BoundPolicy) -> dict:
    mid = message.get("id")
    method = message.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "hmt-devsecops-tools", "version": __version__}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": n, "description": "Explicitly bounded " + n, "inputSchema": {"type": "object", "properties": {"args": {"type": "object"}, "request_id": {"type": "string"}}, "additionalProperties": False}} for n in TOOLS]}}
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Unknown tool"}}
        arguments = params.get("arguments") or {}
        try:
            request = ToolRequest(tool=name, **arguments)
            result = execute(request, config)
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": result.model_dump_json()}], "isError": result.disposition != "PASS"}}
        except Exception:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "Invalid arguments"}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Unsupported method"}}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HMT DevSecOps MCP")
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args(argv)
    try:
        config = parse_config(policy_path(args.policy))
    except Denied as error:
        print(str(error), file=sys.stderr)
        return 2
    for line in sys.stdin.buffer:
        if len(line) > 65536:
            break
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                continue
            if message.get("method", "").startswith("notifications/"):
                continue
            result = respond(message, config)
            sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
            sys.stdout.flush()
        except (ValueError, UnicodeError):
            sys.stdout.write('{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}\n')
            sys.stdout.flush()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
