from __future__ import annotations
import argparse
import json
from pathlib import Path
from .contracts import ToolRequest
from .operations import execute
from .policy import Denied, parse_config, policy_path, read_credential

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HMT DevSecOps governed PMCS")
    parser.add_argument("tool", choices=ToolRequest.model_fields["tool"].annotation.__args__)
    parser.add_argument("--path", default="")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--approval-file", type=Path)
    parser.add_argument("--content", default="")
    args = parser.parse_args(argv)
    try:
        policy = parse_config(policy_path(args.policy))
        approval = read_credential(args.approval_file).decode("ascii") if args.approval_file else ""
    except Denied as error:
        parser.exit(2, str(error) + "\n")
    result = execute(ToolRequest(tool=args.tool, args={"path": args.path, "approval": approval, "content": args.content}), policy)
    print(json.dumps(result.model_dump(), indent=2))
    return 0 if result.disposition == "PASS" else 2

if __name__ == "__main__":
    raise SystemExit(main())
