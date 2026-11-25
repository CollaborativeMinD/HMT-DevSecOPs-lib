"""Expose the HMT inventory contract under its original host policy and grant."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hmt_devsecops.contracts import ToolRequest
from hmt_devsecops.operations import execute as dispatch
from hmt_devsecops.policy import authorize, parse_config

TITLE = "HMT DevSecOps"
OPERATIONS = {"inventory"}


def validate(binding, inputs):
    if inputs != {}:
        raise ValueError("Inventory accepts no arguments")


def observe(binding):
    bound = parse_config(binding["source"])
    authorize(bound, "inventory")
    return bound.sha256, f"{bound.policy.principal} · generation {bound.policy.generation} · {len(bound.policy.allowed)} grants"


def execute(binding, inputs, directory, receipt_id, revision):
    bound = parse_config(binding["source"])
    if bound.sha256 != revision:
        raise ValueError("Host policy changed")
    result = dispatch(ToolRequest(tool="inventory", request_id=receipt_id), bound)
    if result.disposition != "PASS":
        raise ValueError(result.reason)
    return result.model_dump()
