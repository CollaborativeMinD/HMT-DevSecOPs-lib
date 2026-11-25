from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

ToolName = Literal["create", "read", "update", "verify", "evidence", "inventory", "terraform_plan", "ansible_check", "k3s_status", "tailscale_status"]

class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: ToolName
    args: dict[str, str] = Field(default_factory=dict, max_length=12)
    request_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$", default="local")

class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: Literal["PASS", "DENIED", "HOLD", "INSUFFICIENT_EVIDENCE"]
    reason: str
    payload: dict[str, object] = Field(default_factory=dict)
