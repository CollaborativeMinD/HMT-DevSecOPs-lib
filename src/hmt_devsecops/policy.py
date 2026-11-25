"""Bind one operator declaration to the paths and authority it governs."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from .contracts import ToolName

POLICY_PATH = "HMT_DEVSECOPS_CONFIG"
PathText = Annotated[str, Field(strict=True, min_length=1)]
Image = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_./:-]*@sha256:[0-9a-f]{64}$")]


class Denied(ValueError):
    pass


class Declaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class HTTPPolicy(Declaration):
    max_inflight: Annotated[int, Field(strict=True, ge=1, le=64)]
    api_token_file: PathText
    metrics_token_file: PathText


class Executables(Declaration):
    terraform_plan: PathText | None = None
    ansible_check: PathText | None = None
    k3s_status: PathText | None = None
    tailscale_status: PathText | None = None


class Deployment(Declaration):
    python_image: Image
    uv_image: Image
    prometheus_image: Image
    http_port: Annotated[int, Field(strict=True, ge=1024, le=65535)]


class Policy(Declaration):
    version: Annotated[int, Field(strict=True, ge=1, le=1)]
    workspace: PathText
    principal: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    generation: Annotated[int, Field(strict=True, ge=0)]
    allowed: tuple[ToolName, ...]
    approval_file: PathText | None = None
    http: HTTPPolicy | None = None
    executables: Executables = Field(default_factory=Executables)
    deployment: Deployment | None = None


@dataclass(frozen=True)
class BoundPolicy:
    source: Path
    policy: Policy
    workspace: Path
    sha256: str
    approval: bytes | None = field(default=None, repr=False)

    def resolve_ref(self, value: str) -> Path:
        return Path(os.path.abspath(self.source.parent / value))


def _protected_read(path: Path, limit: int, mode_mask: int, kind: str) -> bytes:
    if os.name != "posix":
        raise Denied(f"{kind}_PERMISSIONS_UNSUPPORTED")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise Denied(f"{kind}_FILE_INVALID")
            if info.st_mode & mode_mask:
                raise Denied(f"{kind}_PERMISSIONS_INVALID")
            raw = stream.read(limit + 1)
    except (OSError, ValueError) as error:
        if isinstance(error, Denied):
            raise
        raise Denied(f"{kind}_FILE_INVALID") from None
    if len(raw) > limit:
        raise Denied(f"{kind}_TOO_LARGE")
    return raw


def credential_refs(policy: Policy) -> tuple[str, ...]:
    http = (policy.http.api_token_file, policy.http.metrics_token_file) if policy.http else ()
    return http + ((policy.approval_file,) if policy.approval_file else ())


def parse_config(path: Path) -> BoundPolicy:
    source = path.absolute()
    raw = _protected_read(source, 32768, 0o022, "POLICY")
    try:
        declaration = Policy.model_validate(tomllib.loads(raw.decode("utf-8")))
    except (ValueError, RecursionError):
        raise Denied("POLICY_SCHEMA_INVALID") from None
    workspace = (source.parent / declaration.workspace).resolve()
    if not workspace.is_dir():
        raise Denied("WORKSPACE_INVALID")
    bound = BoundPolicy(source, declaration, workspace, hashlib.sha256(raw).hexdigest())
    if len(set(declaration.allowed)) != len(declaration.allowed):
        raise Denied("DUPLICATE_GRANT")
    refs = [bound.resolve_ref(value).resolve() for value in credential_refs(declaration)]
    if len(set(refs)) != len(refs):
        raise Denied("CREDENTIAL_PATHS_MUST_DIFFER")
    if any(path.is_relative_to(workspace) for path in [source.resolve(), *refs]):
        raise Denied("AUTHORITY_FILES_INSIDE_WORKSPACE")
    for value in declaration.executables.model_dump(exclude_none=True).values():
        path = Path(value)
        if not path.is_absolute() or path.resolve().is_relative_to(workspace):
            raise Denied("EXECUTABLE_PATH_INVALID")
    if declaration.approval_file:
        bound = BoundPolicy(source, declaration, workspace, bound.sha256,
                            read_credential(bound.resolve_ref(declaration.approval_file)))
    return bound


def policy_path(override: Path | None = None) -> Path:
    if override is not None:
        return override
    location = os.environ.get(POLICY_PATH)
    if not location:
        raise Denied("POLICY_PATH_REQUIRED")
    return Path(location)


def read_credential(path: Path) -> bytes:
    credential = _protected_read(path, 4096, 0o037, "CREDENTIAL").strip()
    if not re.fullmatch(rb"[!-~]+", credential):
        raise Denied("CREDENTIAL_INVALID")
    return credential


def authorize(bound: BoundPolicy, tool: str, approval: str = "") -> None:
    declaration = bound.policy
    if tool not in declaration.allowed:
        raise Denied("GRANT_ABSENT")
    if tool in {"create", "update"}:
        if bound.approval is None or not hmac.compare_digest(bound.approval, approval.encode("utf-8")):
            raise Denied("EXPLICIT_APPROVAL_REQUIRED")


def scoped_path(workspace: Path, value: str) -> Path:
    candidate = Path(os.path.abspath(workspace / value))
    if not candidate.is_relative_to(workspace) or not candidate.resolve().is_relative_to(workspace):
        raise Denied("PATH_OUTSIDE_WORKSPACE")
    for part in (candidate, *candidate.parents):
        if part == workspace:
            break
        if part.is_symlink():
            raise Denied("SYMLINK_DENIED")
    return candidate
