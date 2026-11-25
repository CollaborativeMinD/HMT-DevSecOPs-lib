# Agent orchestration and authority seams
Follow Requirements Engineering → PACE-T → Structural Complexity → V&V → RRCA → HMT-MA. Use repository graph and active contracts before task execution. Host identity and configuration are authoritative. Telemetry and model analysis may never mint mutation authority. The ten tools are fixed; no arbitrary shell, unrestricted filesystem access, `kubectl patch`, `terraform apply`, `systemctl restart`, or implicit host mutation. New files are change proposals only. Recheck prior PASS gates after edits. Record source hashes, failed experiments, and recovery receipts. Operator Runbook.md contains public commands only. Draft references are inherited and non-executable. Stop at deployment gates unsupported by the current environment; do not promote by assertion.

## Reconciled admission seams

Use `architecture/graph.json` for canonical requirements. The two HTML files are
separate, non-authoritative projections: Requirements governs design traceability;
Close-out reports observed gate states. `REQ-006` requires a per-process finite
HTTP concurrency limiter; `REQ-007` binds API metrics and Prometheus credentials.
A 429 response never authorizes retry or mutation. Keep completed background
workers charged to the capacity budget even after caller cancellation.

## Change the operator policy

Start with [the TOML example](examples/hmt_policy.toml) and [the Policy Engine](src/hmt_devsecops/policy.py).
Declare the rule and run admission. Add a typed binding if it is missing. Exercise the
same request through the existing tool and compare the artifact and policy digests.
Keep credentials in protected files outside the workspace. Keep the ten tool contracts,
the JSON-RPC wire format, and the v1.0.0 evidence. [Operator steps](Runbook.md)
