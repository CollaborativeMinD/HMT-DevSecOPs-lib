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

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.

## From policy change to release

Start with [examples/hmt_policy.toml](examples/hmt_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `sh tools/qualify.sh` in the project environment. Exercise the normal entry point and the denial. Review the authorized workspace inventory and its policy digest. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.
