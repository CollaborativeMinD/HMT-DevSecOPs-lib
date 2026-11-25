---
name: hmt-policy-change
description: Admit and verify hmt policy changes and qualify the exact revision for release.
---

# Change a governed policy

## From policy change to release

Start with [examples/hmt_policy.toml](examples/hmt_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `sh tools/qualify.sh` in the project environment. Exercise the normal entry point and the denial. Review the authorized workspace inventory and its policy digest. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.
