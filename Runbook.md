# HMT DevSecOps Operator SOP

## Set up the policy

Use a Linux Python 3.12+ environment with POSIX file permissions. Install the pinned uv release and run `uv sync --locked`. The workstation CI lane runs Linux inside Docker. Use a verified wheelhouse in reduced-connectivity PACE-C. PACE-E allows no infrastructure mutation. PACE-T removes authority.

Copy [the example](examples/hmt_policy.toml) into a private runtime directory. Create the workspace and the referenced credential files first. Local paths in the policy are relative to the policy file. Keep the policy and credentials outside the public tool workspace.

```sh
umask 077
mkdir -p runtime/workspace runtime/secrets
cp -n examples/hmt_policy.toml runtime/hmt_policy.toml
uv run --locked hmt-devsecops inventory --policy runtime/hmt_policy.toml
uv run --locked hmt-devsecops-mcp --policy runtime/hmt_policy.toml
```

The stock grants are inspection grants. Put the API and metrics bearer values in separate protected files to run HTTP. For proposals, declare `approval_file`, add the explicit `create` or `update` grant, and present approval through the existing request. The CLI accepts a protected caller file via `--approval-file`. Each proposal is an exclusive create. Its bytes carry the principal, generation, request ID, and policy digest. It grants no infrastructure mutation authority.

## Admit and verify a change

1. Change the TOML. Run the relevant entry point. A new field should fail admission until the typed model owns it.
2. Bind the field to the existing tool or transport. To invoke a host tool, declare its reviewed absolute executable under `[executables]`. The runtime supplies the fixed arguments. An absent binary yields `HOLD`.
3. Re-run the same witness. Compare the policy hash, the result, and the artifact bytes. Keep credentials out of receipts and logs.

```sh
uv run --locked pytest --cov=hmt_devsecops --cov-branch
uv run --locked python tools/qualify_policy.py --output ci-proof/witness --revision "$(git rev-parse HEAD)"
```

Use a new output path for each witness. Forgejo qualifies the exact pushed revision and preserves the fixture policy, rendered Compose artifact, proposal, and receipts. [Workflow](.forgejo/workflows/policy.yml)

## Render Docker Compose

Provision the separate API and metrics files before rendering. A container policy uses paths relative to the policy file so the renderer can mount the same bytes. Set the reviewed OCI digest references in the `[deployment]` section. Give UID 10001 read access to the policy, workspace, and API token. Give both the API and Prometheus read access to the metrics file through GID 10001. Mode `0440` is suitable for a root-owned shared credential with that group. Keep credentials unreadable by other users.

```sh
uv run --locked hmt-devsecops-deploy render --policy runtime/hmt_policy.toml --output runtime/compose.yaml
docker compose -f runtime/compose.yaml config --quiet
docker compose -f runtime/compose.yaml --profile monitoring up -d --build
curl --fail http://127.0.0.1:18080/health/ready
```

The artifact carries the digest and mounts the policy, workspace, and credential files read-only. Prometheus reads the same metrics file as the API. Use the configured host port if it differs from the example. Compare readiness with the declared SHA-256. For a policy change, render to a fresh artifact path and recreate the API with that file. HTTP holds one policy and capacity limit per process. A `429` denies execution and a disconnected caller retains its slot until the worker ends.

For native HTTP, set `HMT_DEVSECOPS_CONFIG` to the policy path and start `uvicorn hmt_devsecops.http:app --host 127.0.0.1 --port 18080`. That variable selects a file. Authority and limits come from its declarations.

## Inspect and recover

Run real Terraform or Ansible checks only against a reviewed project and inventory. `terraform -chdir=ops/terraform validate` and `ansible-playbook -i ops/ansible/inventory.example.ini ops/ansible/site.yaml --syntax-check` are operator checks. Tailnet and k3s health calls use their fixed read operations. Review the dry-run, rollback, scope, and state ownership before taking a manual change. Compare authority generation after a fault and obtain fresh approval before another proposal.

Use `monitoring/prometheus.local.yml` when Prometheus runs on the host. Check its live scrape before calling the deployment healthy. Keep actual cluster, Tailnet, monitoring, and OCI observations with their own evidence. The [original release gates](release/verification.md) record the 1.0.0 environment.

## Rebuild the historical offline reports

```sh
uv run --locked python tools/generate_reports.py
uv run --locked python tools/verify_reports_browser.py
```

Browser verification requires Playwright and a real Chromium installation. The Requirements and Close-out views explain different stages of the same architecture graph. Their original images and gate receipts stay with the original release.

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.

## From policy change to release

Start with [examples/hmt_policy.toml](examples/hmt_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `sh tools/qualify.sh` in the project environment. Exercise the normal entry point and the denial. Review the authorized workspace inventory and its policy digest. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.

The version 2 `[runtime]` table in `console.toml` sets request size, concurrency and client deadlines. Version 1 files inherit the shipped budget. Reissue them as version 2 to pin these choices in the admitted document.
