# HMT DevSecOps verification

**Software and bounded interface checks: PASS** (see `evidence/pytest.txt`). **Native deployment and host tooling: HOLD** for explicit environment reasons. Do not conflate software proofs and actual deployment.

- G-DRAFT-001: PASS — 17 draft file members extracted intact
- G-CONTRACT-002: PASS — Ten tool contracts and non-authoritative proposals
- G-TEST-003: PASS — 47 pytest tests, no failures; combined statement/branch 96.42%
- G-CLIENT-004: PASS — JSON/TOML templates parsed; signed-in host operation not asserted
- G-MCP-005: PASS — Actual line-delimited MCP subprocess and HTTP ASGI TestClient
- G-SEC-006: PASS — Read grants, approval denial, path fences tested
- G-METRICS-007: PASS — Authenticated metrics generated with actual tool invocation
- G-SKILL-008: PASS — Ten SKILL.md files and dry-run installer tested
- G-PY-009: PASS — Python 3.13.5 runtime used for tests; supported 3.12+ declaration
- G-LOCK-010: HOLD — Resolver lock cannot be generated offline; dependencies unavailable in uv cache
- G-OCI-011: HOLD — Docker and OCI daemon absent; image digest not verified
- G-ANSIBLE-012: HOLD — Ansible CLI absent; only static contract checked
- G-TERRAFORM-013: HOLD — Terraform CLI absent; only static HCL inspected
- G-K3S-014: HOLD — No live k3s credentials and kubectl binary
- G-TAILSCALE-015: HOLD — Tailscale CLI and live tailnet not present
- G-PROM-016: HOLD — Prometheus and Alertmanager daemons unavailable; rules syntax not runtime evaluated
- G-GRAFANA-017: HOLD — Grafana image not runnable in this container; configuration query/schema check only
- G-HMTMA-018: HOLD — Native HMT-Mission-Assurance evaluator not run in this environment
- G-42-019: HOLD — Native42 standalone tool distribution unavailable for execution
- G-REPORT-020: PASS — Standalone graph and closeout HTML generated from common model; browser capture separate
- G-BROWSER-021: PASS — Chromium rendered 14 graph nodes, requirement search, change-impact view, and actual screenshots
- G-HTTP-022: PASS — Two real Uvicorn localhost startup/restart cycles with auth denial, read, metrics, and readiness

## Three-seam reconciliation verification (2026-11-04)

- 52 full project tests passed, zero failures.
- 273 combined coverage statements and 88 branch opportunities: 96.12% combined coverage; 82/88 branches covered = 93.18% branch coverage.
- Concurrent HTTP admission test proves a held execution consumes the slot, rejects the second request with 429, and allows another only after completion.
- Both standalone HTML projections embed the identical `architecture/graph.json` and have distinct stage-specific interactions.
- Prometheus expects `/run/secrets/hmt_metrics_token`; Compose binds the host secret and injects `HMT_METRICS_TOKEN` into the API. Host must create identical bytes. No plaintext secret is included.
- Existing OCI/container/live monitoring HOLDs remain unchanged.

Evidence: `evidence/patch_regression.txt`, `evidence/patch_coverage.json`, `tests/test_reconciliation.py`, browser screenshot files.
