# Reverse RCA Ledger — scoped corrections

| Incident | Observed defect | Root cause | Correction | Regression |
|---|---|---|---|---|
| RRCA-001 | Python 3.11 Docker draft | Unpinned legacy runtime | Digest-required Python 3.13 + uv build surface | Source review and structural checks |
| RRCA-002 | SSH host-key verification disabled | Draft speed assumption | Host key checks re-enabled | tests/test_artifacts.py |
| RRCA-003 | Alert directly restarts pods | Telemetry treated as authority | Read-only K8s observer; proposal-only approvals | tests/test_ops.py |
| RRCA-004 | Mutable image tags and missing inventory template | Unsealed draft environment | Digest-required inputs; explicit placeholders and inventory example | Structural review; OCI execution HOLD |
| RRCA-005 | Missing static tool contracts | No admission boundary | Fixed ten tools, explicit grants and request schema | tests/test_transport.py |
| RRCA-006 | Missing metrics scrape auth | Public observability path | Dedicated bearer token for `/metrics` | test_metrics_authenticated |
| RRCA-007 | Missing Python environment resolver cache | Registry unavailable | Freeze release with lock gate HOLD, no fabricated lock | evidence/uv_lock.txt |

These interventions preserve draft text under `references/drafts/`. No original file is silently promoted as executable.

## RRCA v1.0.0 reconciliations — 2026-11-04

| Incident | Initiating condition | Observed consequence | Correction | Regression | Disposition |
|---|---|---|---|---|---|
| RRCA-HTML-001 | One HTML template reused for both lifecycle stages | Requirements and release Close-out indistinguishable | Two independent design/evidence projections of the same canonical JSON graph | `test_views_differ_with_identical_canonical_source`; actual Chromium screenshots | INVESTIGATION_COMPLETE / SOLUTION_CANDIDATE_APPLIED |
| RRCA-METRICS-002 | API secret variable not configured in Compose; Prometheus secret path only | Authenticated scrape could never succeed on deployment as written | Host secret environment required, Prometheus secret-file read-only mount, service DNS targets | `test_credentials_wired_and_private`; `test_metrics_separate_token` | INVESTIGATION_COMPLETE / SOLUTION_CANDIDATE_APPLIED |
| RRCA-CAPACITY-003 | HTTP ingress had body/auth bounds but no admission budget | Unbounded parallel tool work possible | Configurable bounded process-local semaphore, pre-execution 429, worker-owned release on cancellation | `test_concurrency_denial_has_no_execution`; `test_limit_rejects_invalid_values` | INVESTIGATION_COMPLETE / SOLUTION_CANDIDATE_APPLIED |

The three repairs are **software admitted** only. Actual Prometheus scrape inside Compose and container startup remain governed by existing deployment HOLDs. No implicit promotion is granted.
