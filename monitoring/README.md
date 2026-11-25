# Monitoring credential and network contract

Use `[http].metrics_token_file` in the admitted TOML. The API and Prometheus read the same protected file. The renderer mounts it read-only at `/run/secrets/hmt_metrics_token` for Prometheus. Keep the API token and proposal approval in separate protected files.

Host-local Prometheus uses `monitoring/prometheus.local.yml`. Point its credential file at the metrics file selected by the policy and its target at the configured loopback port. Containerized Prometheus uses `monitoring/prometheus.yml` and the `devsecops:8080` service on the Compose network.

`[http].max_inflight` admits 1 to 64 worker slots per API process. An over-capacity call gets HTTP 429 before it reaches a tool. A disconnected caller cannot release its slot while the worker is still running.

Alertmanager routing and dashboard files are reference artifacts. A deployment needs live evidence before it clears those gates. [Runbook](../Runbook.md)
