---
name: ansible-dry-run
description: Bounded HMT DevSecOps workflow for ansible dry run.
---
# Ansible Dry Run
Use `hmt-devsecops-mcp` tool `ansible_check`. First inspect `Runbook.md` and current operator grants. Confirm host-managed identity, workspace, and target. Never execute `terraform apply`, `terraform destroy`, `ansible-playbook` without `--check`, `tailscale up`, `systemctl restart`, or Kubernetes patches as an implicit side effect. Keep requests bounded and redact credentials. Required input: installed MCP connection, host configuration; file workflows also require an in-workspace path. Expected output: PASS, DENIED, HOLD, or INSUFFICIENT_EVIDENCE with reason and bounded evidence. On HOLD do not invent a success receipt. Review `AGENTS.md` for the authoritative boundary and `Runbook.md` for operator replay.
