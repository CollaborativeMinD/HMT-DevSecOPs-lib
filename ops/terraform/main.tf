terraform {
  required_version = ">= 1.8.0, < 2.0.0"
}
# Read-only baseline: operator-defined providers must be locked before use.
output "deployment_policy" { value = "plan-only; no unattended apply" }
