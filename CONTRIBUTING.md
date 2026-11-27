# Contributing to ScopeGuard

Thank you for your interest in contributing to ScopeGuard!

## Guidelines

1. **Zero External Python Dependencies**: Keep all scripts in `plugins/scopeguard/` and `portal/` compatible with Python 3.10+ standard library only.
2. **Read-Only Safety Gate**: Never add autonomous IAM policy mutations (`set-iam-policy`, key deletion, SA disabling) to skill scripts. Always emit reviewable Terraform HCL, YAML, or rollback runbooks.
3. **No Personal or Production Data**: Never commit real GCP project IDs, organization IDs, IAM policies, audit bundles, or personal email addresses. Use `my-gcp-project`, `123456789012`, and `example.com`.
4. **Tests**: Run `python3 -m unittest discover -s tests -v` before opening a Pull Request.
