# LinkedIn Post Draft

I upgraded RepoGuard into a more agent-first Go security/backend project for checking repositories before they go public.

It scans for provider-shaped credentials, sensitive config assignments, high-entropy token-like values, committed `.env` secrets, risky MCP configs, dangerous agent permissions, unpinned MCP package execution, and GitHub Actions permission risks.

The interesting part for me was making it useful without making it noisy:

- redacted findings so reports do not re-leak secrets
- CLI exit codes for CI usage
- HTTP API for automation
- SARIF output for GitHub code scanning
- OpenAPI and machine-readable tool docs
- Go and TypeScript SDK examples
- a small stdio MCP-style server exposing a scan tool
- synthetic fixtures and tests
- no external services required

This was inspired by the growing problem of credential leaks in public repositories, especially as AI-assisted coding increases commit volume.

Repo: https://github.com/kamilch1k/repoguard
