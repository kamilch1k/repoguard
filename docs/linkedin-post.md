# LinkedIn Post Draft

I built RepoGuard, a Go security/backend project for checking repositories before they go public.

It scans for provider-shaped credentials, sensitive config assignments, high-entropy token-like values, and MCP JSON configs that embed credential-like environment values.

The interesting part for me was making it useful without making it noisy:

- redacted findings so reports do not re-leak secrets
- CLI exit codes for CI usage
- HTTP API for automation
- synthetic fixtures and tests
- no external services required

This was inspired by the growing problem of credential leaks in public repositories, especially as AI-assisted coding increases commit volume.

Repo: https://github.com/kamilch1k/repoguard
