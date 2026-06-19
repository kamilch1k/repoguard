# RepoGuard

RepoGuard is a Go CLI and HTTP API for auditing repositories before they go public.

It scans source trees and submitted file payloads for provider-shaped credentials, sensitive configuration assignments, high-entropy token-like values, and risky MCP server configs that embed secrets directly in JSON.

## Why This Project Exists

Public code is easier to ship than ever, but that also makes credential leaks easier. RepoGuard is designed as a small, inspectable security tool that can run locally, in CI, or behind a tiny API before a repository is published.

It is intentionally more useful than a portfolio CRUD app:

- recursive source scanning with file-size and directory guards
- provider-style token patterns for common leak shapes
- entropy scoring for unknown token formats
- MCP config inspection for embedded environment values
- redacted findings so reports do not re-leak the secret
- CLI exit codes for CI and an HTTP API for automation

## Quick Start

```powershell
go test ./...
go run ./cmd/repoguard -path samples/demo -fail-on none
```

JSON output:

```powershell
go run ./cmd/repoguard -path samples/demo -format json -fail-on none
```

Fail a pipeline when warnings or errors are present:

```powershell
go run ./cmd/repoguard -path . -fail-on warn
```

## API

Run the service:

```powershell
go run ./cmd/api -addr :8080
```

Scan a synthetic payload:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/scan -ContentType application/json -InFile samples/demo/api-scan.json
```

Endpoints:

```text
GET  /health
POST /api/scan
```

`POST /api/scan` accepts:

```json
{
  "files": [
    { "path": "mcp.json", "content": "{ ... }" }
  ]
}
```

## Rule Families

| Rule | Severity | Detector | Meaning |
| --- | --- | --- | --- |
| `RG001`-`RG005` | error | provider-pattern | Known provider-shaped credentials and private key blocks |
| `RG101` | warn | config-keyword | Sensitive assignments such as token or secret values |
| `RG201` | warn | entropy | High-entropy token-like values |
| `RG301` | error | mcp-config | MCP JSON embeds a credential-like environment value |

## Project Layout

```text
cmd/repoguard        CLI entrypoint
cmd/api              HTTP API entrypoint
internal/scanner     rules, entropy, MCP inspection, path scanner
internal/httpapi     HTTP handlers and endpoint tests
samples/demo         synthetic fixtures that are safe to publish
docs                 testing notes and LinkedIn copy
```

## Security

The sample data is synthetic. RepoGuard redacts findings in reports and does not need any external credentials.
