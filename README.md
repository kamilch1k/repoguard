# RepoGuard

RepoGuard is an agent-first Go security scanner for auditing repositories before they go public.

It scans source trees and submitted file payloads for provider-shaped credentials, sensitive configuration assignments, high-entropy token-like values, committed `.env` secrets, risky MCP server configs, dangerous agent permission settings, unpinned MCP package execution, and over-broad GitHub Actions permissions.

## Why This Project Exists

Public code is easier to ship than ever, but that also makes credential leaks easier. RepoGuard is designed as a small, inspectable security tool that can run locally, in CI, or behind a tiny API before a repository is published.

It is intentionally more useful than a portfolio CRUD app:

- recursive source scanning with file-size and directory guards
- provider-style token patterns for common leak shapes
- entropy scoring for unknown token formats
- MCP and agent config inspection for embedded secrets, auto-approval, and permission bypasses
- SARIF output for GitHub code scanning and CI systems
- OpenAPI, machine-readable tool docs, SDK examples, and a small stdio MCP server
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

SARIF output:

```powershell
go run ./cmd/repoguard -path samples/demo -format sarif -fail-on none > repoguard.sarif
```

Fail a pipeline when warnings or errors are present:

```powershell
go run ./cmd/repoguard -path . -fail-on warn
```

Run the MCP-style stdio server:

```powershell
go run ./cmd/mcp
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
GET  /openapi.json
GET  /api/tools
POST /api/scan
POST /api/scan/sarif
```

`POST /api/scan` accepts:

```json
{
  "files": [
    { "path": "mcp.json", "content": "{ ... }" }
  ]
}
```

## GitHub Action

Use RepoGuard in a workflow after setting up Go:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
    with:
      go-version: '1.26.x'
  - uses: kamilch1k/repoguard@main
    with:
      path: .
      fail-on: error
      sarif-file: repoguard.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: repoguard.sarif
```

## Agent-First Surfaces

- CLI: `repoguard -path . -format sarif -fail-on error`
- HTTP: `POST /api/scan` and `POST /api/scan/sarif`
- OpenAPI: `docs/openapi.json` and `GET /openapi.json`
- Tool manifest: `docs/agent-tools.json` and `GET /api/tools`
- SDK examples: `examples/sdk/go` and `examples/sdk/typescript`
- MCP-style stdio tool server: `cmd/mcp`, exposing `repoguard_scan_payload`

## Rule Families

| Rule | Severity | Detector | Meaning |
| --- | --- | --- | --- |
| `RG001`-`RG005` | error | provider-pattern | Known provider-shaped credentials and private key blocks |
| `RG101` | warn | config-keyword | Sensitive assignments such as token or secret values |
| `RG102` | error | env-file | Sensitive value committed in a non-example `.env` file |
| `RG201` | warn | entropy | High-entropy token-like values |
| `RG301` | error | mcp-config | MCP JSON embeds a credential-like environment value |
| `RG302` | error | agent-config | Agent config bypasses permission checks or enables dangerous tools |
| `RG303` | warn | mcp-supply-chain | MCP server executes an unpinned package through `npx`/`uvx` |
| `RG304` | error/warn | github-actions | Workflow grants `write-all` or sensitive token-minting permissions |
| `RG305` | warn | agent-config | Agent config auto-approves tools or commands |

## Project Layout

```text
cmd/repoguard        CLI entrypoint with text, JSON, and SARIF output
cmd/api              HTTP API entrypoint
cmd/mcp              stdio MCP-style tool server
internal/scanner     rules, entropy, SARIF, MCP/agent inspection, path scanner
internal/httpapi     HTTP handlers, OpenAPI/tool docs, endpoint tests
examples/sdk         Go and TypeScript client examples
samples/demo         synthetic fixtures that are safe to publish
docs                 testing notes, OpenAPI, agent manifest, LinkedIn copy
```

## Security

The sample data is synthetic. RepoGuard redacts findings in reports and does not need any external credentials.
