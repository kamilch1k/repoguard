# Testing Guide

Run the full automated suite:

```powershell
go test ./...
```

Run the CLI against safe synthetic fixtures:

```powershell
go run ./cmd/repoguard -path samples/demo -fail-on none
```

Expected output includes `RG101`, `RG201`, and `RG301` findings.

Generate SARIF:

```powershell
go run ./cmd/repoguard -path samples/demo -format sarif -fail-on none > repoguard.sarif
```

Run the MCP-style stdio server smoke:

```powershell
'{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | go run ./cmd/mcp
```

Run the API:

```powershell
go run ./cmd/api -addr :8080
```

Scan the JSON payload fixture:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/scan -ContentType application/json -InFile samples/demo/api-scan.json
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/scan/sarif -ContentType application/json -InFile samples/demo/api-scan.json
Invoke-RestMethod -Uri http://localhost:8080/openapi.json
Invoke-RestMethod -Uri http://localhost:8080/api/tools
```

The API returns `422` when error-severity findings are present and `200` when a scan only has warnings or no findings.
