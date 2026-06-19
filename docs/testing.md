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

Run the API:

```powershell
go run ./cmd/api -addr :8080
```

Scan the JSON payload fixture:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/scan -ContentType application/json -InFile samples/demo/api-scan.json
```

The API returns `422` when error-severity findings are present and `200` when a scan only has warnings or no findings.
