package httpapi

func ToolManifest() map[string]any {
	return map[string]any{
		"name":        "repoguard",
		"description": "Repository security scanner for secrets, risky env files, MCP configs, agent permissions, and GitHub Actions permissions.",
		"commands": []map[string]any{
			{
				"name":        "scan_path",
				"description": "Scan a local repository path with text, JSON, or SARIF output.",
				"example":     "repoguard -path . -format sarif -fail-on error",
			},
		},
		"http": map[string]any{
			"health":       "GET /health",
			"scan":         "POST /api/scan",
			"scanSarif":    "POST /api/scan/sarif",
			"openapi":      "GET /openapi.json",
			"toolManifest": "GET /api/tools",
		},
		"mcp": map[string]any{
			"command": "repoguard-mcp",
			"tools":   []string{"repoguard_scan_payload"},
		},
	}
}

func OpenAPI() map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "RepoGuard API",
			"version":     "0.2.0",
			"description": "Agent-first repository security scanner for secrets, MCP configs, agent permissions, and SARIF reporting.",
		},
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"operationId": "getHealth",
					"responses": map[string]any{
						"200": map[string]any{"description": "Service status"},
					},
				},
			},
			"/api/tools": map[string]any{
				"get": map[string]any{
					"operationId": "getToolManifest",
					"responses": map[string]any{
						"200": map[string]any{"description": "Machine-readable tool manifest"},
					},
				},
			},
			"/api/scan": map[string]any{
				"post": map[string]any{
					"operationId": "scanFiles",
					"requestBody": scanRequestBody(),
					"responses": map[string]any{
						"200": map[string]any{"description": "Scan completed without error-severity findings"},
						"422": map[string]any{"description": "Scan completed with error-severity findings"},
					},
				},
			},
			"/api/scan/sarif": map[string]any{
				"post": map[string]any{
					"operationId": "scanFilesSarif",
					"requestBody": scanRequestBody(),
					"responses": map[string]any{
						"200": map[string]any{"description": "SARIF report without error-severity findings"},
						"422": map[string]any{"description": "SARIF report with error-severity findings"},
					},
				},
			},
		},
	}
}

func scanRequestBody() map[string]any {
	return map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{
					"type":     "object",
					"required": []string{"files"},
					"properties": map[string]any{
						"files": map[string]any{
							"type": "array",
							"items": map[string]any{
								"type":     "object",
								"required": []string{"path", "content"},
								"properties": map[string]any{
									"path":    map[string]any{"type": "string"},
									"content": map[string]any{"type": "string"},
								},
							},
						},
						"config": map[string]any{"type": "object"},
					},
				},
			},
		},
	}
}
