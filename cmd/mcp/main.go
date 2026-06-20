package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kamilch1k/repoguard/internal/scanner"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type scanArguments struct {
	Files  []scanner.FileInput `json:"files"`
	Config *scanner.Config     `json:"config,omitempty"`
	Format string              `json:"format,omitempty"`
}

func main() {
	scannerInput := bufio.NewScanner(os.Stdin)
	for scannerInput.Scan() {
		var request rpcRequest
		if err := json.Unmarshal(scannerInput.Bytes(), &request); err != nil {
			write(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: err.Error()}})
			continue
		}
		write(handle(request))
	}
}

func handle(request rpcRequest) rpcResponse {
	switch request.Method {
	case "initialize":
		return ok(request.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "repoguard",
				"version": "0.2.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		})
	case "tools/list":
		return ok(request.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "repoguard_scan_payload",
					"description": "Scan submitted files for secrets, risky env files, MCP configs, agent permission bypasses, and GitHub Actions permission risks.",
					"inputSchema": map[string]any{
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
							"format": map[string]any{"type": "string", "enum": []string{"json", "sarif"}},
						},
					},
				},
			},
		})
	case "tools/call":
		return callTool(request)
	default:
		return fail(request.ID, -32601, "method not found")
	}
}

func callTool(request rpcRequest) rpcResponse {
	var params toolCallParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		return fail(request.ID, -32602, err.Error())
	}
	if params.Name != "repoguard_scan_payload" {
		return fail(request.ID, -32602, "unknown tool")
	}
	var args scanArguments
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		return fail(request.ID, -32602, err.Error())
	}
	if len(args.Files) == 0 {
		return fail(request.ID, -32602, "files must not be empty")
	}
	config := scanner.DefaultConfig()
	if args.Config != nil {
		config = *args.Config
	}
	report := scanner.ScanFiles(args.Files, config)
	payload := any(report)
	if args.Format == "sarif" {
		payload = scanner.ToSARIF(report)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fail(request.ID, -32603, err.Error())
	}
	return ok(request.ID, map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": string(encoded)},
		},
		"isError": report.Summary.Errors > 0,
	})
}

func ok(id any, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func fail(id any, code int, message string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

func write(response rpcResponse) {
	payload, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintln(os.Stdout, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"marshal response"}}`)
		return
	}
	fmt.Fprintln(os.Stdout, string(payload))
}
