package scanner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var envAssignmentPattern = regexp.MustCompile(`(?im)^\s*([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*=\s*["']?([^"'\s#]{8,})`)

func scanAgentAndMCPConfig(report *Report, file FileInput) {
	scanEnvFile(report, file)
	scanGitHubActionsPermissions(report, file)
	scanDangerousAgentText(report, file)

	if !looksLikeAgentConfig(file) {
		return
	}

	var document any
	if err := json.Unmarshal([]byte(file.Content), &document); err != nil {
		return
	}
	walkAgentJSON(report, file, document, nil)
}

func scanEnvFile(report *Report, file FileInput) {
	base := strings.ToLower(filepath.Base(file.Path))
	if !strings.Contains(base, ".env") || strings.Contains(base, "example") || strings.Contains(base, "sample") {
		return
	}
	for _, match := range envAssignmentPattern.FindAllStringSubmatchIndex(file.Content, -1) {
		value := file.Content[match[4]:match[5]]
		if isPlaceholder(value) {
			continue
		}
		line, column := position(file.Content, match[0])
		report.add(Finding{
			RuleID:   "RG102",
			Severity: SeverityError,
			Path:     file.Path,
			Line:     line,
			Column:   column,
			Detector: "env-file",
			Snippet:  redact(value),
			Reason:   "Sensitive value is committed in an environment file",
		})
	}
}

func scanGitHubActionsPermissions(report *Report, file FileInput) {
	path := strings.ToLower(filepath.ToSlash(file.Path))
	if !strings.Contains(path, ".github/workflows/") {
		return
	}

	lines := strings.Split(file.Content, "\n")
	for index, line := range lines {
		normalized := strings.ToLower(strings.TrimSpace(line))
		switch {
		case normalized == "permissions: write-all":
			report.add(Finding{
				RuleID:   "RG304",
				Severity: SeverityError,
				Path:     file.Path,
				Line:     index + 1,
				Column:   1,
				Detector: "github-actions",
				Snippet:  "permissions: write-all",
				Reason:   "GitHub Actions workflow grants broad write permissions",
			})
		case strings.HasPrefix(normalized, "id-token: write"):
			report.add(Finding{
				RuleID:   "RG304",
				Severity: SeverityWarn,
				Path:     file.Path,
				Line:     index + 1,
				Column:   1,
				Detector: "github-actions",
				Snippet:  strings.TrimSpace(line),
				Reason:   "GitHub Actions workflow grants OIDC token minting permission; confirm it is required",
			})
		}
	}
}

func scanDangerousAgentText(report *Report, file FileInput) {
	dangerousPatterns := []struct {
		Needle string
		RuleID string
		Reason string
	}{
		{"--dangerously-skip-permissions", "RG302", "Agent command bypasses interactive permission checks"},
		{"dangerouslySkipPermissions", "RG302", "Agent configuration bypasses interactive permission checks"},
		{"allowDangerous", "RG302", "Agent configuration enables dangerous tool access"},
		{"autoApprove", "RG305", "Agent configuration auto-approves tools or commands"},
		{"alwaysAllow", "RG305", "Agent configuration always allows tools or commands"},
	}
	for _, pattern := range dangerousPatterns {
		offset := strings.Index(file.Content, pattern.Needle)
		if offset < 0 {
			continue
		}
		line, column := position(file.Content, offset)
		severity := SeverityWarn
		if pattern.RuleID == "RG302" {
			severity = SeverityError
		}
		report.add(Finding{
			RuleID:   pattern.RuleID,
			Severity: severity,
			Path:     file.Path,
			Line:     line,
			Column:   column,
			Detector: "agent-config",
			Snippet:  pattern.Needle,
			Reason:   pattern.Reason,
		})
	}
}

func walkAgentJSON(report *Report, file FileInput, value any, path []string) {
	switch typed := value.(type) {
	case map[string]any:
		command, _ := typed["command"].(string)
		args := stringList(typed["args"])
		if command != "" {
			scanMCPCommand(report, file, command, args)
		}
		for key, child := range typed {
			walkAgentJSON(report, file, child, append(path, key))
		}
	case []any:
		for _, child := range typed {
			walkAgentJSON(report, file, child, path)
		}
	case string:
		key := ""
		if len(path) > 0 {
			key = path[len(path)-1]
		}
		if isSensitiveKey(key) && strings.TrimSpace(typed) != "" && !isPlaceholder(typed) {
			line, column := findValuePosition(file.Content, typed)
			report.add(Finding{
				RuleID:   "RG301",
				Severity: SeverityError,
				Path:     file.Path,
				Line:     line,
				Column:   column,
				Detector: "mcp-config",
				Snippet:  redact(typed),
				Reason:   "MCP configuration embeds a credential-like environment value",
			})
		}
	}
}

func scanMCPCommand(report *Report, file FileInput, command string, args []string) {
	lowerCommand := strings.ToLower(command)
	joined := strings.Join(args, " ")
	lowerJoined := strings.ToLower(joined)
	if lowerCommand != "npx" && lowerCommand != "uvx" && !strings.Contains(lowerJoined, " npx ") {
		return
	}
	if strings.Contains(lowerJoined, "--from") || hasPinnedPackage(args) {
		return
	}
	line, column := findValuePosition(file.Content, command)
	report.add(Finding{
		RuleID:   "RG303",
		Severity: SeverityWarn,
		Path:     file.Path,
		Line:     line,
		Column:   column,
		Detector: "mcp-supply-chain",
		Snippet:  fmt.Sprintf("%s %s", command, joined),
		Reason:   "MCP server command installs or executes an unpinned package",
	})
}

func looksLikeAgentConfig(file FileInput) bool {
	path := strings.ToLower(file.Path)
	content := strings.ToLower(file.Content)
	return strings.Contains(content, "mcpservers") ||
		strings.Contains(path, "mcp") ||
		strings.Contains(path, "claude") ||
		strings.Contains(path, "agent") ||
		strings.Contains(path, ".cursor")
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func hasPinnedPackage(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "/") {
			lastSlash := strings.LastIndex(arg, "/")
			return strings.Contains(arg[lastSlash+1:], "@")
		}
		return strings.Contains(arg, "@")
	}
	return false
}
