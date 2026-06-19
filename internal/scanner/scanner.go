package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9_+=/@.-]{24,}`)

func ScanPath(root string, config Config) (Report, error) {
	config = normalizeConfig(config)

	var inputs []FileInput
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > config.MaxFileBytes || !looksTextual(path) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		inputs = append(inputs, FileInput{
			Path:    filepath.ToSlash(rel),
			Content: string(content),
		})
		return nil
	})
	if err != nil {
		return Report{}, fmt.Errorf("scan path: %w", err)
	}

	return ScanFiles(inputs, config), nil
}

func ScanFiles(files []FileInput, config Config) Report {
	config = normalizeConfig(config)

	report := Report{}
	rules := DefaultRules()
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	for _, file := range files {
		report.Summary.FilesScanned++
		scanContent(&report, file, rules, config)
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		left := report.Findings[i]
		right := report.Findings[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.RuleID < right.RuleID
	})

	return report
}

func scanContent(report *Report, file FileInput, rules []Rule, config Config) {
	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringIndex(file.Content, -1)
		for _, match := range matches {
			value := file.Content[match[0]:match[1]]
			if isPlaceholder(value) {
				continue
			}
			line, column := position(file.Content, match[0])
			report.add(Finding{
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Path:     file.Path,
				Line:     line,
				Column:   column,
				Detector: rule.Detector,
				Snippet:  redact(value),
				Reason:   rule.Reason,
			})
		}
	}

	scanMCPConfig(report, file)

	if config.EnableEntropy {
		for _, match := range entropyCandidate.FindAllStringIndex(file.Content, -1) {
			value := file.Content[match[0]:match[1]]
			if isPlaceholder(value) || !hasSecretShape(value) {
				continue
			}
			entropy := ShannonEntropy(value)
			if entropy < config.EntropyThreshold {
				continue
			}
			line, column := position(file.Content, match[0])
			report.add(Finding{
				RuleID:   "RG201",
				Severity: SeverityWarn,
				Path:     file.Path,
				Line:     line,
				Column:   column,
				Detector: "entropy",
				Snippet:  redact(value),
				Reason:   "High-entropy token-like value",
				Entropy:  entropy,
			})
		}
	}
}

func scanMCPConfig(report *Report, file FileInput) {
	if !strings.Contains(file.Content, "mcpServers") && !strings.Contains(strings.ToLower(file.Path), "mcp") {
		return
	}

	var document any
	if err := json.Unmarshal([]byte(file.Content), &document); err != nil {
		return
	}
	walkJSON(report, file, document, nil)
}

func walkJSON(report *Report, file FileInput, value any, path []string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			walkJSON(report, file, child, append(path, key))
		}
	case []any:
		for _, child := range typed {
			walkJSON(report, file, child, path)
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

func normalizeConfig(config Config) Config {
	defaults := DefaultConfig()
	if config.MaxFileBytes <= 0 {
		config.MaxFileBytes = defaults.MaxFileBytes
	}
	if config.EntropyThreshold <= 0 {
		config.EntropyThreshold = defaults.EntropyThreshold
	}
	return config
}

func shouldSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".hg", ".svn", "node_modules", "bin", "obj", "dist", "coverage", "go-build-cache", ".next", "vendor":
		return true
	default:
		return false
	}
}

func looksTextual(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".cs", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".md", ".ps1", ".sh", ".sql", ".xml", ".config", ".ini", ".properties":
		return true
	default:
		base := strings.ToLower(filepath.Base(path))
		return strings.Contains(base, ".env") || base == "dockerfile" || base == "makefile"
	}
}

func position(content string, offset int) (int, int) {
	line := 1
	column := 1
	for i, r := range content {
		if i >= offset {
			break
		}
		if r == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}
	return line, column
}

func findValuePosition(content string, value string) (int, int) {
	index := strings.Index(content, value)
	if index < 0 {
		return 1, 1
	}
	return position(content, index)
}

func redact(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 10 {
		return "[redacted]"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func isPlaceholder(value string) bool {
	normalized := strings.ToLower(value)
	placeholders := []string{"example", "placeholder", "changeme", "replace_me", "dummy", "fake", "sample"}
	for _, placeholder := range placeholders {
		if strings.Contains(normalized, placeholder) {
			return true
		}
	}
	return false
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	return strings.Contains(normalized, "TOKEN") ||
		strings.Contains(normalized, "SECRET") ||
		strings.Contains(normalized, "PASSWORD") ||
		strings.Contains(normalized, "API_KEY") ||
		strings.Contains(normalized, "PRIVATE_KEY")
}

func hasSecretShape(value string) bool {
	if len(value) < 24 {
		return false
	}
	var hasLetter, hasDigit, hasSymbol bool
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	return hasLetter && hasDigit && (hasSymbol || len(value) >= 32)
}

func SeverityAtLeast(value Severity, threshold Severity) bool {
	rank := map[Severity]int{
		SeverityInfo:  1,
		SeverityWarn:  2,
		SeverityError: 3,
	}
	return rank[value] >= rank[threshold]
}

func ParseSeverity(value string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return "", nil
	case "info":
		return SeverityInfo, nil
	case "warn", "warning":
		return SeverityWarn, nil
	case "error":
		return SeverityError, nil
	default:
		return "", errors.New("severity must be one of none, info, warn, or error")
	}
}
