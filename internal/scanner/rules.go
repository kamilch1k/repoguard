package scanner

import "regexp"

type Rule struct {
	ID       string
	Reason   string
	Detector string
	Severity Severity
	Pattern  *regexp.Regexp
}

func DefaultRules() []Rule {
	return []Rule{
		{
			ID:       "RG001",
			Reason:   "AWS access key-shaped value",
			Detector: "provider-pattern",
			Severity: SeverityError,
			Pattern:  regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		},
		{
			ID:       "RG002",
			Reason:   "GitHub personal access token-shaped value",
			Detector: "provider-pattern",
			Severity: SeverityError,
			Pattern:  regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
		},
		{
			ID:       "RG003",
			Reason:   "OpenAI-style API key-shaped value",
			Detector: "provider-pattern",
			Severity: SeverityError,
			Pattern:  regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
		},
		{
			ID:       "RG004",
			Reason:   "Slack token-shaped value",
			Detector: "provider-pattern",
			Severity: SeverityError,
			Pattern:  regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		},
		{
			ID:       "RG005",
			Reason:   "Private key block marker",
			Detector: "provider-pattern",
			Severity: SeverityError,
			Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----`),
		},
		{
			ID:       "RG101",
			Reason:   "Sensitive configuration assignment",
			Detector: "config-keyword",
			Severity: SeverityWarn,
			Pattern:  regexp.MustCompile(`(?im)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([A-Za-z0-9_+=/@:.,-]{12,})`),
		},
	}
}
