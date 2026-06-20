package scanner

import "strings"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifText       `json:"shortDescription"`
	FullDescription  sarifText       `json:"fullDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       sarifProperties `json:"properties"`
}

type sarifProperties struct {
	Tags []string `json:"tags"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type ruleMetadata struct {
	Name        string
	Description string
	Tags        []string
}

var ruleCatalog = map[string]ruleMetadata{
	"RG001": {"aws-access-key", "AWS access key-shaped value", []string{"security", "secret", "aws"}},
	"RG002": {"github-token", "GitHub personal access token-shaped value", []string{"security", "secret", "github"}},
	"RG003": {"openai-api-key", "OpenAI-style API key-shaped value", []string{"security", "secret", "openai"}},
	"RG004": {"slack-token", "Slack token-shaped value", []string{"security", "secret", "slack"}},
	"RG005": {"private-key", "Private key block marker", []string{"security", "secret", "private-key"}},
	"RG101": {"sensitive-config-assignment", "Sensitive configuration assignment", []string{"security", "configuration", "secret"}},
	"RG102": {"committed-env-secret", "Sensitive value is committed in an environment file", []string{"security", "configuration", "env"}},
	"RG201": {"high-entropy-token", "High-entropy token-like value", []string{"security", "secret", "entropy"}},
	"RG301": {"mcp-embedded-secret", "MCP configuration embeds a credential-like environment value", []string{"security", "mcp", "agent"}},
	"RG302": {"agent-dangerous-permission", "Agent configuration enables dangerous or non-interactive permission bypass", []string{"security", "mcp", "agent", "permissions"}},
	"RG303": {"mcp-unpinned-package", "MCP server command installs or executes an unpinned package", []string{"security", "mcp", "supply-chain"}},
	"RG304": {"github-actions-write-all", "GitHub Actions workflow grants broad write permissions", []string{"security", "github-actions", "permissions"}},
	"RG305": {"agent-auto-approve", "Agent configuration auto-approves tools or commands", []string{"security", "agent", "permissions"}},
}

func ToSARIF(report Report) sarifLog {
	seenRules := map[string]bool{}
	var rules []sarifRule
	for _, finding := range report.Findings {
		if seenRules[finding.RuleID] {
			continue
		}
		seenRules[finding.RuleID] = true
		metadata := metadataFor(finding.RuleID, finding.Reason)
		rules = append(rules, sarifRule{
			ID:               finding.RuleID,
			Name:             metadata.Name,
			ShortDescription: sarifText{Text: metadata.Description},
			FullDescription:  sarifText{Text: metadata.Description},
			HelpURI:          "https://github.com/kamilch1k/repoguard#rule-families",
			Properties:       sarifProperties{Tags: metadata.Tags},
		})
	}

	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		results = append(results, sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifText{Text: finding.Reason + " (" + finding.Snippet + ")"},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: strings.ReplaceAll(finding.Path, "\\", "/")},
						Region: sarifRegion{
							StartLine:   maxInt(1, finding.Line),
							StartColumn: maxInt(1, finding.Column),
						},
					},
				},
			},
		})
	}

	return sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{Driver: sarifDriver{
					Name:           "RepoGuard",
					InformationURI: "https://github.com/kamilch1k/repoguard",
					Rules:          rules,
				}},
				Results: results,
			},
		},
	}
}

func metadataFor(ruleID string, fallback string) ruleMetadata {
	if metadata, ok := ruleCatalog[ruleID]; ok {
		return metadata
	}
	return ruleMetadata{
		Name:        strings.ToLower(ruleID),
		Description: fallback,
		Tags:        []string{"security"},
	}
}

func sarifLevel(severity Severity) string {
	switch severity {
	case SeverityError:
		return "error"
	case SeverityWarn:
		return "warning"
	default:
		return "note"
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
