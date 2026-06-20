package scanner

import (
	"strings"
	"testing"
)

func TestDetectsProviderPatternsWithoutLeakingFullFixture(t *testing.T) {
	aws := "AKIA" + strings.Repeat("A", 16)
	gh := "ghp_" + strings.Repeat("B", 24)
	openai := "sk-" + strings.Repeat("C", 24)

	report := ScanFiles([]FileInput{{
		Path:    "app.env",
		Content: "AWS_KEY=" + aws + "\nGITHUB_TOKEN=" + gh + "\nOPENAI_API_KEY=" + openai,
	}}, Config{EnableEntropy: false})

	if report.Summary.Errors < 3 {
		t.Fatalf("expected provider findings, got %#v", report)
	}
	for _, finding := range report.Findings {
		if strings.Contains(finding.Snippet, aws) || strings.Contains(finding.Snippet, gh) || strings.Contains(finding.Snippet, openai) {
			t.Fatalf("finding leaked full secret in snippet: %#v", finding)
		}
	}
}

func TestDetectsMCPEmbeddedEnvSecret(t *testing.T) {
	report := ScanFiles([]FileInput{{
		Path: "mcp.json",
		Content: `{
  "mcpServers": {
    "github": {
      "command": "node",
      "env": {
        "GITHUB_TOKEN": "R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4"
      }
    }
  }
}`,
	}}, Config{EnableEntropy: false})

	if report.Summary.Errors != 1 {
		t.Fatalf("expected one MCP config error, got %#v", report)
	}
	if report.Findings[0].RuleID != "RG301" {
		t.Fatalf("expected RG301, got %#v", report.Findings[0])
	}
}

func TestDetectsAgentAndMCPConfigRisks(t *testing.T) {
	report := ScanFiles([]FileInput{
		{
			Path: ".mcp.json",
			Content: `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4"
      }
    }
  },
  "autoApprove": ["shell"],
  "dangerouslySkipPermissions": true
}`,
		},
		{
			Path: ".github/workflows/ci.yml",
			Content: `name: ci
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
`,
		},
		{
			Path:    ".env",
			Content: "SERVICE_TOKEN=R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4\n",
		},
	}, Config{EnableEntropy: false})

	want := map[string]bool{
		"RG102": false,
		"RG301": false,
		"RG302": false,
		"RG303": false,
		"RG304": false,
		"RG305": false,
	}
	for _, finding := range report.Findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for ruleID, seen := range want {
		if !seen {
			t.Fatalf("expected %s finding, got %#v", ruleID, report.Findings)
		}
	}
}

func TestEntropyDetectorFindsTokenLikeValue(t *testing.T) {
	report := ScanFiles([]FileInput{{
		Path:    "settings.json",
		Content: `{"sessionSeed":"Az9_qLm72PqR8vX4sN0kTy6bW3dEfGhJ"}`,
	}}, Config{EnableEntropy: true, EntropyThreshold: 3.5})

	if report.Summary.Warnings == 0 {
		t.Fatalf("expected entropy warning, got %#v", report)
	}
}

func TestPlaceholdersAreIgnored(t *testing.T) {
	report := ScanFiles([]FileInput{{
		Path:    ".env.example",
		Content: "API_KEY=changeme-placeholder-token",
	}}, Config{EnableEntropy: true})

	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings for placeholders, got %#v", report.Findings)
	}
}
