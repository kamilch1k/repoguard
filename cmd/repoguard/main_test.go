package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportsFindingsAndFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "REPOGUARD_TOKEN=R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-path", dir, "-fail-on", "warn"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit 2, got %d; stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "files=1") || !strings.Contains(output, "RG101") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunSupportsJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "nothing sensitive here\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-path", dir, "-format", "json", "-fail-on", "none"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"filesScanned\": 1") {
		t.Fatalf("unexpected json: %s", stdout.String())
	}
}

func TestRunSupportsSARIFOutput(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "OPENAI_API_KEY=sk-"+strings.Repeat("A", 24)+"\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-path", dir, "-format", "sarif", "-fail-on", "none"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, `"version": "2.1.0"`) || !strings.Contains(output, `"ruleId": "RG003"`) {
		t.Fatalf("unexpected sarif: %s", output)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
