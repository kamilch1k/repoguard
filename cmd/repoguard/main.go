package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamilch1k/repoguard/internal/scanner"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("repoguard", flag.ContinueOnError)
	flags.SetOutput(stderr)

	path := flags.String("path", ".", "path to scan")
	format := flags.String("format", "text", "output format: text, json, or sarif")
	failOn := flags.String("fail-on", "error", "minimum finding severity that fails: none, info, warn, error")
	maxFileBytes := flags.Int64("max-file-bytes", scanner.DefaultConfig().MaxFileBytes, "maximum text file size to scan")
	entropyThreshold := flags.Float64("entropy-threshold", scanner.DefaultConfig().EntropyThreshold, "minimum Shannon entropy for token-like findings")
	enableEntropy := flags.Bool("entropy", true, "enable high-entropy token detection")

	if err := flags.Parse(args); err != nil {
		return 64
	}

	threshold, err := scanner.ParseSeverity(*failOn)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 64
	}

	report, err := scanner.ScanPath(*path, scanner.Config{
		MaxFileBytes:     *maxFileBytes,
		EntropyThreshold: *entropyThreshold,
		EnableEntropy:    *enableEntropy,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 65
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			_, _ = fmt.Fprintf(stderr, "write json: %v\n", err)
			return 65
		}
	case "sarif":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scanner.ToSARIF(report)); err != nil {
			_, _ = fmt.Fprintf(stderr, "write sarif: %v\n", err)
			return 65
		}
	case "text":
		writeText(stdout, report)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown -format %q\n", *format)
		return 64
	}

	if threshold != "" && hasFindingAtLeast(report, threshold) {
		return 2
	}
	return 0
}

func writeText(writer io.Writer, report scanner.Report) {
	_, _ = fmt.Fprintf(
		writer,
		"files=%d errors=%d warnings=%d infos=%d\n",
		report.Summary.FilesScanned,
		report.Summary.Errors,
		report.Summary.Warnings,
		report.Summary.Infos,
	)
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(
			writer,
			"%s:%d:%d [%s] %s %s (%s)\n",
			finding.Path,
			finding.Line,
			finding.Column,
			finding.Severity,
			finding.RuleID,
			finding.Reason,
			finding.Detector,
		)
	}
}

func hasFindingAtLeast(report scanner.Report, threshold scanner.Severity) bool {
	for _, finding := range report.Findings {
		if scanner.SeverityAtLeast(finding.Severity, threshold) {
			return true
		}
	}
	return false
}
