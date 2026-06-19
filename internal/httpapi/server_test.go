package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kamilch1k/repoguard/internal/scanner"
)

func TestScanEndpointReportsFindings(t *testing.T) {
	handler := NewHandler()
	body, err := json.Marshal(scanRequest{
		Files: []scanner.FileInput{
			{Path: ".env", Content: "REPOGUARD_TOKEN=R3pQ9vLm7Ks2Qa8Zp0Nv6Xy4"},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with %s", recorder.Code, recorder.Body.String())
	}

	var report scanner.Report
	if err := json.NewDecoder(recorder.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Summary.Warnings == 0 {
		t.Fatalf("expected warnings, got %#v", report)
	}
}

func TestHealthEndpoint(t *testing.T) {
	handler := NewHandler()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}
