package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d with %s", recorder.Code, recorder.Body.String())
	}

	var report scanner.Report
	if err := json.NewDecoder(recorder.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Summary.Warnings == 0 {
		t.Fatalf("expected warnings, got %#v", report)
	}
}

func TestScanSARIPEndpointReportsFindings(t *testing.T) {
	handler := NewHandler()
	body, err := json.Marshal(scanRequest{
		Files: []scanner.FileInput{
			{Path: ".env", Content: "OPENAI_API_KEY=" + "sk-" + strings.Repeat("A", 24)},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/scan/sarif", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d with %s", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"version":"2.1.0"`)) {
		t.Fatalf("expected SARIF body, got %s", recorder.Body.String())
	}
}

func TestToolDocsEndpoints(t *testing.T) {
	handler := NewHandler()
	for _, path := range []string{"/openapi.json", "/api/tools"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d", path, recorder.Code)
		}
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
