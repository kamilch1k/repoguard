package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kamilch1k/repoguard/internal/scanner"
)

type scanRequest struct {
	Files  []scanner.FileInput `json:"files"`
	Config *scanner.Config     `json:"config,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("POST /api/scan", scan)
	return mux
}

func health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "service": "repoguard"})
}

func scan(writer http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	request.Body = http.MaxBytesReader(writer, request.Body, 4<<20)

	var payload scanRequest
	if err := decodeJSON(request, &payload); err != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	if len(payload.Files) == 0 {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "files must not be empty"})
		return
	}

	config := scanner.DefaultConfig()
	if payload.Config != nil {
		config = *payload.Config
	}
	report := scanner.ScanFiles(payload.Files, config)
	status := http.StatusOK
	if report.Summary.Errors > 0 {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(writer, status, report)
}

func decodeJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			return errors.New("request body too large")
		}
		return err
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
