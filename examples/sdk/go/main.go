package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type scanRequest struct {
	Files []fileInput `json:"files"`
}

type fileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func main() {
	payload := scanRequest{
		Files: []fileInput{
			{Path: ".env", Content: "OPENAI_API_KEY=" + "sk-" + strings.Repeat("A", 24)},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	response, err := http.Post("http://127.0.0.1:8080/api/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	fmt.Println("status:", response.Status)
}
