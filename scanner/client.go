package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RegisterAssets uploads a slice of AuditResults to the central QuarkShield backend server
func RegisterAssets(serverURL string, assets []AuditResult) error {
	payload, err := json.Marshal(assets)
	if err != nil {
		return fmt.Errorf("failed to serialize scan findings: %v", err)
	}

	url := fmt.Sprintf("%s/api/assets", serverURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// 10 second timeout for network scans
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to QuarkShield server at %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
