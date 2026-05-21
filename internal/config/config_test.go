package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsEnterpriseMode_Placeholder(t *testing.T) {
	APIKey = "{{API_KEY}}"
	if IsEnterpriseMode() {
		t.Error("placeholder should not be enterprise mode")
	}
}

func TestIsEnterpriseMode_Empty(t *testing.T) {
	APIKey = ""
	if IsEnterpriseMode() {
		t.Error("empty should not be enterprise mode")
	}
}

func TestIsEnterpriseMode_Valid(t *testing.T) {
	APIKey = "sk-test-123456"
	defer func() { APIKey = "{{API_KEY}}" }()
	if !IsEnterpriseMode() {
		t.Error("valid API key should be enterprise mode")
	}
}

func TestIsPlaceholder(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"{{API_KEY}}", true},
		{"{{CUSTOMER_ID}}", true},
		{"real-value", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isPlaceholder(tt.input); got != tt.want {
			t.Errorf("isPlaceholder(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSaveAndLoad(t *testing.T) {
	// This test exercises the ConfigFile JSON marshal/unmarshal contract
	// against a plain temp file — it does NOT cover save()/ConfigFilePath(),
	// which depend on $HOME resolution and (on Windows) elevation checks.
	// See config_nonint_test.go for tests that go through those helpers.
	tmpDir := t.TempDir()
	tmpConfigPath := filepath.Join(tmpDir, "config.json")

	cfg := &ConfigFile{
		CustomerID:         "test-customer",
		APIEndpoint:        "https://api.example.com",
		APIKey:             "sk-test-key",
		ScanFrequencyHours: "4",
		SearchDirs:         []string{"/tmp", "/opt/code"},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpConfigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Read it back
	readData, err := os.ReadFile(tmpConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var loaded ConfigFile
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatal(err)
	}

	if loaded.CustomerID != "test-customer" {
		t.Errorf("customer_id: expected test-customer, got %s", loaded.CustomerID)
	}
	if loaded.APIKey != "sk-test-key" {
		t.Errorf("api_key: expected sk-test-key, got %s", loaded.APIKey)
	}
	if len(loaded.SearchDirs) != 2 {
		t.Errorf("search_dirs: expected 2 dirs, got %d", len(loaded.SearchDirs))
	}
}

func TestConfigFile_JSON(t *testing.T) {
	cfg := ConfigFile{
		CustomerID: "cust-123",
		APIKey:     "key-456",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["customer_id"] != "cust-123" {
		t.Error("customer_id not serialized correctly")
	}
	// Empty fields should be omitted
	if _, ok := parsed["api_endpoint"]; ok {
		t.Error("empty api_endpoint should be omitted")
	}
}
