package devicepolicy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const (
	pypiDeviceID = "DEVICE-123"
	pypiKey      = "step_acme-1_uuid"
	pypiURL      = "https://registry.stepsecurity.io/python/simple"
)

func TestParsePyPIPolicy_ValidClientSubsets(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantClients []PyPIClient
		wantURL     string
	}{
		{
			name:        "pip",
			raw:         `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`,
			wantClients: []PyPIClient{PyPIClientPip},
			wantURL:     pypiURL,
		},
		{
			name:        "uv with trailing slash normalization",
			raw:         `{"ecosystem":"pypi","clients":["uv"],"registry_url":"https://registry.stepsecurity.io/python/simple/","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`,
			wantClients: []PyPIClient{PyPIClientUV},
			wantURL:     pypiURL,
		},
		{
			name:        "pip and uv",
			raw:         `{"ecosystem":"pypi","clients":["pip","uv"],"registry_url":"https://tenant.registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`,
			wantClients: []PyPIClient{PyPIClientPip, PyPIClientUV},
			wantURL:     "https://tenant.registry.stepsecurity.io/python/simple",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePyPIPolicy(json.RawMessage(tc.raw), pypiDeviceID)
			if err != nil {
				t.Fatalf("ParsePyPIPolicy() error = %v", err)
			}
			if got.Ecosystem != "pypi" {
				t.Errorf("Ecosystem = %q, want pypi", got.Ecosystem)
			}
			if got.RegistryURL != tc.wantURL {
				t.Errorf("RegistryURL = %q, want %q", got.RegistryURL, tc.wantURL)
			}
			if !slices.Equal(got.Clients, tc.wantClients) {
				t.Errorf("Clients = %v, want %v", got.Clients, tc.wantClients)
			}
			if got.RegistryHost() != strings.TrimPrefix(strings.Split(tc.wantURL, "/python/simple")[0], "https://") {
				t.Errorf("RegistryHost() = %q", got.RegistryHost())
			}
			if got.DeviceToken() != pypiKey+"::dev:"+pypiDeviceID {
				t.Errorf("DeviceToken() did not append the device suffix exactly once")
			}
			for _, client := range []PyPIClient{PyPIClientPip, PyPIClientUV} {
				if got.Selects(client) != slices.Contains(tc.wantClients, client) {
					t.Errorf("Selects(%q) = %v", client, got.Selects(client))
				}
			}
		})
	}
}

func TestParsePyPIPolicy_Rejections(t *testing.T) {
	valid := `{"ecosystem":"pypi","clients":["pip","uv"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`
	tests := []struct {
		name     string
		raw      string
		deviceID string
	}{
		{name: "empty JSON", raw: ``},
		{name: "malformed JSON", raw: `{`},
		{name: "non-object JSON", raw: `[]`},
		{name: "wrong ecosystem", raw: `{"ecosystem":"npm","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "missing ecosystem", raw: `{"clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "missing clients", raw: `{"ecosystem":"pypi","registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "null clients", raw: `{"ecosystem":"pypi","clients":null,"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "empty clients", raw: `{"ecosystem":"pypi","clients":[],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "duplicate client", raw: `{"ecosystem":"pypi","clients":["pip","pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "unsorted clients", raw: `{"ecosystem":"pypi","clients":["uv","pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "unknown client", raw: `{"ecosystem":"pypi","clients":["poetry"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "missing auth", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple"}`},
		{name: "wrong auth scheme", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"basic","api_key":"step_acme-1_uuid"}}`},
		{name: "empty key", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":""}}`},
		{name: "excessive key length", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"` + strings.Repeat("a", 257) + `"}}`},
		{name: "key whitespace", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step key"}}`},
		{name: "key control byte", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step\u0000key"}}`},
		{name: "key non-ASCII", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"stép"}}`},
		{name: "key unsafe character", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step#key"}}`},
		{name: "key already has device suffix", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_key::dev:other"}}`},
		{name: "key already has another source suffix", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_key::gha:run"}}`},
		{name: "empty registry URL", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "non-HTTPS registry URL", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"http://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL userinfo", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://user:secret@registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL query", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple?x=1","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL bare query", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple?","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL fragment", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple#x","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL bare fragment", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple#","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "URL port", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io:443/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "uppercase hostname", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://Registry.StepSecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "invalid hostname", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://-registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "wrong path", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "double trailing slash", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple//","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "escaped path", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python%2fsimple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "unknown top-level field", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"},"extra":true}`},
		{name: "unknown auth field", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid","token":"secret"}}`},
		{name: "duplicate JSON key", raw: `{"ecosystem":"pypi","ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`},
		{name: "duplicate nested JSON key", raw: `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid","api_key":"step_acme-1_uuid"}}`},
		{name: "trailing JSON", raw: valid + ` {}`},
		{name: "trailing data", raw: valid + ` x`},
		{name: "empty device ID", raw: valid, deviceID: " "},
		{name: "excessive device ID", raw: valid, deviceID: strings.Repeat("d", 129)},
		{name: "unsafe device ID", raw: valid, deviceID: "device id"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deviceID := tc.deviceID
			if deviceID == "" {
				deviceID = pypiDeviceID
			}
			_, err := ParsePyPIPolicy(json.RawMessage(tc.raw), deviceID)
			if err == nil {
				t.Fatal("ParsePyPIPolicy() error = nil, want error")
			}
			for _, secret := range []string{pypiKey, "user:secret", "step#key"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("ParsePyPIPolicy() error leaked credential material: %v", err)
				}
			}
		})
	}
}

func TestSafeObservedRegistryURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "expected HTTPS", raw: pypiURL, want: pypiURL},
		{name: "safe HTTP drift", raw: "http://mirror.example/simple", want: "http://mirror.example/simple"},
		{name: "safe port drift", raw: "https://mirror.example:8443/simple", want: "https://mirror.example:8443/simple"},
		{name: "empty", raw: ""},
		{name: "relative", raw: "/python/simple"},
		{name: "non-HTTP scheme", raw: "file://mirror.example/python/simple"},
		{name: "userinfo credential", raw: "https://user:secret@mirror.example/python/simple"},
		{name: "query", raw: "https://mirror.example/python/simple?token=secret"},
		{name: "bare query", raw: "https://mirror.example/python/simple?"},
		{name: "fragment", raw: "https://mirror.example/python/simple#secret"},
		{name: "bare fragment", raw: "https://mirror.example/python/simple#"},
		{name: "control byte", raw: "https://mirror.example/python/\x00simple"},
		{name: "oversized", raw: "https://mirror.example/" + strings.Repeat("a", npmrcMaxRegistryURLBytes)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeObservedRegistryURL(tc.raw); got != tc.want {
				t.Errorf("safeObservedRegistryURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
