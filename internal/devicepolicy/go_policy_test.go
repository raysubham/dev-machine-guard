package devicepolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func validGoPolicyJSON() json.RawMessage {
	return json.RawMessage(`{"ecosystem":"go","registry_url":"https://registry.stepsecurity.io/go","auth":{"scheme":"stepsecurity_device_token","api_key":"tenant-key"}}`)
}

func TestParseGoPolicy(t *testing.T) {
	policy, err := ParseGoPolicy(validGoPolicyJSON(), "device-1")
	if err != nil {
		t.Fatalf("ParseGoPolicy: %v", err)
	}
	if policy.RegistryURL != "https://registry.stepsecurity.io/go" || policy.RegistryHost() != "registry.stepsecurity.io" {
		t.Fatalf("unexpected registry: %#v", policy)
	}
	if got := policy.DeviceToken(); got != "tenant-key::dev:device-1" {
		t.Fatalf("DeviceToken() = %q", got)
	}

	withSlash := json.RawMessage(`{"ecosystem":"go","registry_url":"https://registry.stepsecurity.io/go/","auth":{"scheme":"stepsecurity_device_token","api_key":"tenant-key"}}`)
	policy, err = ParseGoPolicy(withSlash, "device-1")
	if err != nil || policy.RegistryURL != "https://registry.stepsecurity.io/go" {
		t.Fatalf("trailing slash normalization: policy=%#v err=%v", policy, err)
	}
}

func TestParseGoPolicyRejectsInvalidContract(t *testing.T) {
	valid := string(validGoPolicyJSON())
	cases := map[string]string{
		"wrong ecosystem":        strings.Replace(valid, `"go"`, `"pypi"`, 1),
		"unknown field":          strings.Replace(valid, `"ecosystem"`, `"extra":true,"ecosystem"`, 1),
		"duplicate field":        strings.Replace(valid, `"ecosystem":"go"`, `"ecosystem":"go","ecosystem":"go"`, 1),
		"trailing data":          valid + `{}`,
		"wrong auth scheme":      strings.Replace(valid, "stepsecurity_device_token", "basic", 1),
		"empty key":              strings.Replace(valid, "tenant-key", "", 1),
		"suffixed key":           strings.Replace(valid, "tenant-key", "tenant-key::dev:old", 1),
		"unsafe key":             strings.Replace(valid, "tenant-key", "tenant key", 1),
		"wrong path":             strings.Replace(valid, "/go", "/javascript", 1),
		"double trailing slash":  strings.Replace(valid, "/go", "/go//", 1),
		"http":                   strings.Replace(valid, "https://", "http://", 1),
		"uppercase host":         strings.Replace(valid, "registry.stepsecurity.io", "Registry.stepsecurity.io", 1),
		"port":                   strings.Replace(valid, ".io/go", ".io:443/go", 1),
		"userinfo":               strings.Replace(valid, "https://", "https://user@", 1),
		"query":                  strings.Replace(valid, "/go", "/go?q=1", 1),
		"fragment":               strings.Replace(valid, "/go", "/go#x", 1),
		"comma fallback":         strings.Replace(valid, "/go", "/go,direct", 1),
		"pipe fallback":          strings.Replace(valid, "/go", "/go|direct", 1),
		"wrong registry type":    strings.Replace(valid, `"registry_url":"https://registry.stepsecurity.io/go"`, `"registry_url":7`, 1),
		"wrong auth object type": strings.Replace(valid, `"auth":{"scheme":"stepsecurity_device_token","api_key":"tenant-key"}`, `"auth":null`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGoPolicy(json.RawMessage(raw), "device-1"); err == nil {
				t.Fatal("ParseGoPolicy() error = nil")
			}
		})
	}
	for name, deviceID := range map[string]string{"empty": "", "unsafe": "device id", "oversized": strings.Repeat("x", npmrcMaxSerialBytes+1)} {
		t.Run("device "+name, func(t *testing.T) {
			if _, err := ParseGoPolicy(validGoPolicyJSON(), deviceID); err == nil {
				t.Fatal("ParseGoPolicy() error = nil")
			}
		})
	}
}
