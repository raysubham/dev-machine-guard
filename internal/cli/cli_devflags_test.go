package cli

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestParse_RulesFileAndTelemetryOut(t *testing.T) {
	cfg, err := Parse([]string{"send-telemetry", "--rules-file=/tmp/rules.json", "--telemetry-out=/tmp/out.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/tmp/rules.json" {
		t.Errorf("RulesFile = %q", cfg.RulesFile)
	}
	if cfg.TelemetryOutFile != "/tmp/out.json" {
		t.Errorf("TelemetryOutFile = %q", cfg.TelemetryOutFile)
	}
}

func TestParse_DevFlagsSeparateValue(t *testing.T) {
	cfg, err := Parse([]string{"--rules-file", "r.json", "--telemetry-out", "o.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "r.json" || cfg.TelemetryOutFile != "o.json" {
		t.Errorf("got RulesFile=%q TelemetryOutFile=%q", cfg.RulesFile, cfg.TelemetryOutFile)
	}
}

func TestParse_DevFlagsMissingValue(t *testing.T) {
	if _, err := Parse([]string{"--rules-file"}); err == nil {
		t.Error("--rules-file without value should error")
	}
	if _, err := Parse([]string{"--telemetry-out"}); err == nil {
		t.Error("--telemetry-out without value should error")
	}
}

func TestParse_DevFlagsEnvVarFallback(t *testing.T) {
	t.Setenv("STEPSECURITY_RULES_FILE", "/env/rules.json")
	t.Setenv("STEPSECURITY_TELEMETRY_OUT", "/env/out.json")
	cfg, err := Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/env/rules.json" || cfg.TelemetryOutFile != "/env/out.json" {
		t.Errorf("env fallback failed: RulesFile=%q TelemetryOutFile=%q", cfg.RulesFile, cfg.TelemetryOutFile)
	}
}

func TestParse_FlagBeatsEnvVar(t *testing.T) {
	t.Setenv("STEPSECURITY_RULES_FILE", "/env/rules.json")
	cfg, err := Parse([]string{"--rules-file=/flag/rules.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesFile != "/flag/rules.json" {
		t.Errorf("explicit flag should win over env var, got %q", cfg.RulesFile)
	}
}

func TestParse_DevicePolicyFileFlagForms(t *testing.T) {
	t.Setenv("STEPSECURITY_DEVICE_POLICY_FILE", "")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"separate value", []string{"--device-policy-file", "/tmp/policy.json"}, "/tmp/policy.json"},
		{"equals value", []string{"--device-policy-file=/tmp/policy.json"}, "/tmp/policy.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DevicePolicyFile != tc.want {
				t.Errorf("DevicePolicyFile = %q, want %q", cfg.DevicePolicyFile, tc.want)
			}
		})
	}
}

func TestParse_DevicePolicyFileEnvFallbackAndFlagPrecedence(t *testing.T) {
	t.Setenv("STEPSECURITY_DEVICE_POLICY_FILE", "/env/policy.json")
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DevicePolicyFile != "/env/policy.json" {
		t.Errorf("DevicePolicyFile = %q, want env fallback", cfg.DevicePolicyFile)
	}

	cfg, err = Parse([]string{"--device-policy-file=/flag/policy.json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DevicePolicyFile != "/flag/policy.json" {
		t.Errorf("DevicePolicyFile = %q, want explicit flag", cfg.DevicePolicyFile)
	}
}

func TestParse_DevicePolicyFileMissingValue(t *testing.T) {
	t.Setenv("STEPSECURITY_DEVICE_POLICY_FILE", "/tmp/from-env.json")
	for _, args := range [][]string{
		{"--device-policy-file"},
		{"--device-policy-file="},
		{"--device-policy-file", "--json"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) error = nil, want invalid file path", args)
		}
	}
}

func TestParse_DevicePolicyFileHiddenFromHelp(t *testing.T) {
	old := os.Stdout
	file, err := os.CreateTemp(t.TempDir(), "help-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = file
	printHelp()
	os.Stdout = old
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "device-policy-file") {
		t.Fatalf("hidden flag appeared in help:\n%s", body)
	}
}
