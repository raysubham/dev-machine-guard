//go:build darwin

package browserext

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// Opt-in validation under a one-shot launchd job. It never grants permissions,
// launches a browser, changes a profile, or invokes enterprise telemetry.
func TestLiveProtectedBrowserInventory(t *testing.T) {
	if os.Getenv("DMG_TCC_VALIDATE_LIVE") != "1" {
		t.Skip("explicit live validation only")
	}
	version, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	result := New(executor.NewReal()).WithOSVersion(strings.TrimSpace(string(version))).WithSkipper(tcc.New(u.HomeDir)).Detect(context.Background(), u)
	if result == nil {
		t.Fatal("missing inventory coverage")
	}
	assertPayloadInvariants(t, result)
	summary := struct {
		Version  string `json:"version"`
		Findings int    `json:"findings"`
		Complete bool   `json:"complete"`
		Coverage any    `json:"coverage"`
	}{strings.TrimSpace(string(version)), len(result.Findings), result.ScanComplete, result.Browsers}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if strings.HasPrefix(string(version), "27.") && (len(result.Findings) != 0 || result.ScanComplete) {
		t.Fatal("macOS 27 protected inventory unexpectedly scanned")
	}
}
