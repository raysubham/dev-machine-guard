//go:build windows

package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type windowsUVProbeExecutor struct {
	*executor.Mock
	stdout string
	exit   int
	err    error
}

func (e *windowsUVProbeExecutor) RunInDir(_ context.Context, dir string, _ time.Duration, _ string, _ ...string) (string, string, int, error) {
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o700); err != nil {
		return "", "", 1, err
	}
	return e.stdout, "", e.exit, e.err
}

func TestUVProbeSettingsWindowsCleansEveryOutcome(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "uv-show-settings-0.12.6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	match := string(fixture)
	mismatch := string(bytes.Replace(fixture, []byte("https://registry.stepsecurity.io/python/simple"), []byte("https://other.example/python/simple"), 1))
	tests := []struct {
		name         string
		stdout       string
		exit         int
		err          error
		wantStatus   string
		wantSource   string
		wantRegistry string
	}{
		{"successful probe", match, 0, nil, "match", "none", "https://registry.stepsecurity.io/python/simple"},
		{"effective mismatch", mismatch, 0, nil, "mismatch", "unknown", "https://other.example/python/simple"},
		{"child failure", "", 1, errors.New("uv failed"), "unknown", "unknown", ""},
		{"cancellation", "", 1, context.Canceled, "unknown", "unknown", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			home := newSecureTestHome(t, t.TempDir())
			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformWindows)
			mock.SetEnv("TMPDIR", base)
			exec := &windowsUVProbeExecutor{Mock: mock, stdout: tc.stdout, exit: tc.exit, err: tc.err}
			w := &UVWriter{exec: exec, home: home, versionSupported: true, registryURL: "https://registry.stepsecurity.io/python/simple"}

			status, source, registry := w.probeSettings(context.Background())
			if status != tc.wantStatus || source != tc.wantSource || registry != tc.wantRegistry {
				t.Fatalf("probeSettings = %q, %q, %q, want %q, %q, %q", status, source, registry, tc.wantStatus, tc.wantSource, tc.wantRegistry)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("probe directory remains: %v", entries)
			}
		})
	}
}
