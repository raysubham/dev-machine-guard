package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/paths"
)

func TestTailFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")

	if _, err := tailFile(path, 10); err == nil {
		t.Error("missing file: expected an error")
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := tailFile(path, 10); err != nil || got != nil {
		t.Errorf("empty file: got %q err %v, want nil,nil", got, err)
	}

	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := tailFile(path, 100); string(got) != "hello" {
		t.Errorf("smaller-than-n: got %q, want hello", got)
	}

	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := tailFile(path, 4); string(got) != "6789" {
		t.Errorf("tail: got %q, want 6789", got)
	}
}

func TestLogCapture_Seed(t *testing.T) {
	lc := &LogCapture{ring: newRingBuffer(captureRingCapacity)}
	lc.Seed([]byte("script line A\n"))
	lc.Seed([]byte("script line B\n"))
	tail := string(lc.Tail(captureTailBytes))
	if !strings.Contains(tail, "script line A") || !strings.Contains(tail, "script line B") {
		t.Errorf("seeded bytes missing from tail:\n%s", tail)
	}
}

func TestSeedLoaderLog_ReadsAndDeletes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("STEPSECURITY_HOME", dir)
	// Skip rather than fail if a leaked package global (config.InstallDir /
	// CLI override) redirects paths.Home() away from our sandbox.
	if paths.Home() != dir {
		t.Skipf("paths.Home()=%q not sandboxed to %q; skipping", paths.Home(), dir)
	}

	path := filepath.Join(dir, loaderLogFilename)
	content := "[2026-06-24 15:00:01] Binary v1.2.3 is up-to-date\n" +
		"[2026-06-24 15:00:02] write_config\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	lc := &LogCapture{ring: newRingBuffer(captureRingCapacity)}
	seedLoaderLog(lc)

	tail := string(lc.Tail(captureTailBytes))
	for _, want := range []string{"up-to-date", "write_config", "loader script log"} {
		if !strings.Contains(tail, want) {
			t.Errorf("seeded capture missing %q:\n%s", want, tail)
		}
	}
	// The file must be consumed (deleted) so a later run can't re-fold it.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf(".loader_log not deleted after seeding (stat err=%v)", err)
	}
}

func TestSeedLoaderLog_MissingFileNoPanic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("STEPSECURITY_HOME", dir)
	if paths.Home() != dir {
		t.Skipf("paths.Home()=%q not sandboxed to %q; skipping", paths.Home(), dir)
	}
	lc := &LogCapture{ring: newRingBuffer(captureRingCapacity)}
	seedLoaderLog(lc) // no .loader_log present — must be a no-op, no panic
	if tail := string(lc.Tail(captureTailBytes)); strings.Contains(tail, "loader script log") {
		t.Errorf("expected no loader log seeded, got:\n%s", tail)
	}
}

func TestSeedLoaderLog_NoCaptureNoPanic(t *testing.T) {
	seedLoaderLog(nil) // must not panic
}
