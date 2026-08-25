package execguard

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const (
	binary   = "/usr/local/bin/cursor-agent"
	resolved = "/opt/homebrew/Caskroom/cursor-cli/2026.03.11/cursor-agent"
)

// quarantineStub marks path as carrying com.apple.quarantine.
func quarantineStub(mock *executor.Mock, path string) {
	mock.SetCommand("0083;65a1b2c3;Safari;", "", 0, "/usr/bin/xattr", "-p", "com.apple.quarantine", path)
}

func TestSafeToExec(t *testing.T) {
	spctlArgs := []string{"--assess", "--type", "execute", resolved}

	t.Run("not quarantined is safe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		// xattr unstubbed -> errors -> attribute absent.
		if !SafeToExec(context.Background(), mock, binary) {
			t.Error("unquarantined binary should be safe to exec")
		}
	})

	t.Run("quarantined and rejected is unsafe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		mock.SetCommand("", "rejected", 3, "/usr/sbin/spctl", spctlArgs...)
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined + Gatekeeper-rejected binary must not be exec'd")
		}
	})

	t.Run("quarantined but accepted is safe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		mock.SetCommand("accepted", "", 0, "/usr/sbin/spctl", spctlArgs...)
		if !SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined but notarized (spctl-accepted) binary should be safe")
		}
	})

	t.Run("quarantined parent dir triggers assessment", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		// Binary itself clean (partially-cleared install), containing dir quarantined.
		quarantineStub(mock, "/opt/homebrew/Caskroom/cursor-cli/2026.03.11")
		mock.SetCommand("", "rejected", 3, "/usr/sbin/spctl", spctlArgs...)
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined install dir must trigger assessment and reject")
		}
	})

	t.Run("spctl failure is conservatively unsafe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		// spctl unstubbed -> errors -> treat as rejected.
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined binary with failing spctl must not be exec'd")
		}
	})

	t.Run("non-darwin is always safe", func(t *testing.T) {
		for _, goos := range []string{"linux", "windows"} {
			mock := executor.NewMock()
			mock.SetGOOS(goos)
			quarantineStub(mock, binary)
			if !SafeToExec(context.Background(), mock, binary) {
				t.Errorf("GOOS=%s: quarantine is a macOS concept; must be safe", goos)
			}
		}
	})

	t.Run("empty path is safe", func(t *testing.T) {
		if !SafeToExec(context.Background(), executor.NewMock(), "") {
			t.Error("empty path should be a no-op (safe)")
		}
	})
}
