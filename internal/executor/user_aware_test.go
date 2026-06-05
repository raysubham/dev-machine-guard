package executor

import (
	"context"
	"strings"
	"testing"
)

// TestNewUserAwareExecutor_Wrapping pins the wrapping decision. The fix dropped
// the old `!inner.IsRoot()` gate so the wrapper also applies under a LaunchAgent
// (the agent running as the user, not root). launchd strips PATH in both modes,
// so brew/pip3/npm must run through the user's rc-sourced login shell either
// way — the non-root row is the regression this change fixes.
func TestNewUserAwareExecutor_Wrapping(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		isRoot   bool
		username string
		wantWrap bool
	}{
		{"non-root macOS with user (LaunchAgent regression)", "darwin", false, "alice", true},
		{"root macOS with user (LaunchDaemon)", "darwin", true, "alice", true},
		{"non-root linux with user", "linux", false, "alice", true},
		{"empty username → passthrough", "darwin", false, "", false},
		{"windows → passthrough", "windows", false, "alice", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetIsRoot(tc.isRoot)

			got := NewUserAwareExecutor(mock, tc.username)
			_, wrapped := got.(*UserAwareExecutor)
			if wrapped != tc.wantWrap {
				t.Errorf("NewUserAwareExecutor wrapped=%v, want %v", wrapped, tc.wantWrap)
			}
		})
	}
}

// TestUserAwareExecutor_RunDelegatesNonRoot confirms a wrapped Run is routed
// through the inner RunAsUser (which the Mock dispatches as `bash -c`) even when
// not root — i.e. the command actually reaches the user's shell, where PATH is
// resolved, rather than a bare exec.
func TestUserAwareExecutor_RunDelegatesNonRoot(t *testing.T) {
	mock := NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(false) // LaunchAgent: running as the user, not root
	mock.SetCommand("/opt/homebrew/bin/brew\n", "", 0, "bash", "-c", "which brew")

	exec := NewUserAwareExecutor(mock, "alice")
	stdout, _, code, err := exec.Run(context.Background(), "which", "brew")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(stdout); got != "/opt/homebrew/bin/brew" {
		t.Errorf("stdout = %q, want /opt/homebrew/bin/brew (Run should delegate to RunAsUser)", got)
	}
}
