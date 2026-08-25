// Package execguard decides whether a detector may safely launch a
// third-party binary on this machine.
//
// On macOS, executing a quarantined binary (com.apple.quarantine xattr, set
// by browser downloads and Homebrew cask installs) makes Gatekeeper assess
// it; when the binary or a native library it loads is not notarized, the OS
// shows a "could not verify … free of malware / Move to Bin" dialog in the
// logged-in user's session — a scary popup for something the user never ran
// themselves. SafeToExec answers, without any UI side effects, whether that
// would happen, so version probes can skip the exec (reporting "unknown")
// instead of triggering it. This generalizes the existing IsAppleCLTStub
// guard (which prevents the analogous Command Line Tools install prompt).
package execguard

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const probeTimeout = 5 * time.Second

// SafeToExec reports whether launching binaryPath is safe from a
// GUI-popup perspective. Non-macOS platforms always return true.
//
// On macOS it resolves symlinks, then checks the binary and its containing
// directory for the com.apple.quarantine attribute (cask installs quarantine
// the whole install tree, so the parent dir catches partially-cleared
// installs). Unquarantined binaries are safe: Gatekeeper only assesses
// quarantined files. For quarantined ones, `spctl --assess --type execute`
// gives Gatekeeper's verdict silently — accepted means executing shows no
// popup; rejected (or any spctl failure, conservatively) means skip.
//
// Both probes execute only Apple-provided utilities (/usr/bin/xattr,
// /usr/sbin/spctl), which carry none of the third-party-binary risk this
// package exists to avoid.
func SafeToExec(ctx context.Context, exec executor.Executor, binaryPath string) bool {
	if exec.GOOS() != model.PlatformDarwin || binaryPath == "" {
		return true
	}
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}
	if !isQuarantined(ctx, exec, resolved) && !isQuarantined(ctx, exec, parentDir(resolved)) {
		return true
	}
	_, _, exitCode, err := exec.RunWithTimeout(ctx, probeTimeout, "/usr/sbin/spctl", "--assess", "--type", "execute", resolved)
	return err == nil && exitCode == 0
}

// isQuarantined reports whether path carries the com.apple.quarantine
// extended attribute. xattr -p exits non-zero when the attribute (or the
// file) is absent.
func isQuarantined(ctx context.Context, exec executor.Executor, path string) bool {
	if path == "" {
		return false
	}
	_, _, exitCode, err := exec.RunWithTimeout(ctx, probeTimeout, "/usr/bin/xattr", "-p", "com.apple.quarantine", path)
	return err == nil && exitCode == 0
}

// parentDir returns the directory containing path ("" when there is none).
// Manual instead of filepath.Dir so mock paths behave identically on any
// test host OS.
func parentDir(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return ""
}
