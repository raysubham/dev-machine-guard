package devmdm

import (
	"strconv"
	"strings"
)

// Compliance states the agent may report. These mirror the agent-reportable
// subset of agent-api's policies.State* enum byte-for-byte — the backend
// rejects any value outside its agentReportableStates set, so these strings
// MUST stay in sync with internal/developer-mdm/policies/models.go. The
// backend-derived states (not_assigned, agent_unsupported, agent_stale,
// unsupported_platform) are never reported by the agent.
const (
	StateCompliant          = "compliant"
	StatePending            = "pending"
	StatePolicyNotApplied   = "policy_not_applied"
	StateVSCodeUnsupported  = "vscode_unsupported"
	StateMDMManaged         = "mdm_managed"
	StateWriteFailed        = "write_failed"
	StateVerificationFailed = "verification_failed"
)

// CategoryIDEExtension is the only policy category enforced in v1. It matches
// agent-api's CategoryIDEExtension and is the value passed as ?category= on the
// effective-policy fetch and echoed in the compliance report.
const CategoryIDEExtension = "ide_extension"

// VerifyInput is the result set the verifier reasons over. It is intentionally
// pure data: the writer performs the I/O (write + readback) and the reconciler
// supplies the detected VS Code version, so Verify itself touches nothing.
type VerifyInput struct {
	// WriteOK is true when the native-policy write returned no error.
	WriteOK bool
	// ReadbackMatch is true when the value read back after the write equals the
	// value the agent intended to write. A false value here (with WriteOK true)
	// is the on-device signal that VS Code's policy did not actually take —
	// VS Code applies a malformed/over-long policy silently, so readback is the
	// only evidence the write landed.
	ReadbackMatch bool
	// VSCodeVersion is the installed VS Code version (e.g. "1.96.2"). Empty or
	// "unknown" — including VS Code not being installed — compares below every
	// floor and yields vscode_unsupported.
	VSCodeVersion string
	// MinVSCodeVersion is the per-OS floor the backend supplied in the fetch
	// contract (Windows 1.96 / Linux 1.106). Empty means "no floor" (the
	// backend vouched for the platform by returning a policy) and never blocks.
	MinVSCodeVersion string
}

// Verify maps a result set to the compliance state, with a fixed precedence:
//
//  1. VS Code below the per-OS floor (or absent/unknown) → vscode_unsupported.
//     A too-old VS Code ignores the policy entirely, so the write outcome is
//     irrelevant — the honest signal is that this device cannot enforce.
//  2. Write failed → write_failed.
//  3. Write succeeded but the readback differs → policy_not_applied.
//  4. Otherwise → compliant.
//
// `compliant` means exactly what the PRD's weak-verification model allows: the
// desired policy is present on-device (readback-confirmed) AND VS Code is a
// version that honors it — NOT a per-extension disabled confirmation.
//
// mdm_managed (a foreign on-disk value the agent does not own) and
// verification_failed (the readback itself errored) are decided by the
// reconciler, not here: neither is derivable from these four inputs alone.
func Verify(in VerifyInput) string {
	if !versionAtLeast(in.VSCodeVersion, in.MinVSCodeVersion) {
		return StateVSCodeUnsupported
	}
	if !in.WriteOK {
		return StateWriteFailed
	}
	if !in.ReadbackMatch {
		return StatePolicyNotApplied
	}
	return StateCompliant
}

// versionAtLeast reports whether dotted version v is >= min. It mirrors the
// backend's lenient major.minor.patch comparison (agent-api compliance.go) so
// an agent-side vscode_unsupported decision uses the same arithmetic the
// backend uses for agent capability. An empty min is treated as "no floor".
func versionAtLeast(v, min string) bool {
	return compareVersions(v, min) >= 0
}

// compareVersions compares dotted numeric versions (major.minor.patch). A
// leading "v" and any non-numeric suffix on a segment are ignored. Returns
// -1/0/1. Missing segments read as 0, so "1.96" == "1.96.0".
func compareVersions(v, o string) int {
	a, b := versionParts(v), versionParts(o)
	for i := range 3 {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func versionParts(s string) [3]int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.SplitN(s, ".", 3)
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		out[i] = leadingInt(parts[i])
	}
	return out
}

// leadingInt parses the leading integer of a version segment ("106-rc1" -> 106,
// "unknown" -> 0).
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}
