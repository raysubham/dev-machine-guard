// Package devmdm implements the dev-machine-guard agent side of Developer MDM
// on-device policy enforcement (PRD: "Dev Machine Guard Agent: IDE Extension
// Enforcement"). It is a thin agent: each scheduled cycle it fetches the
// backend-compiled policy, writes the OS-native VS Code managed-policy
// (AllowedExtensions), reads it back to verify, and reports a compliance state.
// VS Code itself performs the disabling — the agent never uninstalls
// extensions, never installs anything, and never touches non-VS-Code IDEs.
//
// This subsystem shares NO code or state with the AI-agent hook-policy feature
// in internal/aiagents (PRD N11). The backend computes the compiled
// extensions.allowed object and a content hash; the agent writes them verbatim
// and never re-implements allow/deny merging, so on-device and MDM-export
// enforcement stay at parity.
//
// Scope (v1): Windows (HKLM registry, floor VS Code 1.96) and Linux
// (/etc/vscode/policy.json, floor 1.106). macOS is delivered via MDM export
// only — the Step 0 spike found VS Code honors AllowedExtensions on macOS only
// from an MDM-installed configuration profile, which a local agent cannot
// produce; see writer_other.go.
//
// Seams (highest first), each independently testable:
//   - Verify (verify.go): pure {write_ok, readback_match, vscode_version,
//     min_vscode_version} → state.
//   - Writer (writer.go + per-OS files): injected; manages only the
//     AllowedExtensions value, preserving foreign policies (coexistence).
//   - Fetcher (fetch.go) / Reporter (report.go): the two dedicated endpoints on
//     the existing developer-mdm-agent auth channel.
//   - Reconciler (reconcile.go): orchestrates fetch → ownership-safe write →
//     verify → report, with idempotency and malformed-→-no-op.
package devmdm
