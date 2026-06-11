//go:build !windows && !linux

package devmdm

// NewWriter reports that on-device native-policy enforcement is unavailable on
// this OS. macOS is intentionally unsupported: the Step 0 spike found VS Code
// only honors AllowedExtensions delivered via an MDM-installed configuration
// profile (@vscode/policy-watcher watches /Library/Managed Preferences/ and
// resolves values through CFPreferences on the bundle-ID domain — both satisfied
// only by an installed profile), so a local agent write cannot take effect.
// macOS is therefore delivered through the MDM-export channel, not the agent.
//
// ok=false tells the reconciler to skip enforcement and report nothing; the
// backend independently gates non-(Windows|Linux) platforms to a clear result,
// so the two ends agree without the agent reporting a state.
func NewWriter() (Writer, bool) { return nil, false }
