package devicepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CacheFilename is the basename of the enforcement state file. It lives under
// ~/.stepsecurity/ alongside config.json and hooks-state.json, and is distinct
// from the AI-agent hook cache (this is a separate subsystem — no shared state).
const CacheFilename = "device-policy-state.json"

// CacheSchemaVersion is the on-disk version of the state file. Bump only on a
// breaking shape change.
const CacheSchemaVersion = 1

const (
	cacheFileMode      os.FileMode = 0o600
	cacheParentDirMode os.FileMode = 0o700
)

// AppliedState records what the agent last wrote to the user-scope VS Code
// settings.json. Two fields drive correctness:
//
//   - AppliedHash is the backend's content hash, stored VERBATIM (never
//     recomputed). Compared against the freshly-fetched hash for idempotency.
//   - WrittenValue is the exact compacted extensions.allowed value the agent
//     wrote. It drives value-based ownership and drift: on a clear, the agent
//     removes the settings key only if the on-disk value still equals
//     WrittenValue (a differing value — e.g. the user's own — is left
//     untouched); on enforce, an on-disk value differing from WrittenValue is
//     drift and is converged back.
//
// An empty AppliedState (zero value) means "the agent owns nothing on disk".
type AppliedState struct {
	SchemaVersion int       `json:"schema_version"`
	Category      string    `json:"category"`
	AppliedHash   string    `json:"applied_hash"`
	WrittenValue  string    `json:"written_value"`
	FetchedAt     time.Time `json:"fetched_at"`
}

// cachePathOverride lets tests redirect reads/writes to a tempdir. Production
// leaves it empty. Same pattern as state.cachePathOverride.
var cachePathOverride string

// SetCachePathForTest redirects CachePath() to the given absolute path and
// returns a restore function. Test-only.
func SetCachePathForTest(p string) (restore func()) {
	prev := cachePathOverride
	cachePathOverride = p
	return func() { cachePathOverride = prev }
}

// CachePath returns the absolute state-file path, honoring the test override.
// Empty string means the home directory could not be resolved.
func CachePath() string {
	if cachePathOverride != "" {
		return cachePathOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".stepsecurity", CacheFilename)
}

// ReadAppliedState returns (state, true) on a successful parse, else
// (zero, false). It never surfaces an error: a missing/corrupt file — or one
// written by a newer agent (schema_version beyond this build's
// CacheSchemaVersion) — simply means "no recorded ownership", and the
// reconciler treats that as owning nothing: safe, because it then refuses to
// clear a value it has no record of writing and re-applies the policy.
func ReadAppliedState() (AppliedState, bool) {
	path := CachePath()
	if path == "" {
		return AppliedState{}, false
	}
	// #nosec G304 -- path is CachePath(): a test override or os.UserHomeDir()
	// joined with the package constant CacheFilename. Never external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return AppliedState{}, false
	}
	var s AppliedState
	if err := json.Unmarshal(b, &s); err != nil {
		return AppliedState{}, false
	}
	// A 0 version predates the field (or was hand-written). WriteAppliedState
	// always stamps the version, so a genuine file from this agent is never 0;
	// treat 0 as the current schema rather than rejecting it.
	if s.SchemaVersion == 0 {
		s.SchemaVersion = CacheSchemaVersion
	}
	// Refuse a file from a newer agent. A schema beyond what this build knows may
	// reuse written_value / applied_hash with changed meaning; acting on data we
	// can't interpret risks a wrong ownership or drift decision. Reporting it
	// unreadable falls back to "owns nothing" — the reconciler re-applies and
	// never wrongly clears. Older/equal versions share today's shape, so they
	// read normally (a future breaking bump owns its own migration here).
	if s.SchemaVersion > CacheSchemaVersion {
		return AppliedState{}, false
	}
	return s, true
}

// WriteAppliedState atomically replaces the state file (temp + sync + rename),
// creating the parent dir with 0o700 and the file with 0o600.
func WriteAppliedState(s AppliedState) error {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = CacheSchemaVersion
	}
	path := CachePath()
	if path == "" {
		return errNoHomeDir
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, cacheParentDirMode); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(parent, "."+CacheFilename+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, cacheFileMode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

type cacheError string

func (e cacheError) Error() string { return string(e) }

const errNoHomeDir = cacheError("devicepolicy: cannot resolve home directory")
