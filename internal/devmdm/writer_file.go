package devmdm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// allowedExtensionsName is VS Code's registered policy name for the
// `extensions.allowed` setting: the JSON key in policy.json and the registry
// value name on Windows. Confirmed against VS Code's policy fixtures and
// FilePolicyService — the file/registry is keyed by POLICY NAME, not by the
// `extensions.allowed` setting id. Defined in this untagged file so it is
// referenced on every platform (no unused-symbol warning on the macOS host).
const allowedExtensionsName = "AllowedExtensions"

const (
	// The policy file must be readable by the logged-in user's VS Code process,
	// so it is world-readable — NOT 0600 like the agent's own home-dir cache.
	policyFileMode os.FileMode = 0o644
	policyDirMode  os.FileMode = 0o755
)

// fileWriter manages the AllowedExtensions key inside a JSON policy file (Linux:
// /etc/vscode/policy.json). It read-modify-writes the whole file so any other VS
// Code policies an admin or MDM placed there survive (coexistence). The logic is
// OS-agnostic; only the production path is Linux-specific, so this lives in an
// untagged file and is unit-tested directly on any platform.
type fileWriter struct{ path string }

// newFileWriterAt builds a file-backed writer for an arbitrary path.
func newFileWriterAt(path string) *fileWriter { return &fileWriter{path: path} }

func (w *fileWriter) Location() string { return w.path + " [" + allowedExtensionsName + "]" }

// readFileMap parses the policy file into a key→raw map. (nil, false, nil) when
// the file is absent. A present-but-unparseable file is an error — the writer
// must never clobber a file it cannot understand.
func (w *fileWriter) readFileMap() (map[string]json.RawMessage, bool, error) {
	// #nosec G304 -- w.path is the Linux package constant or a test override,
	// never external input.
	b, err := os.ReadFile(w.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("devmdm: read %s: %w", w.path, err)
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false, fmt.Errorf("devmdm: %s is not a JSON object: %w", w.path, err)
	}
	return m, true, nil
}

func (w *fileWriter) Read() (string, bool, error) {
	m, _, err := w.readFileMap()
	if err != nil {
		return "", false, err
	}
	raw, ok := m[allowedExtensionsName]
	if !ok {
		return "", false, nil
	}
	// The value is stored as a JSON string whose contents are the policy JSON.
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		// Present but not a JSON string (e.g. a hand-written nested object). Return
		// the raw bytes so the reconciler treats it as a foreign value to leave
		// alone — it will not match the agent's canonical string.
		return string(raw), true, nil
	}
	return s, true, nil
}

func (w *fileWriter) Write(value string) (string, error) {
	m, _, err := w.readFileMap()
	if err != nil {
		return "", err
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	// Store the policy as a JSON string (VS Code parses it downstream). Marshaling
	// a Go string yields the correctly quoted/escaped JSON string literal.
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("devmdm: encode policy value: %w", err)
	}
	m[allowedExtensionsName] = encoded
	if err := w.writeFileMap(m); err != nil {
		return "", err
	}
	rb, _, err := w.Read()
	if err != nil {
		return "", err
	}
	return rb, nil
}

func (w *fileWriter) Clear() error {
	m, present, err := w.readFileMap()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if _, ok := m[allowedExtensionsName]; !ok {
		return nil
	}
	delete(m, allowedExtensionsName)
	if len(m) == 0 {
		// The file held only the agent's policy — remove it rather than leave an
		// empty object behind.
		if err := os.Remove(w.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("devmdm: remove %s: %w", w.path, err)
		}
		return nil
	}
	return w.writeFileMap(m)
}

// writeFileMap atomically replaces the policy file (temp + rename) with the
// pretty-printed map, creating the parent dir if needed.
func (w *fileWriter) writeFileMap(m map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("devmdm: encode policy file: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, policyDirMode); err != nil {
		return fmt.Errorf("devmdm: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".policy.json.tmp-*")
	if err != nil {
		return fmt.Errorf("devmdm: temp file: %w", err)
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
	if err := os.Chmod(tmpPath, policyFileMode); err != nil {
		return err
	}
	return os.Rename(tmpPath, w.path)
}
