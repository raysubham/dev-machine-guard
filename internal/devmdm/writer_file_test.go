package devmdm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempPolicyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vscode", "policy.json")
}

const samplePolicy = `{"*":false,"ms-python.python":true}`

func TestFileWriterWriteCreatesStringValuedKey(t *testing.T) {
	w := newFileWriterAt(tempPolicyPath(t))

	rb, err := w.Write(samplePolicy)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb != samplePolicy {
		t.Fatalf("readback = %q, want %q", rb, samplePolicy)
	}

	// Parity-critical: the on-disk shape is {"AllowedExtensions": "<json string>"} —
	// the value is a STRINGIFIED JSON object (a JSON string), NOT a nested object.
	// This is what VS Code's FilePolicyService honors; a nested object is ignored.
	raw, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("file is not a JSON object: %v\n%s", err, raw)
	}
	val, ok := probe[allowedExtensionsName]
	if !ok {
		t.Fatalf("file missing %q key: %s", allowedExtensionsName, raw)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(val)), `"`) {
		t.Fatalf("%s value must be a JSON string, got: %s", allowedExtensionsName, val)
	}
	var decoded string
	if err := json.Unmarshal(val, &decoded); err != nil {
		t.Fatalf("%s value is not a JSON string: %v", allowedExtensionsName, err)
	}
	if decoded != samplePolicy {
		t.Fatalf("decoded value = %q, want %q", decoded, samplePolicy)
	}
}

func TestFileWriterReadAbsent(t *testing.T) {
	w := newFileWriterAt(tempPolicyPath(t))
	v, present, err := w.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if present || v != "" {
		t.Fatalf("absent file should yield present=false, got present=%v v=%q", present, v)
	}
}

func TestFileWriterPreservesForeignKeysOnWrite(t *testing.T) {
	path := tempPolicyPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// An admin/MDM placed another policy in the same file.
	seed := `{"TelemetryLevel":"all","UpdateMode":"none"}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	w := newFileWriterAt(path)
	if _, err := w.Write(samplePolicy); err != nil {
		t.Fatalf("Write: %v", err)
	}

	raw, _ := os.ReadFile(path)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, k := range []string{"TelemetryLevel", "UpdateMode", allowedExtensionsName} {
		if _, ok := m[k]; !ok {
			t.Fatalf("expected key %q preserved/added; file: %s", k, raw)
		}
	}
}

func TestFileWriterClearRemovesOnlyOwnKey(t *testing.T) {
	path := tempPolicyPath(t)
	w := newFileWriterAt(path)
	if _, err := w.Write(samplePolicy); err != nil {
		t.Fatal(err)
	}
	// Add a foreign key alongside.
	raw, _ := os.ReadFile(path)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	m["TelemetryLevel"] = json.RawMessage(`"all"`)
	if err := w.writeFileMap(m); err != nil {
		t.Fatal(err)
	}

	if err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file should still exist (foreign key remains): %v", err)
	}
	var after map[string]json.RawMessage
	_ = json.Unmarshal(raw, &after)
	if _, ok := after[allowedExtensionsName]; ok {
		t.Fatalf("Clear should remove %q; file: %s", allowedExtensionsName, raw)
	}
	if _, ok := after["TelemetryLevel"]; !ok {
		t.Fatalf("Clear must preserve foreign key; file: %s", raw)
	}
}

func TestFileWriterClearRemovesFileWhenOnlyOwnKey(t *testing.T) {
	path := tempPolicyPath(t)
	w := newFileWriterAt(path)
	if _, err := w.Write(samplePolicy); err != nil {
		t.Fatal(err)
	}
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should be removed when it held only the agent policy; stat err=%v", err)
	}
}

func TestFileWriterClearAbsentIsNoop(t *testing.T) {
	w := newFileWriterAt(tempPolicyPath(t))
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear on absent file should be a no-op, got %v", err)
	}
}

func TestFileWriterForeignNestedObjectReadAsForeign(t *testing.T) {
	path := tempPolicyPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// A hand-written nested-object value (the WRONG shape) — the writer must
	// surface it as a non-matching value, never decode it as the agent's string.
	if err := os.WriteFile(path, []byte(`{"AllowedExtensions":{"*":false}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	w := newFileWriterAt(path)
	v, present, err := w.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !present {
		t.Fatal("nested-object value should read as present")
	}
	if v == samplePolicy {
		t.Fatal("nested object must not be mistaken for the agent's canonical value")
	}
}

func TestFileWriterRejectsUnparseableFile(t *testing.T) {
	path := tempPolicyPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	w := newFileWriterAt(path)
	if _, _, err := w.Read(); err == nil {
		t.Fatal("Read of a non-JSON file must error (never clobber it)")
	}
	if _, err := w.Write(samplePolicy); err == nil {
		t.Fatal("Write must refuse to clobber a non-JSON file")
	}
}
