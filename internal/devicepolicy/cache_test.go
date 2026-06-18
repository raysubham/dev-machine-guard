package devicepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppliedStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := SetCachePathForTest(filepath.Join(dir, CacheFilename))
	defer restore()

	want := AppliedState{
		Category:     CategoryIDEExtension,
		AppliedHash:  "sha256:abc",
		WrittenValue: samplePolicy,
		FetchedAt:    time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(want); err != nil {
		t.Fatalf("WriteAppliedState: %v", err)
	}
	got, ok := ReadAppliedState()
	if !ok {
		t.Fatal("ReadAppliedState ok=false after write")
	}
	if got.AppliedHash != want.AppliedHash || got.WrittenValue != want.WrittenValue || got.Category != want.Category {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", got.SchemaVersion, CacheSchemaVersion)
	}
}

func TestReadAppliedStateAbsent(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), "nope.json"))
	defer restore()
	if _, ok := ReadAppliedState(); ok {
		t.Fatal("absent cache should yield ok=false")
	}
}

func TestReadAppliedStateCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(); ok {
		t.Fatal("corrupt cache should yield ok=false (owns nothing)")
	}
}

func TestReadAppliedStateRejectsFutureSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// A state file written by a newer agent: a schema beyond what this build
	// understands. It decodes fine, but its fields may mean something else, so
	// the reader must refuse it rather than drive ownership/drift off it.
	future := `{"schema_version":999,"category":"ide_extension","applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(); ok {
		t.Fatal("future schema_version must be unreadable (ok=false) so the agent owns nothing")
	}
}

func TestReadAppliedStateMissingSchemaReadsAsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// No schema_version field (legacy or hand-written): read it, normalized to
	// the current version — not rejected.
	noVer := `{"category":"ide_extension","applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(noVer), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	got, ok := ReadAppliedState()
	if !ok {
		t.Fatal("missing schema_version should read as current, not be rejected")
	}
	if got.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want normalized to %d", got.SchemaVersion, CacheSchemaVersion)
	}
}
