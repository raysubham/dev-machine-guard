package devicepolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ownRec / npmOwnRec build the one-entry ownership record a single-value lane
// persists: WrittenSettings is the only ownership field, so a lane that owns one
// opaque value records it under its own ownership key — the allowlist setting id
// for a plain VS Code Writer, NPMOwnedKey for the ~/.npmrc block.
func ownRec(value string) map[string]string {
	return map[string]string{allowedExtensionsSettingKey: value}
}

func npmOwnRec(value string) map[string]string {
	return map[string]string{NPMOwnedKey: value}
}

func TestAppliedTargetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := SetCachePathForTest(filepath.Join(dir, CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash:     "sha256:abc",
		WrittenSettings: ownRec(samplePolicy),
		FetchedAt:       time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, want); err != nil {
		t.Fatalf("WriteAppliedState: %v", err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("ReadAppliedState ok=false after write")
	}
	if got.AppliedHash != want.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != want.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// On disk it is the schema-versioned wrapper keyed by category then target.
	raw, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("on-disk file is not a valid AppliedStateFile: %v", err)
	}
	if f.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", f.SchemaVersion, CacheSchemaVersion)
	}
	cat, ok := f.Categories[CategoryIDEExtension]
	if !ok {
		t.Fatalf("category %q missing from on-disk wrapper: %+v", CategoryIDEExtension, f)
	}
	if _, ok := cat.Targets[TargetVSCode]; !ok {
		t.Fatalf("target %q missing under category %q: %+v", TargetVSCode, CategoryIDEExtension, f)
	}
}

func TestReadAbsentFileOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), "nope.json"))
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("absent cache should yield ok=false")
	}
}

func TestReadCorruptFileOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("corrupt cache should yield ok=false (owns nothing)")
	}
}

func TestReadFutureSchemaOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// A wrapper written by a newer agent: a schema beyond what this build
	// understands. It decodes fine, but its metadata may mean something else, so
	// the reader must refuse it rather than drive ownership/drift off it.
	future := `{"schema_version":999,"categories":{"ide_extension":{"targets":{"vscode":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("future schema_version must be unreadable (ok=false) so the agent owns nothing")
	}
}

func TestReadMissingSchemaReadsAsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// No schema_version field (legacy or hand-written) but the wrapper shape:
	// read it, normalized to the current version — not rejected.
	noVer := `{"categories":{"ide_extension":{"targets":{"vscode":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(noVer), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("missing schema_version should read as current, not be rejected")
	}
	if got.AppliedHash != "sha256:x" {
		t.Fatalf("applied_hash = %q, want sha256:x", got.AppliedHash)
	}
}

func TestReadAbsentCategoryOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	// The file exists and holds one category; a DIFFERENT category owns nothing.
	if err := WriteAppliedState("other_category", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("x")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("a category with no entry should yield ok=false even when the file exists")
	}
}

func TestReadAbsentTargetOwnsNothing(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	// The category exists with a vscode target; a DIFFERENT target owns nothing.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); ok {
		t.Fatal("a target with no entry should yield ok=false even when the category exists")
	}
	// Sanity: the populated target still reads.
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok {
		t.Fatal("the populated target must still read ok=true")
	}
}

func TestWritePreservesOtherCategories(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	other := AppliedTargetState{AppliedHash: "sha256:OTHER", WrittenSettings: ownRec("other-value")}
	if err := WriteAppliedState("other_category", TargetVSCode, other); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	// Writing ide_extension must not disturb other_category.
	got, ok := ReadAppliedState("other_category", TargetVSCode)
	if !ok || got.AppliedHash != other.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != other.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("other category not preserved across a sibling write: got %+v ok=%v", got, ok)
	}
}

func TestWritePreservesOtherTargets(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under the SAME category. Rewriting one must not disturb the other.
	jb := AppliedTargetState{AppliedHash: "sha256:JB", WrittenSettings: ownRec("jetbrains-value")}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", jb); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	// Rewrite vscode again — the sibling jetbrains target must still stand.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:VS2", WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains")
	if !ok || got.AppliedHash != jb.AppliedHash || got.WrittenSettings[allowedExtensionsSettingKey] != jb.WrittenSettings[allowedExtensionsSettingKey] {
		t.Fatalf("sibling target not preserved across a same-category write: got %+v ok=%v", got, ok)
	}
	if vs, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || vs.AppliedHash != "sha256:VS2" {
		t.Fatalf("vscode target should hold the latest write: got %+v ok=%v", vs, ok)
	}
}

func TestWriteRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"targets":{"vscode":{"applied_hash":"sha256:z","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)})
	if !errors.Is(err, errFutureSchema) {
		t.Fatalf("write over a future-schema file must refuse with errFutureSchema, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("future-schema file must be left byte-identical; got %q", string(after))
	}
}

func TestClearRemovesTargetAndPreservesSiblingCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("keep")}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared target should be gone")
	}
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "keep" {
		t.Fatalf("untouched category must survive a sibling clear: got %+v ok=%v", got, ok)
	}
}

func TestClearRemovesOnlyTargetWithinCategory(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// Two targets under one category; clearing one must leave the other — and the
	// category itself — intact. Clearing the last target then drops the category.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenSettings: ownRec(samplePolicy)}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", AppliedTargetState{WrittenSettings: ownRec("jb")}); err != nil {
		t.Fatal(err)
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState vscode: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("cleared vscode target should be gone")
	}
	if got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "jb" {
		t.Fatalf("sibling jetbrains target must survive a vscode clear: got %+v ok=%v", got, ok)
	}
	// On disk the category must still exist (it still has the jetbrains target).
	raw, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Categories[CategoryIDEExtension]; !ok {
		t.Fatalf("category must remain while a target survives: %+v", f)
	}
	// Clearing the last remaining target drops the now-empty category.
	if err := ClearAppliedState(CategoryIDEExtension, "jetbrains"); err != nil {
		t.Fatalf("ClearAppliedState jetbrains: %v", err)
	}
	raw, err = os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	f = AppliedStateFile{}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Categories[CategoryIDEExtension]; ok {
		t.Fatalf("category should be dropped once its last target is cleared: %+v", f)
	}
}

func TestClearReclaimsEmptyTargetRecord(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	// An empty-ownership entry, as a preflight leaves when its settings write
	// then fails: present in the file but with no value/hash.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{FetchedAt: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState("keep_me", TargetVSCode, AppliedTargetState{WrittenSettings: ownRec("keep")}); err != nil {
		t.Fatal(err)
	}
	// The empty entry is still a present key (ok=true) — the reconciler's
	// entry-exists drop is what reclaims it.
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok {
		t.Fatal("empty-ownership entry should be a present key")
	}
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("ClearAppliedState: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("empty target record should be reclaimed by clear")
	}
	if got, ok := ReadAppliedState("keep_me", TargetVSCode); !ok || got.WrittenSettings[allowedExtensionsSettingKey] != "keep" {
		t.Fatalf("sibling category must survive: got %+v ok=%v", got, ok)
	}
}

func TestClearRefusesFutureSchemaFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_only":{"targets":{"vscode":{"applied_hash":"sha256:z"}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); !errors.Is(err, errFutureSchema) {
		t.Fatalf("clear over a future-schema file must refuse with errFutureSchema, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("future-schema file must be left byte-identical; got %q", string(after))
	}
}

func TestClearAbsentFileIsNoOp(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()
	if err := ClearAppliedState(CategoryIDEExtension, TargetVSCode); err != nil {
		t.Fatalf("clearing an absent file should be a no-op, got %v", err)
	}
}

func TestLegacySingleObjectReadsAsOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// The pre-refactor single-object shape (also schema_version 1). It parses as
	// a wrapper with no "categories" key → empty map → owns nothing → one
	// harmless re-apply. We deliberately do NOT migrate it.
	legacy := `{"schema_version":1,"category":"ide_extension","applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("legacy single-object file should read as owns-nothing (no migration)")
	}
}

func TestOldCategoryShapeReadsAsOwnsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	// The pre-target category-keyed shape: categories.<cat> carried the ownership
	// fields directly, with no "targets" map. Under the target-aware reader this
	// decodes to a nil Targets map → owns nothing → one harmless re-apply. Not
	// migrated (pre-GA, no rollback support).
	old := `{"schema_version":1,"categories":{"ide_extension":{"applied_hash":"sha256:x","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()
	if _, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); ok {
		t.Fatal("pre-target category-only file should read as owns-nothing (no migration)")
	}
}

func TestAppliedTargetWrittenSettingsRoundTrip(t *testing.T) {
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	defer restore()

	want := AppliedTargetState{
		AppliedHash: "sha256:abc",
		WrittenSettings: map[string]string{
			allowedExtensionsSettingKey: samplePolicy,
			galleryServiceURLSettingKey: `"https://mkt.example/api/v1"`,
		},
		FetchedAt: time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC),
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("ok=false after write")
	}
	for key, wantVal := range want.WrittenSettings {
		if got.WrittenSettings[key] != wantVal {
			t.Fatalf("WrittenSettings[%s] not round-tripped: got %+v", key, got.WrittenSettings)
		}
	}
}

func TestAppliedTargetEmptyOwnershipOmitsField(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	// A record that owns nothing (the preflight writability probe writes exactly
	// this) must omit written_settings on disk and read back as a nil map. This is
	// the only shape that omits it now that WrittenSettings is the sole ownership
	// field: a single-value lane records one entry, so its record always carries it.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{
		AppliedHash: "sha256:H",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "written_settings") {
		t.Fatalf("a record owning nothing must omit written_settings:\n%s", raw)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok || got.WrittenSettings != nil {
		t.Fatalf("WrittenSettings must be nil when nothing is owned, got %+v ok=%v", got.WrittenSettings, ok)
	}
}

func TestAppliedTargetSingleValueRecordsOneEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	// The single-value lanes (the ~/.npmrc block writer, and the degraded VS Code
	// writer) record ownership as exactly ONE written_settings entry keyed by their
	// own ownership key. This is the shape the retired written_value field used to
	// hold, so the collapse must not change what round-trips.
	if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, AppliedTargetState{
		AppliedHash: "sha256:N", WrittenSettings: npmOwnRec("registry=https://x.example/javascript"),
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM)
	if !ok {
		t.Fatal("ok=false after write")
	}
	if len(got.WrittenSettings) != 1 || got.WrittenSettings[NPMOwnedKey] != "registry=https://x.example/javascript" {
		t.Fatalf("single-value record = %+v, want exactly one %s entry", got.WrittenSettings, NPMOwnedKey)
	}
}

// TestAppliedTargetLegacyWrittenValueReadsAsUnowned pins the no-migrator
// decision: a state file written before the collapse carries only the retired
// written_value key, which decodes into no WrittenSettings entry — so the target
// reads as "owns nothing" and the next enforce re-converges and re-records it. No
// production devices exist, so nothing is owed beyond not crashing.
func TestAppliedTargetLegacyWrittenValueReadsAsUnowned(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	legacy := `{"schema_version":1,"categories":{"ide_extension":{"targets":{"vscode":` +
		`{"applied_hash":"sha256:OLD","written_value":"{\"*\":false}","fetched_at":"2026-07-01T00:00:00Z"}}}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok {
		t.Fatal("a legacy record must still decode (ok=true), just own nothing")
	}
	if got.AppliedHash != "sha256:OLD" {
		t.Fatalf("applied_hash = %q, want the legacy hash preserved", got.AppliedHash)
	}
	if len(got.WrittenSettings) != 0 {
		t.Fatalf("legacy written_value must not decode into ownership, got %+v", got.WrittenSettings)
	}
	if len(ownedKeys(got, ok)) != 0 {
		t.Fatal("ownedKeys over a legacy record must be empty (owns nothing)")
	}
}
