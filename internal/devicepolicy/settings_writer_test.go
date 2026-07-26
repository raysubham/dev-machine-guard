package devicepolicy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/atomicfile"
)

const samplePolicyObject = `{"github.copilot":true,"ms-python.python":"1.2.3"}`

// sampleSettings exercises every JSONC feature the writer must preserve:
// line + block comments, trailing commas (object and nested), irregular
// whitespace, and unrelated keys before and after where the policy lands.
const sampleSettings = `// StepSecurity test fixture — user settings
{
	/* appearance */
	"workbench.colorTheme": "Solarized Dark", // user's favorite
	"editor.fontSize":   14,
	"files.exclude": {
		"**/.git": true,
	},

	// telemetry opt-out
	"telemetry.telemetryLevel": "off",
}
`

// preservedFragments are exact byte sequences from sampleSettings that must
// survive any single-key edit untouched.
var preservedFragments = []string{
	"// StepSecurity test fixture — user settings",
	"/* appearance */",
	`"workbench.colorTheme": "Solarized Dark", // user's favorite`,
	`"editor.fontSize":   14,`,
	"\"files.exclude\": {\n\t\t\"**/.git\": true,\n\t},",
	"// telemetry opt-out",
	// No trailing comma asserted: when the policy key is removed from the end
	// of the object, hujson also drops the separator comma after this (then
	// last) member — separator syntax is part of the touched region.
	`"telemetry.telemetryLevel": "off"`,
}

func newTestSettingsWriter(t *testing.T) (*settingsWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "User", "settings.json")
	return newSettingsWriterAt(path), path
}

func writeSettingsFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertFragmentsPreserved(t *testing.T, got string) {
	t.Helper()
	for _, frag := range preservedFragments {
		if !strings.Contains(got, frag) {
			t.Errorf("fragment lost after edit:\n%q\n--- file now:\n%s", frag, got)
		}
	}
}

func TestSettingsWriteAddsKeyPreservingFile(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	rb, err := w.Write(samplePolicyObject)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb != samplePolicyObject {
		t.Fatalf("readback = %q, want %q", rb, samplePolicyObject)
	}

	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)

	// The file must remain valid JSONC holding both old and new keys.
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

func TestSettingsWriteReplacesExistingKeyOnly(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	fixture := strings.Replace(sampleSettings,
		"\t// telemetry opt-out",
		"\t/* managed below */\n\t\"extensions.allowed\": { \"old.ext\": true /* stale */ },\n\n\t// telemetry opt-out", 1)
	writeSettingsFixture(t, path, fixture)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}
	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)
	if strings.Contains(after, "old.ext") {
		t.Fatalf("stale policy value survived the replace:\n%s", after)
	}
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

// TestSettingsWriteLeavesRecoverableBackup pins the safety net for editing a
// file the user owns: before overwriting settings.json the writer (through
// atomicfile) drops a sibling `<path>.dmg-<stamp>.bak` holding the EXACT prior
// bytes, so a botched write is always recoverable. A single write yields
// exactly one backup; retention beyond that (the MaxBackups=3 cap and prune
// ordering) is atomicfile's own concern — and can't be exercised through Write
// here because the stamp has second granularity, so sub-second writes collide
// on one filename. atomicfile_test.go covers the cap with an injectable clock.
func TestSettingsWriteLeavesRecoverableBackup(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	backups, err := filepath.Glob(path + atomicfile.BackupPrefix + "*" + atomicfile.BackupExt)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("want exactly 1 backup after one write, got %d: %v", len(backups), backups)
	}
	// The backup must be the pre-write file verbatim — the point is a usable
	// rollback, not merely some file ending in .bak.
	if got := readFileString(t, backups[0]); got != sampleSettings {
		t.Fatalf("backup is not the original file:\nbackup:\n%s\n--- want:\n%s", got, sampleSettings)
	}
	// Sanity: the live file took the new key (we backed up the OLD content, and
	// the write still landed).
	if got, present, err := w.Read(); err != nil || !present || got != samplePolicyObject {
		t.Fatalf("live file Read = (%q, %v, %v), want %q", got, present, err, samplePolicyObject)
	}
}

// TestSettingsWriteCreatingFileMakesNoBackup is the boundary of the rule above:
// a first-ever write (no settings.json yet) has nothing to preserve, so it must
// NOT leave a phantom .bak. Locks the behavior so nobody later "fixes"
// TakeBackup to error on a missing source.
func TestSettingsWriteCreatingFileMakesNoBackup(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}
	backups, err := filepath.Glob(path + atomicfile.BackupPrefix + "*" + atomicfile.BackupExt)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("first-write should make no backup, got %v", backups)
	}
}

func TestSettingsWriteIsByteIdempotent(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	first := readFileString(t, path)
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if second := readFileString(t, path); second != first {
		t.Fatalf("second identical Write changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestSettingsWriteCreatesMissingFileAndDirs(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	// No fixture: neither the User dir nor the file exists.

	rb, err := w.Write(samplePolicyObject)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rb != samplePolicyObject {
		t.Fatalf("readback = %q, want %q", rb, samplePolicyObject)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFileString(t, path)), &m); err != nil {
		t.Fatalf("created file is not plain JSON: %v", err)
	}
	if _, ok := m[allowedExtensionsSettingKey]; !ok || len(m) != 1 {
		t.Fatalf("created file should hold exactly the policy key, got %v", m)
	}
}

func TestSettingsWriteTreatsBlankFileAsEmptyObject(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, "\n  \n")

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write on blank file: %v", err)
	}
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
}

func TestSettingsReadCompactsFormattedValue(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, `{
	"extensions.allowed": {
		// allow-list managed elsewhere
		"github.copilot": true,
		"ms-python.python": "1.2.3",
	},
}`)
	got, present, err := w.Read()
	if err != nil || !present {
		t.Fatalf("Read = (%q, %v, %v), want present", got, present, err)
	}
	want := `{"github.copilot":true,"ms-python.python":"1.2.3"}`
	if got != want {
		t.Fatalf("Read = %q, want compacted %q", got, want)
	}
}

func TestSettingsReadAbsent(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	// Missing file.
	if got, present, err := w.Read(); err != nil || present || got != "" {
		t.Fatalf("Read(missing file) = (%q, %v, %v), want absent", got, present, err)
	}
	// File without the key.
	writeSettingsFixture(t, path, sampleSettings)
	if got, present, err := w.Read(); err != nil || present || got != "" {
		t.Fatalf("Read(no key) = (%q, %v, %v), want absent", got, present, err)
	}
}

func TestSettingsClearRemovesOnlyTheKey(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	after := readFileString(t, path)
	assertFragmentsPreserved(t, after)
	if strings.Contains(after, allowedExtensionsSettingKey) {
		t.Fatalf("policy key survived Clear:\n%s", after)
	}
	if _, present, err := w.Read(); err != nil || present {
		t.Fatalf("key still present after Clear (err=%v)", err)
	}
}

func TestSettingsClearAbsentIsNoOp(t *testing.T) {
	w, path := newTestSettingsWriter(t)

	// Missing file: Clear must not create it.
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear(missing file): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Clear created the settings file")
	}

	// File without the key: Clear must not rewrite it.
	writeSettingsFixture(t, path, sampleSettings)
	if err := w.Clear(); err != nil {
		t.Fatalf("Clear(no key): %v", err)
	}
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("Clear rewrote a file it had no key in:\n%s", got)
	}
}

func TestSettingsUnsalvageableFileIsNeverTouched(t *testing.T) {
	const broken = `{"editor.fontSize": 14, <<<garbage` // not JSONC

	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, broken)

	if _, _, err := w.Read(); err == nil {
		t.Fatal("Read on unparseable file: want error")
	}
	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write on unparseable file: want error")
	}
	if err := w.Clear(); err == nil {
		t.Fatal("Clear on unparseable file: want error")
	}
	if got := readFileString(t, path); got != broken {
		t.Fatalf("unparseable file was modified:\n%s", got)
	}
}

func TestSettingsRootNotObjectIsNeverTouched(t *testing.T) {
	const arrayRoot = `[1, 2, 3] // valid JSONC, wrong shape`

	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, arrayRoot)

	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write on non-object root: want error")
	}
	if got := readFileString(t, path); got != arrayRoot {
		t.Fatalf("non-object file was modified:\n%s", got)
	}
}

func TestSettingsWriteRejectsNonObjectValue(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	for _, bad := range []string{`"a string"`, `[1,2]`, `42`, `not json at all`, ``} {
		if _, err := w.Write(bad); err == nil {
			t.Errorf("Write(%q): want error", bad)
		}
	}
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("rejected value still modified the file:\n%s", got)
	}
}

func TestSettingsWriteFailureLeavesFileUntouched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write-permission semantics differ on Windows")
	}
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)

	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if _, err := w.Write(samplePolicyObject); err == nil {
		t.Fatal("Write into read-only dir: want error")
	}
	_ = os.Chmod(dir, 0o755)
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("failed write modified the file:\n%s", got)
	}
}

func TestSettingsPathPerOS(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Setenv("APPDATA", `C:\Users\dev\AppData\Roaming`)
		got, ok := settingsPath()
		want := filepath.Join(`C:\Users\dev\AppData\Roaming`, "Code", "User", "settings.json")
		if !ok || got != want {
			t.Fatalf("settingsPath = (%q, %v), want (%q, true)", got, ok, want)
		}
		t.Setenv("APPDATA", "")
		if _, ok := settingsPath(); ok {
			t.Fatal("settingsPath with empty %APPDATA%: want ok=false")
		}
	case "darwin":
		got, ok := settingsPath()
		want := filepath.Join("Library", "Application Support", "Code", "User", "settings.json")
		if !ok || !strings.HasSuffix(got, want) {
			t.Fatalf("settingsPath = (%q, %v), want suffix %q", got, ok, want)
		}
	case "linux":
		t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
		got, ok := settingsPath()
		want := filepath.Join("/tmp/xdg-test", "Code", "User", "settings.json")
		if !ok || got != want {
			t.Fatalf("settingsPath = (%q, %v), want (%q, true)", got, ok, want)
		}
		t.Setenv("XDG_CONFIG_HOME", "")
		got, ok = settingsPath()
		if !ok || !strings.HasSuffix(got, filepath.Join(".config", "Code", "User", "settings.json")) {
			t.Fatalf("settingsPath without XDG = (%q, %v), want ~/.config suffix", got, ok)
		}
	default:
		if _, ok := settingsPath(); ok {
			t.Fatalf("settingsPath on %s: want ok=false", runtime.GOOS)
		}
	}
}

// --- managed multi-key API -------------------------------------------------

// TestApplyManagedAllowlistOnlyMatchesWriteBytes pins that a managed write of
// only the allowlist produces settings.json bytes identical to the single-key
// Write, so the allowlist path is unchanged in effect.
func TestApplyManagedAllowlistOnlyMatchesWriteBytes(t *testing.T) {
	w1, p1 := newTestSettingsWriter(t)
	writeSettingsFixture(t, p1, sampleSettings)
	if _, err := w1.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	w2, p2 := newTestSettingsWriter(t)
	writeSettingsFixture(t, p2, sampleSettings)
	if _, err := w2.ApplyManaged([]settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)}}); err != nil {
		t.Fatalf("ApplyManaged: %v", err)
	}

	if b1, b2 := readFileString(t, p1), readFileString(t, p2); b1 != b2 {
		t.Fatalf("ApplyManaged(allowlist-only) bytes differ from Write:\n--- Write:\n%s\n--- ApplyManaged:\n%s", b1, b2)
	}
}

func TestApplyManagedWritesBothKeysPreservingFile(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	rb, err := w.ApplyManaged([]settingOp{
		{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)},
		{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(galleryRaw(galURLA))},
	})
	if err != nil {
		t.Fatalf("ApplyManaged: %v", err)
	}
	if al := rb[allowedExtensionsSettingKey]; !al.Present || al.Raw != samplePolicyObject {
		t.Fatalf("allowlist readback = %+v", al)
	}
	if gal := rb[galleryServiceURLSettingKey]; !gal.Present || gal.Raw != galleryRaw(galURLA) {
		t.Fatalf("gallery readback = %+v", gal)
	}
	assertFragmentsPreserved(t, readFileString(t, path))
	// Confirm on-disk persistence of both keys (fresh read).
	got, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatal(err)
	}
	if got[allowedExtensionsSettingKey].Raw != samplePolicyObject || got[galleryServiceURLSettingKey].Raw != galleryRaw(galURLA) {
		t.Fatalf("on-disk keys = %+v", got)
	}
}

func TestApplyManagedRemoveGalleryToleratesAbsence(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	if _, err := w.ApplyManaged([]settingOp{
		{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)},
		{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(galleryRaw(galURLA))},
	}); err != nil {
		t.Fatalf("ApplyManaged set: %v", err)
	}
	if _, err := w.ApplyManaged([]settingOp{{Key: galleryServiceURLSettingKey, Remove: true}}); err != nil {
		t.Fatalf("ApplyManaged remove: %v", err)
	}
	got, _ := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if got[galleryServiceURLSettingKey].Present {
		t.Fatal("gallery must be removed")
	}
	if !got[allowedExtensionsSettingKey].Present {
		t.Fatal("allowlist must remain")
	}
	// Removing an already-absent key is a no-op: no error, no rewrite.
	before := readFileString(t, path)
	if _, err := w.ApplyManaged([]settingOp{{Key: galleryServiceURLSettingKey, Remove: true}}); err != nil {
		t.Fatalf("ApplyManaged remove-absent: %v", err)
	}
	if after := readFileString(t, path); after != before {
		t.Fatalf("remove of an absent key rewrote the file:\n--- before:\n%s\n--- after:\n%s", before, after)
	}
}

func TestApplyManagedLeavesUnmentionedKeys(t *testing.T) {
	// A foreign gallery value already on disk; a write mentioning ONLY the
	// allowlist must leave it (and every other key/comment) untouched.
	w, path := newTestSettingsWriter(t)
	fixture := strings.Replace(sampleSettings,
		"\t// telemetry opt-out",
		"\t\"extensions.gallery.serviceUrl\": \"https://foreign.example/api/v1\",\n\n\t// telemetry opt-out", 1)
	writeSettingsFixture(t, path, fixture)
	if _, err := w.ApplyManaged([]settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)}}); err != nil {
		t.Fatalf("ApplyManaged: %v", err)
	}
	got, _ := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if got[allowedExtensionsSettingKey].Raw != samplePolicyObject {
		t.Fatalf("allowlist = %+v", got[allowedExtensionsSettingKey])
	}
	if got[galleryServiceURLSettingKey].Raw != `"https://foreign.example/api/v1"` {
		t.Fatalf("foreign gallery value must be preserved untouched, got %+v", got[galleryServiceURLSettingKey])
	}
	assertFragmentsPreserved(t, readFileString(t, path))
}

func TestReadManagedPresenceFlags(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	// Missing file: all absent.
	got, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatal(err)
	}
	if got[allowedExtensionsSettingKey].Present || got[galleryServiceURLSettingKey].Present {
		t.Fatalf("missing file → all absent, got %+v", got)
	}
	// A present-but-empty-string value is distinct from absent.
	writeSettingsFixture(t, path, `{"extensions.gallery.serviceUrl": ""}`)
	got, err = w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatal(err)
	}
	if got[allowedExtensionsSettingKey].Present {
		t.Fatalf("allowlist must be absent, got %+v", got[allowedExtensionsSettingKey])
	}
	if gv := got[galleryServiceURLSettingKey]; !gv.Present || gv.Raw != `""` {
		t.Fatalf("gallery must be present-empty (Raw==%q), got %+v", `""`, gv)
	}
}

func TestRestoreManagedRoundTrip(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	// Snapshot: allowlist present, gallery absent.
	if _, err := w.ApplyManaged([]settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatal(err)
	}
	// Mutate away: change allowlist, add gallery.
	if _, err := w.ApplyManaged([]settingOp{
		{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(`{"changed":true}`)},
		{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(galleryRaw(galURLA))},
	}); err != nil {
		t.Fatal(err)
	}
	// Restore → back to the snapshot exactly.
	if err := w.RestoreManaged(snapshot); err != nil {
		t.Fatalf("RestoreManaged: %v", err)
	}
	got, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatal(err)
	}
	if got[allowedExtensionsSettingKey] != snapshot[allowedExtensionsSettingKey] {
		t.Fatalf("allowlist not restored: got %+v want %+v", got[allowedExtensionsSettingKey], snapshot[allowedExtensionsSettingKey])
	}
	if got[galleryServiceURLSettingKey].Present {
		t.Fatalf("gallery should be restored to absent, got %+v", got[galleryServiceURLSettingKey])
	}
}

func TestManagedMethodsRefuseUnsalvageableFile(t *testing.T) {
	const broken = `{"editor.fontSize": 14, <<<garbage`
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, broken)
	if _, err := w.ReadManaged([]string{allowedExtensionsSettingKey}); err == nil {
		t.Fatal("ReadManaged on unparseable file: want error")
	}
	if _, err := w.ApplyManaged([]settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)}}); err == nil {
		t.Fatal("ApplyManaged on unparseable file: want error")
	}
	if got := readFileString(t, path); got != broken {
		t.Fatalf("unparseable file was modified:\n%s", got)
	}

	const arrayRoot = `[1,2,3]`
	writeSettingsFixture(t, path, arrayRoot)
	if _, err := w.ApplyManaged([]settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)}}); err == nil {
		t.Fatal("ApplyManaged on non-object root: want error")
	}
	if got := readFileString(t, path); got != arrayRoot {
		t.Fatalf("non-object file was modified:\n%s", got)
	}
}

func TestApplyManagedRejectsInvalidJSONValue(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, sampleSettings)
	if _, err := w.ApplyManaged([]settingOp{{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(`not json`)}}); err == nil {
		t.Fatal("ApplyManaged with invalid JSON value: want error")
	}
	if got := readFileString(t, path); got != sampleSettings {
		t.Fatalf("rejected value modified the file:\n%s", got)
	}
}

func TestApplyManagedEscapesUnusualKeys(t *testing.T) {
	// The managed key set is backend-driven. A key holding JSON-Pointer
	// metacharacters ('/', '~') or JSON-string metacharacters ('"', '\') must be
	// written as ONE literal top-level member — never a nested pointer path, and
	// never a corrupt patch document that clobbers the file.
	for _, key := range []string{`weird/key`, `tilde~key`, `quote"key`, `back\slash`} {
		w, path := newTestSettingsWriter(t)
		writeSettingsFixture(t, path, `{"keep.me": 1}`)
		if _, err := w.ApplyManaged([]settingOp{{Key: key, Set: true, Value: json.RawMessage(`"v"`)}}); err != nil {
			t.Fatalf("ApplyManaged(%q): %v", key, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(readFileString(t, path)), &m); err != nil {
			t.Fatalf("file not valid JSON after writing key %q: %v", key, err)
		}
		if string(m["keep.me"]) != "1" {
			t.Fatalf("untouched key lost after writing %q: %v", key, m)
		}
		if got, ok := m[key]; !ok || string(got) != `"v"` {
			t.Fatalf("key %q must be one literal top-level member = \"v\", got ok=%v val=%s", key, ok, got)
		}
	}
}

// TestGalleryValueRoundTrips pins the ownership invariant on the value path the
// reconciler now uses: the gallery URL arrives as a JSON string in the settings
// map, is compacted (compactPolicySettings), written, and recorded as owned — and that
// value must equal what a write→read round-trip returns, or ownership /
// convergence would churn forever. Includes a URL with &, =, <, > — the
// HTML-escaping edge (canonical JSON must not HTML-escape; json.Compact and the
// JSONC writer both preserve the literal token byte-for-byte).
func TestGalleryValueRoundTrips(t *testing.T) {
	for _, wire := range []string{
		`"https://mkt.example/api/v1"`,
		`"https://mkt.example/api/v1?tenant=acme&mode=strict"`,
		`"https://mkt.example/p/<odd>"`,
	} {
		w, _ := newTestSettingsWriter(t)
		gv, err := compactJSON([]byte(wire))
		if err != nil {
			t.Fatalf("compactJSON(%s): %v", wire, err)
		}
		if _, err := w.ApplyManaged([]settingOp{{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(gv)}}); err != nil {
			t.Fatalf("ApplyManaged(%s): %v", wire, err)
		}
		got, err := w.ReadManaged([]string{galleryServiceURLSettingKey})
		if err != nil {
			t.Fatal(err)
		}
		if sv := got[galleryServiceURLSettingKey]; !sv.Present || sv.Raw != gv {
			t.Fatalf("wire %s: readback Raw=%q, want %q (owned value must equal readback)", wire, sv.Raw, gv)
		}
	}
}

// --- UTF-8 BOM ---------------------------------------------------------------
//
// A settings.json carrying a leading BOM must be fully enforceable. The mark is
// not whitespace and is not a valid start of a JSON value, so before it was
// split off in load() every entry point failed with "not valid JSONC" — and
// permanently, because removing the three bytes needs the write the writer then
// refused. VS Code strips it on read; tooling that seeds the file emits it
// (PowerShell 5.1's Set-Content -Encoding UTF8, editors set to utf8bom).

// Escaped, not literal: the Go scanner rejects a raw BOM inside a source file.
const utf8BOM = "\ufeff"

func TestSettingsBOMFileIsReadable(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, utf8BOM+`{"extensions.allowed":`+samplePolicyObject+`}`)

	got, present, err := w.Read()
	if err != nil {
		t.Fatalf("Read on BOM file: %v", err)
	}
	if !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v), want (%q, true)", got, present, samplePolicyObject)
	}

	m, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatalf("ReadManaged on BOM file: %v", err)
	}
	if sv := m[allowedExtensionsSettingKey]; !sv.Present || sv.Raw != samplePolicyObject {
		t.Fatalf("ReadManaged allowed = %+v, want present %q", sv, samplePolicyObject)
	}
	if sv := m[galleryServiceURLSettingKey]; sv.Present {
		t.Fatalf("ReadManaged gallery = %+v, want absent", sv)
	}
}

// The BOM is the user's file encoding, not a value the agent owns: a write
// preserves it, exactly once, still at the very front.
func TestSettingsWritePreservesBOM(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, utf8BOM+sampleSettings)

	rb, err := w.Write(samplePolicyObject)
	if err != nil {
		t.Fatalf("Write on BOM file: %v", err)
	}
	if rb != samplePolicyObject {
		t.Fatalf("readback = %q, want %q", rb, samplePolicyObject)
	}

	after := readFileString(t, path)
	if !strings.HasPrefix(after, utf8BOM) {
		t.Fatalf("BOM lost from the front of the file: %q", after)
	}
	if n := strings.Count(after, utf8BOM); n != 1 {
		t.Fatalf("BOM appears %d times, want exactly 1: %q", n, after)
	}
	assertFragmentsPreserved(t, after)

	// A second write must not accumulate marks, and must stay byte-idempotent.
	before := after
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if got := readFileString(t, path); got != before {
		t.Fatalf("second write not byte-idempotent on a BOM file:\n%q\n--- vs ---\n%q", got, before)
	}
}

// Clear must work on a BOM file too — otherwise an unassignment can never
// remove the key the agent wrote, leaving policy applied after offboarding.
func TestSettingsClearPreservesBOM(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, utf8BOM+sampleSettings)
	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Clear(); err != nil {
		t.Fatalf("Clear on BOM file: %v", err)
	}
	if _, present, err := w.Read(); err != nil || present {
		t.Fatalf("Read after Clear = (present=%v, err=%v), want absent", present, err)
	}

	after := readFileString(t, path)
	if !strings.HasPrefix(after, utf8BOM) || strings.Count(after, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once through Clear: %q", after)
	}
	assertFragmentsPreserved(t, after)
}

// ApplyManaged / RestoreManaged share load+store with the single-key path, so
// the multi-key lane must round-trip a BOM file too.
func TestApplyAndRestoreManagedPreserveBOM(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, utf8BOM+sampleSettings)

	gallery := `"https://mkt.example/api/v1"`
	snapshot, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey})
	if err != nil {
		t.Fatalf("ReadManaged: %v", err)
	}
	if _, err := w.ApplyManaged([]settingOp{
		{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(samplePolicyObject)},
		{Key: galleryServiceURLSettingKey, Set: true, Value: json.RawMessage(gallery)},
	}); err != nil {
		t.Fatalf("ApplyManaged on BOM file: %v", err)
	}
	after := readFileString(t, path)
	if !strings.HasPrefix(after, utf8BOM) || strings.Count(after, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once through ApplyManaged: %q", after)
	}

	if err := w.RestoreManaged(snapshot); err != nil {
		t.Fatalf("RestoreManaged: %v", err)
	}
	restored := readFileString(t, path)
	if !strings.HasPrefix(restored, utf8BOM) || strings.Count(restored, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once through RestoreManaged: %q", restored)
	}
	if m, err := w.ReadManaged([]string{allowedExtensionsSettingKey, galleryServiceURLSettingKey}); err != nil {
		t.Fatal(err)
	} else if m[allowedExtensionsSettingKey].Present || m[galleryServiceURLSettingKey].Present {
		t.Fatalf("rollback left a managed key behind: %+v", m)
	}
	assertFragmentsPreserved(t, restored)
}

// A file holding nothing but a BOM is the blank-file case once the mark is off
// the front — an empty object to patch a first key into, not a parse error.
func TestSettingsBOMOnlyFileIsTreatedAsEmptyObject(t *testing.T) {
	w, path := newTestSettingsWriter(t)
	writeSettingsFixture(t, path, utf8BOM)

	if _, err := w.Write(samplePolicyObject); err != nil {
		t.Fatalf("Write on BOM-only file: %v", err)
	}
	got, present, err := w.Read()
	if err != nil || !present || got != samplePolicyObject {
		t.Fatalf("Read = (%q, %v, %v), want (%q, true, nil)", got, present, err, samplePolicyObject)
	}
	if after := readFileString(t, path); !strings.HasPrefix(after, utf8BOM) || strings.Count(after, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once: %q", after)
	}
}

// The BOM must not become a way to smuggle a broken file past the
// never-clobber contract: with the mark off the front, the remainder is still
// parsed, and unparseable content is still refused without a write.
func TestSettingsBOMDoesNotBypassNeverClobber(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unparseable", `{"extensions.allowed": ,,,}`},
		{"root not object", `[1,2,3]`},
		{"second BOM inside", utf8BOM + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newTestSettingsWriter(t)
			content := utf8BOM + tc.body
			writeSettingsFixture(t, path, content)

			if _, err := w.Write(samplePolicyObject); err == nil {
				t.Fatal("Write must refuse a BOM file whose remainder is not a JSON object")
			}
			if got := readFileString(t, path); got != content {
				t.Fatalf("file was modified:\n%q\n--- want unchanged ---\n%q", got, content)
			}
		})
	}
}

// End to end over the REAL writer (not a fake), because the symptom was a
// compliance state, not a parse error: a BOM'd settings.json reported
// verification_failed on every cycle forever, with the file untouched, and no
// signal to the developer beyond the agent log. Enforce must converge and report
// compliant instead — and the clear that follows must remove the key it wrote.
func TestReconcileEnforcesAndClearsThroughABOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "User", "settings.json")
	writeSettingsFixture(t, path, utf8BOM+sampleSettings)

	r, rep := newRec(t, policyEP("sha256:H"), nil, nil)
	r.Writer = newSettingsWriterAt(path)

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := lastReport(t, rep); got.State != StateCompliant {
		t.Fatalf("state = %q, want %q", got.State, StateCompliant)
	}
	after := readFileString(t, path)
	if !strings.HasPrefix(after, utf8BOM) || strings.Count(after, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once through enforce: %q", after)
	}
	assertFragmentsPreserved(t, after)

	// Unassignment: the key the agent just wrote must come back out.
	rep.reports = nil
	r.Fetcher = &fakeFetcher{ep: EffectivePolicy{Category: CategoryIDEExtension, Clear: true}}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile(clear): %v", err)
	}
	if m, err := r.Writer.(managedSettingsWriter).ReadManaged([]string{allowedExtensionsSettingKey}); err != nil {
		t.Fatal(err)
	} else if m[allowedExtensionsSettingKey].Present {
		t.Fatalf("clear left the agent-written key behind: %+v", m)
	}
	if final := readFileString(t, path); !strings.HasPrefix(final, utf8BOM) || strings.Count(final, utf8BOM) != 1 {
		t.Fatalf("BOM not preserved exactly once through clear: %q", final)
	}
}
