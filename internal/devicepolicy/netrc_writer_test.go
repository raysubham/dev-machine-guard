package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const netrcExpected = "machine registry.stepsecurity.io\nlogin step-security\npassword step_acme-1_uuid::dev:DEVICE-123"

func newNetrcTestWriter(t *testing.T, initial []byte) (*NetrcWriter, string) {
	t.Helper()
	t.Setenv("NETRC", "")
	home := t.TempDir()
	if initial != nil {
		if err := os.WriteFile(filepath.Join(home, ".netrc"), initial, 0o600); err != nil {
			t.Fatalf("seed .netrc: %v", err)
		}
	}
	h := newSecureTestHome(t, home)
	w, err := NewNetrcWriter(h, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewNetrcWriter: %v", err)
	}
	return w, filepath.Join(home, ".netrc")
}

func netrcTestPolicy(t *testing.T) PyPIPolicy {
	t.Helper()
	policy, err := ParsePyPIPolicy(json.RawMessage(`{"ecosystem":"pypi","clients":["pip","uv"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`), "DEVICE-123")
	if err != nil {
		t.Fatalf("ParsePyPIPolicy: %v", err)
	}
	return policy
}

func TestNetrcWriter_PreservesOrdinaryGrammarAndClearRestores(t *testing.T) {
	initial := []byte("\ufeff# keep this comment\r\nmachine files.example login \"user name\" account deploy password \"secret with space\"\r\ndefault login fallback password fallback-secret\r\n")
	w, path := newNetrcTestWriter(t, initial)

	got, err := w.Write(netrcExpected)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != netrcExpected {
		t.Fatalf("Write readback = %q, want exact managed entry", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), string(initial)) {
		t.Fatalf("unrelated netrc bytes changed:\n%s", content)
	}
	if !strings.Contains(string(content), "\r\n"+dmgNetrcBegin+"\r\n") || strings.Contains(strings.ReplaceAll(string(content), "\r\n", ""), "\n") {
		t.Fatalf("managed block did not preserve CRLF style:\n%q", content)
	}
	if converged, err := w.Converged(netrcExpected); err != nil || !converged {
		t.Fatalf("Converged = %v, %v, want true", converged, err)
	}

	changed, err := w.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !changed {
		t.Fatal("Clear changed = false, want true")
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(initial) {
		t.Fatalf("clear restored %q, want exact original %q", restored, initial)
	}
}

func TestNetrcWriter_MigratesOneExactHostReversibly(t *testing.T) {
	initial := []byte("# before\nmachine registry.stepsecurity.io\n  login old-user\n  account old-account\n  password old-secret\nmachine other.example login other password other-secret")
	w, path := newNetrcTestWriter(t, initial)

	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"machine registry.stepsecurity.io",
		"  login old-user",
		"  account old-account",
		"  password old-secret",
	} {
		if !strings.Contains(string(content), dmgNetrcDisabledPrefix+line) {
			t.Errorf("migration did not reversibly comment %q:\n%s", line, content)
		}
	}
	if !strings.Contains(string(content), "machine other.example login other password other-secret") {
		t.Fatalf("unrelated host was not preserved:\n%s", content)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(initial) {
		t.Fatalf("clear restored %q, want exact original %q", restored, initial)
	}
}

func TestNetrcWriter_CreatesRotatesAndRemovesCredential(t *testing.T) {
	w, path := newNetrcTestWriter(t, nil)
	if w.Location() != path {
		t.Fatalf("Location = %q, want %q", w.Location(), path)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if enforcePOSIXMetadata && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}

	rotated := strings.Replace(netrcExpected, "step_acme-1_uuid", "step_acme-1_rotated", 1)
	_, writeErr := w.Write(rotated)
	if writeErr == nil {
		t.Fatal("Write accepted an entry different from the constructor policy")
	}
	if strings.Contains(writeErr.Error(), "step_acme") {
		t.Fatalf("Write error leaked credential material: %v", writeErr)
	}

	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential-only file remains after clear: %v", err)
	}
	if backups, err := filepath.Glob(path + ".dmg-*.bak"); err != nil || len(backups) != 0 {
		t.Fatalf("backups after clear = %v, %v, want none", backups, err)
	}
	staleBackup := path + ".dmg-stale.bak"
	if err := os.WriteFile(staleBackup, []byte("stale protected credential backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Clear(); err != nil || changed {
		t.Fatalf("absent-file Clear = %v, %v, want unchanged", changed, err)
	}
	if _, err := os.Stat(staleBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale credential backup remains after clear: %v", err)
	}
}

func TestParseNetrc_PreservesHashInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"embedded hash", "pa#ss"},
		{"leading hash", "#secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("# comment\nmachine other.example login user password " + tc.password + "\n")
			entries, err := parseNetrc(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].pass != tc.password {
				t.Fatalf("entries = %+v, want password %q", entries, tc.password)
			}
		})
	}
}

func TestNetrcWriter_RejectsAmbiguousOrMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"duplicate exact host", "machine registry.stepsecurity.io login one password old\nmachine registry.stepsecurity.io login two password old"},
		{"exact host shares a line", "machine other.example login u password p machine registry.stepsecurity.io login stale password old"},
		{"macdef", "macdef init\necho unsafe\n\nmachine other.example login u password p\n"},
		{"unterminated quote", "machine other.example login \"unterminated"},
		{"missing directive value", "machine other.example login"},
		{"unknown directive", "machine other.example protocol https"},
		{"duplicate default", "default login one\ndefault login two"},
		{"duplicate begin marker", dmgNetrcBegin + "\n" + dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n"},
		{"duplicate end marker", dmgNetrcBegin + "\n" + netrcExpected + "\n" + dmgNetrcEnd + "\n" + dmgNetrcEnd + "\n"},
		{"incomplete MDM marker", mdmNetrcBegin + "\n" + netrcExpected + "\n"},
		{"end before begin", dmgNetrcEnd + "\n" + dmgNetrcBegin + "\n" + netrcExpected + "\n"},
		{"lone carriage return", "machine other.example\rlogin user"},
		{"invalid utf8", string([]byte{0xff, 0xfe})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte(tc.body))
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(netrcExpected); err == nil {
				t.Fatal("Write error = nil, want fail-closed refusal")
			} else if strings.Contains(err.Error(), "step_acme") || strings.Contains(err.Error(), "old-secret") {
				t.Fatalf("Write error leaked credential material: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("refused write changed file: before=%q after=%q", before, after)
			}
		})
	}
}

func TestNetrcWriter_ObservationUsesExactTokenAndNETRCOverride(t *testing.T) {
	w, _ := newNetrcTestWriter(t, nil)
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenAbsent {
		t.Fatalf("absent Observation = %q, %v", status, err)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatal(err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("matching Observation = %q, %v", status, err)
	}

	prefixOnly := strings.TrimSuffix(netrcExpected, "DEVICE-123")
	content, err := os.ReadFile(w.Location())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.Location(), bytes.Replace(content, []byte(netrcExpected), []byte(prefixOnly), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMismatch {
		t.Fatalf("prefix-only on-disk Observation = %q, %v, want mismatch", status, err)
	}
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatalf("repair after prefix-only token: %v", err)
	}

	t.Setenv("NETRC", filepath.Join(t.TempDir(), "alternate.netrc"))
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMismatch {
		t.Fatalf("NETRC override Observation = %q, %v, want mismatch", status, err)
	}
	t.Setenv("NETRC", w.Location())
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("exact NETRC Observation = %q, %v, want match", status, err)
	}
}

func TestNetrcWriter_SecurityRefusalsAndPermissionRepair(t *testing.T) {
	t.Run("wrong owner", func(t *testing.T) {
		w, _ := newNetrcTestWriter(t, []byte("machine other.example login u password p\n"))
		w.file.home.owners = netrcFakeOwner{uid: uint32(w.file.home.uid + 1), enforced: true}
		if _, err := w.Write(netrcExpected); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want ErrTargetUnusable", err)
		}
	})

	t.Run("non-regular", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want ErrTargetUnusable", err)
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		outside := filepath.Join(t.TempDir(), "outside.netrc")
		if err := os.WriteFile(outside, []byte("machine other.example login u password p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want ErrTargetUnusable", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		w, path := newNetrcTestWriter(t, nil)
		if err := os.WriteFile(path, []byte(strings.Repeat("x", maxManagedUserFileBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(netrcExpected); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Write error = %v, want ErrTargetUnusable", err)
		}
	})

	if enforcePOSIXMetadata {
		t.Run("loose mode repaired", func(t *testing.T) {
			w, path := newNetrcTestWriter(t, []byte("machine other.example login u password p\n"))
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if converged, err := w.Converged(netrcExpected); err != nil || converged {
				t.Fatalf("Converged before repair = %v, %v, want false", converged, err)
			}
			if _, err := w.Write(netrcExpected); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode after write = %#o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func TestNetrcWriter_OwnershipStateNeverPersistsCredential(t *testing.T) {
	t.Setenv("NETRC", "")
	homeDir := t.TempDir()
	home := newSecureTestHome(t, homeDir)
	withTempCache(t)
	if err := WriteAppliedState(CategoryPackageConfig, TargetPyPI, AppliedTargetState{
		AppliedHash:     "sibling",
		WrittenSettings: map[string]string{"keep": "non-secret"},
	}); err != nil {
		t.Fatal(err)
	}

	run := func(raw, hash string) *NetrcWriter {
		t.Helper()
		policy, err := ParsePyPIPolicy(json.RawMessage(raw), "DEVICE-123")
		if err != nil {
			t.Fatal(err)
		}
		writer, err := NewNetrcWriter(home, policy)
		if err != nil {
			t.Fatal(err)
		}
		r := &Reconciler{
			Fetcher: &fakeFetcher{ep: EffectivePolicy{
				Category: CategoryPackageConfig,
				Target:   TargetPyPI,
				Policy:   json.RawMessage(raw),
				Hash:     hash,
			}},
			Writer:              writer,
			Category:            CategoryPackageConfig,
			Target:              TargetPyPI,
			OwnershipTarget:     PyPICredentialOwnershipTarget,
			OwnershipStateValue: PyPICredentialOwnershipValue,
			OwnershipKey:        "credential",
			OwnsByMarker:        true,
			Render: func(raw json.RawMessage) (string, error) {
				parsed, err := ParsePyPIPolicy(raw, "DEVICE-123")
				if err != nil {
					return "", err
				}
				return renderNetrcEntry(parsed.RegistryHost(), parsed.DeviceToken()), nil
			},
			Converged:       writer.Converged,
			RestoreSnapshot: writer.RestoreSnapshot,
			Probe:           func() (bool, string) { return false, "" },
			Now:             func() time.Time { return time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC) },
		}
		if err := r.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		assertNetrcStateSecretFree(t, pypiKey, policy.DeviceToken())
		return writer
	}

	oldRaw := `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`
	writer := run(oldRaw, "sha256:OLD")
	run(oldRaw, "sha256:OLD") // idempotent convergence

	content, err := os.ReadFile(writer.Location())
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte("step_acme-1_uuid::dev:DEVICE-123"), []byte("tampered"), 1)
	if err := os.WriteFile(writer.Location(), content, 0o600); err != nil {
		t.Fatal(err)
	}
	run(oldRaw, "sha256:OLD") // same-hash drift repair

	newRaw := `{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"step_rotated"}}`
	writer = run(newRaw, "sha256:NEW")
	assertNetrcStateSecretFree(t, "step_rotated", "step_rotated::dev:DEVICE-123")

	r := &Reconciler{
		Fetcher:             &fakeFetcher{ep: EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}},
		Writer:              writer,
		Category:            CategoryPackageConfig,
		Target:              TargetPyPI,
		OwnershipTarget:     PyPICredentialOwnershipTarget,
		OwnershipStateValue: PyPICredentialOwnershipValue,
		OwnershipKey:        "credential",
		OwnsByMarker:        true,
		RestoreSnapshot:     writer.RestoreSnapshot,
		Probe:               func() (bool, string) { return false, "" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("clear Reconcile: %v", err)
	}
	assertNetrcStateSecretFree(t, pypiKey, "step_rotated", "::dev:")
	if _, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget); ok {
		t.Fatal("credential ownership state remains after clear")
	}
}

func assertNetrcStateSecretFree(t *testing.T, forbidden ...string) {
	t.Helper()
	state, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatalf("read complete ownership state: %v", err)
	}
	for _, value := range forbidden {
		if value != "" && bytes.Contains(state, []byte(value)) {
			t.Fatalf("ownership state contains credential material %q: %s", value, state)
		}
	}
}

func TestNetrcWriter_MDMOwnershipRequiresExactHostInsideBlock(t *testing.T) {
	tests := []struct {
		name    string
		initial string
	}{
		{"unmarked", netrcExpected + "\n"},
		{"marker around other host", mdmNetrcBegin + "\nmachine other.example login step-security password other\n" + mdmNetrcEnd + "\n" + netrcExpected + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newNetrcTestWriter(t, []byte(tc.initial))
			owned, err := w.MDMOwned()
			if err != nil {
				t.Fatal(err)
			}
			if owned {
				t.Fatal("MDMOwned = true, want false")
			}
		})
	}
}

func TestNetrcWriter_ReadAndMDMMarker(t *testing.T) {
	w, _ := newNetrcTestWriter(t, []byte(mdmNetrcBegin+"\n"+netrcExpected+"\n"+mdmNetrcEnd+"\n"))
	hardenSecureTestFile(t, w.file)
	if present, err := w.HasMDMMarker(); err != nil || !present {
		t.Fatalf("HasMDMMarker = %v, %v, want true", present, err)
	}
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	if _, present, err := w.Read(); err != nil || present {
		t.Fatalf("Read DMG block = present %v, %v, want absent", present, err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMatch {
		t.Fatalf("MDM credential Observation = %q, %v, want match", status, err)
	}
}

type netrcFakeOwner struct {
	uid      uint32
	enforced bool
}

func (f netrcFakeOwner) ownerUIDGID(*os.File) (uint32, uint32, bool, error) {
	return f.uid, 0, f.enforced, nil
}
