package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const pipExpected = "index-url = https://registry.stepsecurity.io/python/simple\nno-index = false"

func newPipTestWriter(t *testing.T, initial []byte) (*PipWriter, *executor.Mock, string) {
	t.Helper()
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	if initial != nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, initial, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	writer, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewPipWriter: %v", err)
	}
	writer.exec = mock
	return writer, mock, path
}

func TestPipWriter_TransformsAndRestoresConflicts(t *testing.T) {
	initial := []byte("# keep\n[install]\nfind_links: ./wheelhouse\nno_index = true\ntrusted-host = old.example\n[global]\ntimeout = 30\nINDEX_URL = https://old.example/simple\nextra-index-url =\n  https://one.example/simple\n  https://two.example/simple\n")
	w, _, path := newPipTestWriter(t, initial)

	got, err := w.Write(pipExpected)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != pipExpected {
		t.Fatalf("Write = %q, want %q", got, pipExpected)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{dmgPipBegin, dmgPipEnd} {
		if !bytes.Contains(content, []byte(marker)) {
			t.Errorf("managed output missing marker %q:\n%s", marker, content)
		}
	}
	for _, line := range []string{
		"INDEX_URL = https://old.example/simple",
		"extra-index-url =",
		"  https://one.example/simple",
		"  https://two.example/simple",
		"find_links: ./wheelhouse",
		"no_index = true",
	} {
		if !bytes.Contains(content, []byte(dmgPipDisabledPrefix+line)) {
			t.Errorf("conflict block line %q was not reversibly disabled:\n%s", line, content)
		}
	}
	if !bytes.Contains(content, []byte("[global]\n"+dmgPipBegin+"\n"+pipExpected+"\n"+dmgPipEnd)) {
		t.Errorf("managed block was not placed inside existing [global]:\n%s", content)
	}
	if converged, err := w.Converged(pipExpected); err != nil || !converged {
		t.Fatalf("Converged = %v, %v, want true", converged, err)
	}

	changed, err := w.Clear()
	if err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("Clear restored:\n%q\nwant:\n%q", restored, initial)
	}
}

func TestPipWriter_AppendsGlobalAndPreservesBOMCRLF(t *testing.T) {
	initial := []byte("\ufeff# comment\r\n[download]\r\ntimeout = 15\r\n")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("\ufeff")) {
		t.Fatal("UTF-8 BOM was not preserved")
	}
	withoutCRLF := bytes.ReplaceAll(got, []byte("\r\n"), nil)
	if bytes.Contains(withoutCRLF, []byte{'\n'}) {
		t.Fatalf("managed output mixed newline styles: %q", got)
	}
	if !bytes.Contains(got, []byte("\r\n"+dmgPipBegin+"\r\n"+pipAppendMetadata)) || !bytes.Contains(got, []byte("\r\n[global]\r\n"+strings.ReplaceAll(pipExpected, "\n", "\r\n"))) {
		t.Fatalf("missing appended [global] managed block: %q", got)
	}
	before := append([]byte(nil), got...)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("idempotent write changed bytes:\nbefore=%q\nafter=%q", before, after)
	}
}

func TestPipWriter_CommentedGlobalHeaderRoundTrips(t *testing.T) {
	initial := []byte("[global] # user comment\ncache-dir = /tmp/cache\n")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	changed, err := w.Clear()
	if err != nil || !changed {
		t.Fatalf("Clear = %v, %v", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("round trip = %q, want %q", got, initial)
	}
}

func TestPipWriter_GlobalHeaderWithoutFinalNewlineRestoresExactly(t *testing.T) {
	initial := []byte("[global]")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("Clear restored %q, want %q", got, initial)
	}
}

func TestPipWriter_RefusesMalformedAndDuplicateINI(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"option before section", []byte("index-url = https://old.example/simple\n")},
		{"duplicate section", []byte("[global]\ntimeout=1\n[GLOBAL]\ntimeout=2\n")},
		{"normalized duplicate option", []byte("[global]\nindex_url=https://one.example\nINDEX-URL=https://two.example\n")},
		{"orphan continuation", []byte("[global]\n  continuation\n")},
		{"malformed section", []byte("[global\ntimeout=1\n")},
		{"lone carriage return", []byte("[global]\rindex-url=x\n")},
		{"invalid UTF-8", []byte{0xff, 0xfe}},
		{"duplicate begin marker", []byte("[global]\n" + dmgPipBegin + "\n" + dmgPipBegin + "\n" + pipExpected + "\n" + dmgPipEnd + "\n")},
		{"MDM marker conflict", []byte("[global]\n" + mdmPipBegin + "\n" + pipExpected + "\n" + mdmPipEnd + "\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, path := newPipTestWriter(t, tc.body)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(pipExpected); err == nil {
				t.Fatal("Write error = nil, want fail-closed refusal")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("refused write changed file: before=%q after=%q", before, after)
			}
		})
	}
}

func TestPipWriter_DriftRepairAndMultipleUserFiles(t *testing.T) {
	homeDir := t.TempDir()
	current := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	legacy := filepath.Join(homeDir, ".pip", "pip.conf")
	for path, body := range map[string]string{
		current: "[global]\ntimeout=30\n",
		legacy:  "[install]\nextra-index-url=https://legacy.example/simple\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	mock.SetFile(current, nil)
	mock.SetFile(legacy, nil)
	w, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current, legacy} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(content, []byte(dmgPipBegin)) {
			t.Errorf("%s was not managed:\n%s", path, content)
		}
	}
	content, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, []byte("extra-index-url=https://drift.example/simple\n")...)
	if err := os.WriteFile(current, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if converged, err := w.Converged(pipExpected); err != nil || converged {
		t.Fatalf("Converged after drift = %v, %v, want false", converged, err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("drift repair: %v", err)
	}
	if converged, err := w.Converged(pipExpected); err != nil || !converged {
		t.Fatalf("Converged after repair = %v, %v, want true", converged, err)
	}
}

func TestPipWriter_MultiFileFailureRollsBackEarlierFiles(t *testing.T) {
	homeDir := t.TempDir()
	current := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	legacy := filepath.Join(homeDir, ".pip", "pip.conf")
	initial := map[string][]byte{
		current: []byte("[global]\ntimeout=30\n"),
		legacy:  []byte("[global]\nextra-index-url=https://legacy.example/simple\n"),
	}
	for path, body := range initial {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	mock.SetFile(current, nil)
	mock.SetFile(legacy, nil)
	w, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err == nil {
		t.Fatal("Write error = nil, want second-file refusal")
	}
	got, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if want := initial[current]; !bytes.Equal(got, want) {
		t.Fatalf("current file after rollback = %q, want %q", got, want)
	}
}

func TestPipWriter_SecurityAndMDMMarker(t *testing.T) {
	w, _, path := newPipTestWriter(t, []byte("[global]\ntimeout=30\n"))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	if enforcePOSIXMetadata {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
		}
	}
	if has, err := w.HasMDMMarker(); err != nil || has {
		t.Fatalf("HasMDMMarker = %v, %v, want false", has, err)
	}
	if err := os.WriteFile(path, []byte("[global]\n"+mdmPipBegin+"\n"+pipExpected+"\n"+mdmPipEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if has, err := w.HasMDMMarker(); err != nil || !has {
		t.Fatalf("HasMDMMarker = %v, %v, want true", has, err)
	}
}

func TestPipObservation_UserEnvironmentFailureIsUnknown(t *testing.T) {
	w, mock, _ := newPipTestWriter(t, nil)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.exec = executor.NewUserAwareExecutor(&failedUserEnvironmentExecutor{Executor: mock}, "alice")
	got, err := w.Observation(context.Background(), pipExpected)
	if err == nil {
		t.Fatal("Observation error = nil, want environment inspection failure")
	}
	if got.EffectiveStatus != "unknown" || got.OverrideSource != "unknown" {
		t.Fatalf("Observation = %+v, want unknown environment", got)
	}
}

func TestPipObservation_VersionBoundaryAndAbsent(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		wantEffective string
	}{
		{"pip absent", "", "not_installed"},
		{"pip below 20.2", "19.3.1", "unknown"},
		{"pip 20.2", "20.2", "match"},
		{"current pip", "25.2", "match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, mock, _ := newPipTestWriter(t, nil)
			if _, err := w.Write(pipExpected); err != nil {
				t.Fatal(err)
			}
			if tc.version != "" {
				mock.SetPath("pip", "/opt/bin/pip")
				mock.SetCommand("pip "+tc.version+" from /opt/pip\n", "", 0, "pip", "--version")
				mock.SetCommand("user:\n", "", 0, "pip", "config", "debug")
				mock.SetCommand("global.index-url='https://registry.stepsecurity.io/python/simple'\nglobal.no-index='false'\n", "", 0, "pip", "config", "list", "-v")
				w.invocations = [][]string{{"pip"}}
			}
			got, err := w.Observation(context.Background(), pipExpected)
			if err != nil {
				t.Fatalf("Observation: %v", err)
			}
			if got.ConfigStatus != "match" || got.EffectiveStatus != tc.wantEffective || got.OverrideSource != "none" {
				t.Fatalf("Observation = %+v, want config match, effective %s, no override", got, tc.wantEffective)
			}
		})
	}
}

func TestPipObservation_OverridesAndUnknownOutput(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*executor.Mock)
		listOutput    string
		wantEffective string
		wantOverride  string
	}{
		{"environment", func(m *executor.Mock) { m.SetEnv("PIP_INDEX_URL", "https://user:SECRET@evil.example/simple") }, "", "mismatch", "environment"},
		{"explicit config", func(m *executor.Mock) { m.SetEnv("PIP_CONFIG_FILE", "/tmp/secret-path") }, "", "mismatch", "explicit_config"},
		{"virtualenv", func(m *executor.Mock) { m.SetEnv("VIRTUAL_ENV", "/tmp/venv") }, "", "mismatch", "virtualenv"},
		{"system config", func(*executor.Mock) {}, "global.index-url='https://evil.example/simple' from /etc/pip.conf\nglobal.no-index='false' from /etc/pip.conf\n", "mismatch", "system_config"},
		{"command section", func(*executor.Mock) {}, "install.index-url='https://evil.example/simple'\nglobal.index-url='https://registry.stepsecurity.io/python/simple'\nglobal.no-index='false'\n", "mismatch", "command_section"},
		{"unknown output", func(*executor.Mock) {}, "changed format without equals\n", "unknown", "unknown"},
		{"userinfo mismatch", func(*executor.Mock) {}, "global.index-url='https://user:SECRET@evil.example/simple'\nglobal.no-index='false'\n", "mismatch", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, mock, _ := newPipTestWriter(t, nil)
			if _, err := w.Write(pipExpected); err != nil {
				t.Fatal(err)
			}
			mock.SetPath("pip", "/opt/bin/pip")
			mock.SetCommand("pip 25.2 from /opt/pip\n", "", 0, "pip", "--version")
			mock.SetCommand("user:\n", "", 0, "pip", "config", "debug")
			mock.SetCommand(tc.listOutput, "", 0, "pip", "config", "list", "-v")
			tc.configure(mock)
			w.invocations = [][]string{{"pip"}}

			got, err := w.Observation(context.Background(), pipExpected)
			if err != nil {
				t.Fatalf("Observation: %v", err)
			}
			if got.EffectiveStatus != tc.wantEffective || got.OverrideSource != tc.wantOverride {
				t.Fatalf("Observation = %+v, want effective=%s override=%s", got, tc.wantEffective, tc.wantOverride)
			}
			if strings.Contains(got.RegistryURL, "SECRET") || (err != nil && strings.Contains(err.Error(), "SECRET")) {
				t.Fatalf("Observation leaked URL userinfo: %+v, %v", got, err)
			}
			if tc.name == "userinfo mismatch" && got.RegistryURL != "" {
				t.Fatalf("userinfo registry URL = %q, want empty", got.RegistryURL)
			}
		})
	}
}

func TestPipWriter_MDMOwnershipRejectsOtherLanes(t *testing.T) {
	tests := []struct {
		name    string
		initial string
	}{
		{"unmarked", "[global]\n" + pipExpected + "\n"},
		{"DMG marker", "[global]\n" + dmgPipBegin + "\n" + pipExpected + "\n" + dmgPipEnd + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := newPipTestWriter(t, []byte(tc.initial))
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

func TestPipObservation_MDMManagedStaticConfiguration(t *testing.T) {
	initial := []byte("[global]\n" + mdmPipBegin + "\n" + pipExpected + "\n" + mdmPipEnd + "\n")
	w, _, _ := newPipTestWriter(t, initial)
	for _, managed := range w.files {
		if managed.current {
			hardenSecureTestFile(t, managed.file)
		}
	}
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	got, err := w.Observation(context.Background(), pipExpected)
	if err != nil {
		t.Fatalf("Observation: %v", err)
	}
	if got.ConfigStatus != "match" || got.EffectiveStatus != "not_installed" || got.RegistryURL != "https://registry.stepsecurity.io/python/simple" {
		t.Fatalf("Observation = %+v, want matching MDM static config", got)
	}
}

func TestPipWriter_ExpectedValidationAndSnapshotRestore(t *testing.T) {
	w, _, path := newPipTestWriter(t, []byte("[global]\ntimeout=30\n"))
	if _, err := w.Write("index-url = https://evil.example/simple\nno-index = false"); err == nil {
		t.Fatal("Write accepted settings not rendered from policy")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("RestoreSnapshot = %q, want %q", after, before)
	}
	if _, err := w.Write(pipExpected); err != nil && !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("Write after restore: %v", err)
	}
}
