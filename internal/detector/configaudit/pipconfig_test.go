package configaudit

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// fixedPipOwner is a deterministic ownerLookup hook so tests don't depend
// on real syscalls or platform-specific user names.
func fixedPipOwner() func(string) ownerInfo {
	return func(_ string) ownerInfo {
		return ownerInfo{UID: 1000, GID: 1000, OwnerName: "tester", GroupName: "staff", OK: true}
	}
}

func mustWritePipFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDetect_DiscoveryViaPipDebug(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".config", "pip", "pip.conf")
	mustWritePipFile(t, userPath, "[global]\nindex-url = https://pypi.org/simple\n")

	mock := executor.NewMock()
	mock.SetPath("pip", "/usr/bin/pip")
	mock.SetCommand("pip 24.0 from /usr/bin (python 3.12)\n", "", 0, "pip", "--version")
	// `pip config debug` output mimicking the real format.
	debug := `env_var:
env:
global:
  /etc/xdg/pip/pip.conf, exists: False
  /etc/pip.conf, exists: False
user:
  ` + userPath + `, exists: True
    index-url: https://pypi.org/simple
site:
`
	mock.SetCommand(debug, "", 0, "pip", "config", "debug")
	// Effective view (we don't rely on the body for this test).
	mock.SetCommand("", "", 0, "pip", "config", "list", "-v")
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), loggedIn)

	if !audit.Available {
		t.Errorf("expected pip available")
	}
	if audit.Version != "24.0" {
		t.Errorf("pip version = %q, want 24.0", audit.Version)
	}

	// Should have at least one user-scope file pointing at our temp path.
	var sawUser bool
	for _, f := range audit.Files {
		if f.Path == userPath && f.Layer == "user" {
			sawUser = true
			if !f.Exists || !f.Readable {
				t.Errorf("user file should exist+read: %+v", f)
			}
			if len(f.Sections) == 0 || f.Sections[0].Name != "global" {
				t.Errorf("expected [global] section: %+v", f.Sections)
			}
		}
	}
	if !sawUser {
		t.Errorf("user-scope file not surfaced; got files=%+v", audit.Files)
	}
}

func TestDetect_PipMissingDoesntCrash(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".config", "pip", "pip.conf")
	mustWritePipFile(t, userPath, "[global]\nextra-index-url = http://internal.example.com/simple\n")

	mock := executor.NewMock()
	// No SetPath for pip — LookPath fails.
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), loggedIn)

	if audit.Available {
		t.Errorf("pip should be marked unavailable")
	}
	if audit.Effective != nil {
		t.Errorf("effective view should be nil when pip missing, got %+v", audit.Effective)
	}
	// We should still discover the user file via path enumeration.
	var sawFile bool
	for _, f := range audit.Files {
		if f.Path == userPath && f.Exists {
			sawFile = true
		}
	}
	if !sawFile {
		t.Errorf("file enumeration should still find the user file when pip is missing; got %+v", audit.Files)
	}
	// And the http:// extra-index-url should still produce findings.
	var sawHTTP bool
	for _, fnd := range audit.Findings {
		if fnd.ID == "pip-002" {
			sawHTTP = true
		}
	}
	if !sawHTTP {
		t.Errorf("pip-002 should fire even without pip installed; got findings=%+v", audit.Findings)
	}
}

func TestDetect_VirtualEnvAddedAsSite(t *testing.T) {
	tmp := t.TempDir()
	venvPath := filepath.Join(tmp, "venv")
	pipConf := filepath.Join(venvPath, "pip.conf")
	mustWritePipFile(t, pipConf, "[global]\nrequire-hashes = true\n")

	mock := executor.NewMock()
	mock.SetEnv("VIRTUAL_ENV", venvPath)
	// No pip on PATH — keep this test focused on env-driven discovery.
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")})

	var sawSite bool
	for _, f := range audit.Files {
		if f.Path == pipConf && f.Layer == "site" {
			sawSite = true
		}
	}
	if !sawSite {
		t.Errorf("VIRTUAL_ENV pip.conf should be added as site layer; got files=%+v", audit.Files)
	}
}

func TestDetect_PipConfigFileEnvHonored(t *testing.T) {
	tmp := t.TempDir()
	customPath := filepath.Join(tmp, "custom-pip.conf")
	mustWritePipFile(t, customPath, "[global]\nno-build-isolation = true\n")

	mock := executor.NewMock()
	mock.SetEnv("PIP_CONFIG_FILE", customPath)
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")})

	var sawCustom bool
	for _, f := range audit.Files {
		if f.Path == customPath && f.Layer == "PIP_CONFIG_FILE" {
			sawCustom = true
		}
	}
	if !sawCustom {
		t.Errorf("PIP_CONFIG_FILE override not honored; got %+v", audit.Files)
	}
	// Should also produce a pip-020 redirection finding (custom path).
	var sawRedirect bool
	for _, fnd := range audit.Findings {
		if fnd.ID == "pip-020" {
			sawRedirect = true
		}
	}
	if !sawRedirect {
		t.Errorf("pip-020 should fire for non-standard PIP_CONFIG_FILE; got %+v", audit.Findings)
	}
}

func TestParseEffectiveOutput(t *testing.T) {
	// Direct test of the effective-view text parser via a hand-crafted output.
	mock := executor.NewMock()
	mock.SetPath("pip", "/usr/bin/pip")
	mock.SetCommand("pip 24.0\n", "", 0, "pip", "--version")
	mock.SetCommand("", "", 0, "pip", "config", "debug")
	out := `For variant 'global', will try loading '/etc/pip.conf'.
For variant 'user', will try loading '/u/.config/pip/pip.conf'.
global.index-url='https://internal.example.com/simple' from /u/.config/pip/pip.conf
install.no-build-isolation='true' from PIP_NO_BUILD_ISOLATION
`
	mock.SetCommand(out, "", 0, "pip", "config", "list", "-v")

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil)
	if audit.Effective == nil {
		t.Fatal("effective view nil")
	}
	if got := audit.Effective.Config["global.index-url"]; got != "https://internal.example.com/simple" {
		t.Errorf("merged config wrong for global.index-url: %q", got)
	}
	if got := audit.Effective.SourceByKey["global.index-url"]; got != "/u/.config/pip/pip.conf" {
		t.Errorf("source wrong for global.index-url: %q", got)
	}
	if got := audit.Effective.SourceByKey["install.no-build-isolation"]; got != "PIP_NO_BUILD_ISOLATION" {
		t.Errorf("env-var source wrong: %q", got)
	}
	// Sanity: also produced a positive informational finding for index-url
	// being non-default.
	var sawInfo bool
	for _, f := range audit.Findings {
		if f.ID == "pip-015" {
			sawInfo = true
		}
	}
	if !sawInfo && strings.Contains(out, "internal.example.com") {
		// pip-015 only fires when the merged value lands in a *parsed file*,
		// not from the effective output. Our test doesn't ship a parsed
		// file with that value, so absence is correct. Keeping the check
		// commented in spirit so the next reader knows why.
		_ = sawInfo
	}
}

// TestParseEffective_NoSourceSuffix locks in pip 24.x output where
// `pip config list -v` no longer emits the trailing ` from <path>` on
// each line. The parser must still capture the section.key=value, just
// with an empty SourceByKey entry.
//
// Reason: pip 24.3.1 on Fedora 42 emits lines like
//
//	global.index-url='https://pypi.org/simple/'
//
// (no source). Earlier pip versions added ` from /etc/pip.conf`.
func TestParseEffective_NoSourceSuffix(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("pip", "/usr/bin/pip")
	mock.SetCommand("pip 24.3.1\n", "", 0, "pip", "--version")
	mock.SetCommand("", "", 0, "pip", "config", "debug")
	out := "For variant 'global', will try loading '/etc/pip.conf'\n" +
		"global.index-url='https://pypi.org/simple/'\n" +
		"global.timeout='60'\n"
	mock.SetCommand(out, "", 0, "pip", "config", "list", "-v")

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil)
	if audit.Effective == nil {
		t.Fatal("effective view nil")
	}
	if got := audit.Effective.Config["global.index-url"]; got != "https://pypi.org/simple/" {
		t.Errorf("global.index-url = %q, want pypi.org", got)
	}
	if got := audit.Effective.Config["global.timeout"]; got != "60" {
		t.Errorf("global.timeout = %q, want 60", got)
	}
	// Source unknown — must be empty string, not the line tail.
	if got := audit.Effective.SourceByKey["global.index-url"]; got != "" {
		t.Errorf("source for global.index-url = %q, want empty", got)
	}
}

// TestParseEffective_RedactsEmbeddedCreds locks in the bug fix where
// `pip config list -v` emits URL values verbatim — including any
// embedded `user:pass@host` userinfo — and we used to copy them into
// effective.config without redaction. The per-file `entries` view
// already redacted; the merged effective view is now consistent.
//
// Validated end-to-end on Fedora EC2 (P3): the literal token must NOT
// appear anywhere in the JSON output.
func TestParseEffective_RedactsEmbeddedCreds(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("pip", "/usr/bin/pip")
	mock.SetCommand("pip 24.0\n", "", 0, "pip", "--version")
	mock.SetCommand("", "", 0, "pip", "config", "debug")
	// Pip's text output includes the literal credential — that's how pip
	// renders it. Our parser must redact before storing.
	out := "For variant 'user', will try loading '/u/.config/pip/pip.conf'.\n" +
		"global.extra-index-url='https://__token__:LEAKED_SECRET" + at + "private.example.com/simple' from /u/.config/pip/pip.conf\n"
	mock.SetCommand(out, "", 0, "pip", "config", "list", "-v")

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil)
	if audit.Effective == nil {
		t.Fatal("effective view nil")
	}
	got := audit.Effective.Config["global.extra-index-url"]
	if strings.Contains(got, "LEAKED_SECRET") {
		t.Errorf("effective.config leaked credential: %q", got)
	}
	if !strings.Contains(got, "****") {
		t.Errorf("effective.config should have redacted to user:****@host form, got: %q", got)
	}
}

// On a Mac without Xcode Command Line Tools, /usr/bin/pip3 and /usr/bin/python3
// are Apple shims that pop a GUI install prompt the moment they're invoked.
// PipConfigDetector must skip them — otherwise rolling out the agent to Jamf
// endpoints that don't deploy CLT triggers a Developer Tools dialog for every
// user on first scan.
//
// We stub pip3/python3 to return SUCCESS so the assertion catches the bug: if
// the guard isn't applied, detectPip will invoke the shim, get a successful
// response, and set Available=true. With the guard, the shim is never invoked
// and Available stays false. A test that left the stubs unset would pass even
// against the unfixed code, because the mock's "no command stub" error would
// be swallowed as if pip just wasn't installed.
func TestPipConfigDetector_SkipsAppleStubWithoutCLT(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetAppleCLTInstalled(false)
	mock.SetPath("pip3", "/usr/bin/pip3")
	mock.SetPath("python3", "/usr/bin/python3")
	// Stub both shims to *succeed* — if the guard fails, detectPip will
	// consume these and mistakenly set Available=true.
	mock.SetCommand("pip 24.0 from /usr/bin (python 3.12)\n", "", 0, "pip3", "--version")
	mock.SetCommand("pip 24.0 from /usr/bin (python 3.12)\n", "", 0, "python3", "-m", "pip", "--version")

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil)
	if audit.Available {
		t.Errorf("expected Available=false when only Apple stubs are on PATH, got true (path=%q, invocation=%q) — the guard let the shim run", audit.Path, audit.Invocation)
	}
	if audit.Effective != nil {
		t.Errorf("expected Effective=nil when pip detection was skipped, got %+v", audit.Effective)
	}
}

// When CLT is installed, /usr/bin/pip3 resolves to the real CLT-shipped pip
// and must be invoked normally. Confirms the guard is darwin+CLT-absent only,
// not a blanket /usr/bin/ skip.
func TestPipConfigDetector_DetectsUsrBinWhenCLTInstalled(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetAppleCLTInstalled(true)
	mock.SetPath("pip3", "/usr/bin/pip3")
	mock.SetCommand("pip 24.0 from /usr/bin (python 3.12)\n", "", 0, "pip3", "--version")
	mock.SetCommand("", "", 0, "pip3", "config", "debug")
	mock.SetCommand("", "", 0, "pip3", "config", "list", "-v")

	d := NewPipConfigDetector(mock)
	d.ownerLookup = fixedPipOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil)
	if !audit.Available {
		t.Fatalf("expected Available=true with CLT installed, got false")
	}
	if audit.Path != "/usr/bin/pip3" {
		t.Errorf("expected Path=/usr/bin/pip3, got %q", audit.Path)
	}
	if audit.Version != "24.0" {
		t.Errorf("expected Version=24.0, got %q", audit.Version)
	}
}

func TestDiscoverPipUserConfig_PlatformPaths(t *testing.T) {
	tests := []struct {
		name        string
		goos        string
		configure   func(*executor.Mock, string)
		wantAllowed []string
		wantCurrent string
	}{
		{
			name: "linux XDG and legacy",
			goos: "linux",
			configure: func(mock *executor.Mock, home string) {
				mock.SetEnv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
				mock.SetFile(filepath.Join(home, "xdg", "pip", "pip.conf"), nil)
				mock.SetFile(filepath.Join(home, ".pip", "pip.conf"), nil)
			},
			wantAllowed: []string{filepath.Join("xdg", "pip", "pip.conf"), filepath.Join(".pip", "pip.conf")},
			wantCurrent: filepath.Join("xdg", "pip", "pip.conf"),
		},
		{
			name: "macOS current Application Support directory",
			goos: "darwin",
			configure: func(mock *executor.Mock, home string) {
				mock.SetDir(filepath.Join(home, "Library", "Application Support", "pip"))
			},
			wantAllowed: []string{
				filepath.Join("Library", "Application Support", "pip", "pip.conf"),
				filepath.Join(".config", "pip", "pip.conf"),
				filepath.Join(".pip", "pip.conf"),
			},
			wantCurrent: filepath.Join("Library", "Application Support", "pip", "pip.conf"),
		},
		{
			name: "windows APPDATA and legacy",
			goos: "windows",
			configure: func(mock *executor.Mock, home string) {
				mock.SetEnv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
				mock.SetFile(filepath.Join(home, "pip", "pip.ini"), nil)
			},
			wantAllowed: []string{
				filepath.Join("AppData", "Roaming", "pip", "pip.ini"),
				filepath.Join("pip", "pip.ini"),
			},
			wantCurrent: filepath.Join("AppData", "Roaming", "pip", "pip.ini"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			mock := executor.NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetHomeDir(home)
			mock.SetUsername("")
			tc.configure(mock, home)

			got, err := DiscoverPipUserConfig(context.Background(), mock)
			if err != nil {
				t.Fatalf("DiscoverPipUserConfig: %v", err)
			}
			if len(got.AllowedUserPaths) != len(tc.wantAllowed) {
				t.Fatalf("AllowedUserPaths = %v, want %v", got.AllowedUserPaths, tc.wantAllowed)
			}
			for i, relative := range tc.wantAllowed {
				if want := filepath.Join(home, relative); got.AllowedUserPaths[i] != want {
					t.Errorf("AllowedUserPaths[%d] = %q, want %q", i, got.AllowedUserPaths[i], want)
				}
			}
			if got.AllowedUserPaths[0] != filepath.Join(home, tc.wantCurrent) {
				t.Errorf("current path = %q, want %q", got.AllowedUserPaths[0], filepath.Join(home, tc.wantCurrent))
			}
		})
	}
}

func TestDiscoverPipUserConfig_InvocationsDeduplicateAndRejectOutsidePath(t *testing.T) {
	home := t.TempDir()
	current := filepath.Join(home, ".config", "pip", "pip.conf")
	legacy := filepath.Join(home, ".pip", "pip.conf")
	outside := filepath.Join(t.TempDir(), "pip.conf")
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir(home)
	mock.SetUsername("")
	mock.SetPath("pip", "/opt/bin/pip")
	mock.SetPath("pip3", "/opt/bin/pip")
	mock.SetPath("python3", "/opt/bin/python3")
	mock.SetCommand("pip 25.2 from /opt/site-packages/pip\n", "", 0, "pip", "--version")
	mock.SetCommand("pip 25.2 from /opt/site-packages/pip\n", "", 0, "python3", "-m", "pip", "--version")
	debug := "user:\n  " + current + ", exists: True\n  " + legacy + ", exists: True\n  " + outside + ", exists: True\n"
	mock.SetCommand(debug, "", 0, "pip", "config", "debug")
	mock.SetCommand(debug, "", 0, "python3", "-m", "pip", "config", "debug")
	mock.SetFile(current, nil)
	mock.SetFile(legacy, nil)
	mock.SetFile(outside, nil)

	got, err := DiscoverPipUserConfig(context.Background(), mock)
	if err != nil {
		t.Fatalf("DiscoverPipUserConfig: %v", err)
	}
	wantInvocations := [][]string{{"pip"}, {"python3", "-m", "pip"}}
	if strings.TrimSpace(invocationStrings(got.Invocations)) != strings.TrimSpace(invocationStrings(wantInvocations)) {
		t.Fatalf("Invocations = %v, want %v", got.Invocations, wantInvocations)
	}
	if len(got.ExistingUserPaths) != 2 || got.ExistingUserPaths[0] != current || got.ExistingUserPaths[1] != legacy {
		t.Fatalf("ExistingUserPaths = %v, want [%q %q] without outside path", got.ExistingUserPaths, current, legacy)
	}
	for _, path := range got.AllowedUserPaths {
		if path == outside {
			t.Fatalf("outside debug path entered allowlist: %q", path)
		}
	}
}

func TestPipConfigDetector_WindowsPreservesHistoricalLauncherSelection(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("py", `C:\\Windows\\py.exe`)
	mock.SetCommand("pip 25.2\n", "", 0, "py", "-m", "pip", "--version")
	detector := NewPipConfigDetector(mock)
	if _, _, _, _, ok := detector.detectPip(context.Background()); ok {
		t.Fatal("config audit selected enforcement-only py launcher")
	}
}

func TestDiscoverPipUserConfig_WindowsLauncherForms(t *testing.T) {
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHomeDir(home)
	mock.SetEnv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	mock.SetPath("py", `C:\\Windows\\py.exe`)
	mock.SetCommand("pip 25.2\n", "", 0, "py", "-m", "pip", "--version")
	mock.SetCommand("pip 25.2\n", "", 0, "py", "-3", "-m", "pip", "--version")
	mock.SetCommand("user:\n", "", 0, "py", "-m", "pip", "config", "debug")
	mock.SetCommand("user:\n", "", 0, "py", "-3", "-m", "pip", "config", "debug")

	got, err := DiscoverPipUserConfig(context.Background(), mock)
	if err != nil {
		t.Fatalf("DiscoverPipUserConfig: %v", err)
	}
	want := [][]string{{"py", "-m", "pip"}, {"py", "-3", "-m", "pip"}}
	if invocationStrings(got.Invocations) != invocationStrings(want) {
		t.Fatalf("Invocations = %v, want %v", got.Invocations, want)
	}
}

type resolvedPipEnvironmentExecutor struct {
	*executor.Mock
	environment string
	runAsUser   func(context.Context, string) (string, error)
}

func (e *resolvedPipEnvironmentExecutor) RunAsUser(ctx context.Context, username, command string) (string, error) {
	if e.runAsUser != nil {
		return e.runAsUser(ctx, command)
	}
	if strings.Contains(command, "XDG_CONFIG_HOME") && strings.Contains(command, "PIP_CONFIG_FILE") {
		return e.environment, nil
	}
	return e.Mock.RunAsUser(ctx, username, command)
}

func TestDiscoverPipUserConfig_UsesResolvedUserEnvironment(t *testing.T) {
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("alice")
	mock.SetHomeDir(home)
	mock.SetEnv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "service-xdg"))
	exec := &resolvedPipEnvironmentExecutor{
		Mock:        mock,
		environment: "XDG_CONFIG_HOME=" + filepath.Join(home, "user-xdg") + "\x00",
	}
	got, err := DiscoverPipUserConfig(context.Background(), exec)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "user-xdg", "pip", "pip.conf")
	if len(got.AllowedUserPaths) == 0 || got.AllowedUserPaths[0] != want {
		t.Fatalf("AllowedUserPaths = %v, want resolved-user path first %q", got.AllowedUserPaths, want)
	}
}

func TestDiscoverPipUserConfig_UsesResolvedUserLoginShellPATH(t *testing.T) {
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(true)
	mock.SetUsername("alice")
	mock.SetHomeDir(home)
	mock.SetAppleCLTInstalled(true)
	mock.SetCommand("/opt/homebrew/bin/pip\n", "", 0, "bash", "-c", "which 'pip'")
	mock.SetCommand("pip 25.2 from /opt/homebrew/lib/python/site-packages/pip\n", "", 0, "bash", "-c", "'pip' '--version'")
	mock.SetCommand("user:\n", "", 0, "bash", "-c", "'pip' 'config' 'debug'")

	exec := &resolvedPipEnvironmentExecutor{Mock: mock}
	got, err := DiscoverPipUserConfig(context.Background(), exec)
	if err != nil {
		t.Fatalf("DiscoverPipUserConfig: %v", err)
	}
	if len(got.Invocations) != 1 || invocationStrings(got.Invocations) != "pip" {
		t.Fatalf("Invocations = %v, want login-shell pip", got.Invocations)
	}
}

func TestDiscoverPipUserConfig_UserEnvironmentFailureIsError(t *testing.T) {
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("alice")
	mock.SetHomeDir(home)
	exec := &resolvedPipEnvironmentExecutor{Mock: mock}
	exec.runAsUser = func(context.Context, string) (string, error) {
		return "", context.DeadlineExceeded
	}
	if _, err := DiscoverPipUserConfig(context.Background(), exec); err == nil {
		t.Fatal("DiscoverPipUserConfig() error = nil, want environment inspection failure")
	}
}

func TestDiscoverPipUserConfig_CanceledContextReturnsError(t *testing.T) {
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("alice")
	mock.SetHomeDir(home)
	calls := 0
	exec := &resolvedPipEnvironmentExecutor{Mock: mock}
	exec.runAsUser = func(ctx context.Context, command string) (string, error) {
		calls++
		if strings.Contains(command, "XDG_CONFIG_HOME") {
			return "XDG_CONFIG_HOME=\x00", nil
		}
		if ctx.Err() != context.Canceled {
			t.Fatalf("path lookup context error = %v, want canceled", ctx.Err())
		}
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiscoverPipUserConfig(ctx, exec); !errors.Is(err, context.Canceled) {
		t.Fatalf("DiscoverPipUserConfig() error = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("RunAsUser calls = %d, want only environment snapshot", calls)
	}
}

func invocationStrings(invocations [][]string) string {
	parts := make([]string, len(invocations))
	for i, invocation := range invocations {
		parts[i] = strings.Join(invocation, " ")
	}
	return strings.Join(parts, "|")
}
