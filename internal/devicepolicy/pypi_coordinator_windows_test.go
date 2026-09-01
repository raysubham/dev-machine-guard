//go:build windows

package devicepolicy

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

func TestPyPICoordinatorWindows_MDMUsesUnderscoreNetrcWhenBothExist(t *testing.T) {
	withTempCache(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	current.HomeDir = homeDir
	normalizeSecureTestUser(t, current)
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetUsername(current.Username)
	mock.SetHomeDir(homeDir)
	mock.SetEnv("APPDATA", appData)
	exec := &coordinatorUserExecutor{Mock: mock, user: current}
	home, err := secureuserfile.OpenUserHome(exec)
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()

	effective := coordinatorPolicy(`["pip"]`, "sha256:MDM", enforcementMDM)
	policy, err := ParsePyPIPolicy(effective.Policy, "DEVICE-123")
	if err != nil {
		t.Fatal(err)
	}
	pipExpected, err := renderPipSettings(policy)
	if err != nil {
		t.Fatal(err)
	}
	credentialExpected := renderNetrcEntry(policy.RegistryHost(), policy.DeviceToken())
	dotInitial := []byte("machine unrelated.example login user password keep\r\n")
	underscoreInitial := []byte(mdmNetrcBegin + "\r\n" + strings.ReplaceAll(credentialExpected, "\n", "\r\n") + "\r\n" + mdmNetrcEnd + "\r\n")
	pipInitial := []byte(mdmPipBegin + "\r\n# [stepsecurity-pypi-pip-mdm] created=true\r\n[global]\r\n" + strings.ReplaceAll(pipExpected, "\n", "\r\n") + "\r\n" + mdmPipEnd + "\r\n")
	writeSecure := func(relative, backupPrefix string, data []byte) string {
		t.Helper()
		file, err := home.Open(relative, backupPrefix, secureuserfile.MaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := home.EnsureParent(relative); err != nil {
			t.Fatal(err)
		}
		if err := file.Commit(data, secureuserfile.FileMode); err != nil {
			t.Fatal(err)
		}
		return file.Location()
	}
	dotPath := writeSecure(".netrc", netrcBackupPrefix, dotInitial)
	underscorePath := writeSecure("_netrc", netrcBackupPrefix, underscoreInitial)
	writeSecure(filepath.Join("AppData", "Roaming", "pip", "pip.ini"), pipBackupPrefix, pipInitial)

	type fileSnapshot struct {
		data       []byte
		info       os.FileInfo
		securitySD string
	}
	snapshot := func(path string) fileSnapshot {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return fileSnapshot{data: data, info: info, securitySD: descriptor.String()}
	}
	before := map[string]fileSnapshot{
		dotPath:        snapshot(dotPath),
		underscorePath: snapshot(underscorePath),
	}

	reporter := &coordinatorReporter{}
	coordinator := &PyPICoordinator{
		Fetcher: &coordinatorFetcher{policy: effective}, Reporter: reporter, Exec: exec,
		CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StateMDMManaged || reporter.reports[0].AppliedHash != "" {
		t.Fatalf("reports = %+v, want mdm_managed without applied hash", reporter.reports)
	}
	for path, want := range before {
		got := snapshot(path)
		if !bytes.Equal(got.data, want.data) || !os.SameFile(got.info, want.info) || !got.info.ModTime().Equal(want.info.ModTime()) ||
			got.info.Mode() != want.info.Mode() || got.securitySD != want.securitySD {
			t.Fatalf("%s changed during MDM verification", path)
		}
	}
	if _, err := os.Stat(CachePath()); !os.IsNotExist(err) {
		t.Fatalf("MDM verification state residue: %v", err)
	}
	if err := filepath.WalkDir(homeDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if strings.Contains(name, ".dmg-") || strings.Contains(name, ".install") || strings.Contains(name, ".restore") {
			t.Fatalf("temporary residue remains at %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPyPICoordinatorWindowsReclaimsEmptyCredentialLaneAfterWrongOwnerInit(t *testing.T) {
	withTempCache(t)
	if err := WriteAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget, AppliedTargetState{}); err != nil {
		t.Fatal(err)
	}
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sibling"}); err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(homeDir, "_netrc"), []byte("machine other.example login u password p\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	target := &user.User{Username: "SYSTEM", Uid: systemSID.String(), Gid: current.Gid, HomeDir: homeDir}
	home, err := secureuserfile.OpenUserHome(secureTestExecutor{Executor: executor.NewReal(), user: target})
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()

	fixture := newCoordinatorFixture()
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
	coordinator := &PyPICoordinator{
		Fetcher:    &coordinatorFetcher{policy: clear},
		Reporter:   &coordinatorReporter{},
		CustomerID: "cust",
		DeviceID:   "DEVICE-123",
		Platform:   "windows",
		buildComponents: func(_ context.Context, _ executor.Executor, policy PyPIPolicy) (*pypiComponents, error) {
			credential, credentialErr := NewNetrcWriter(home, policy)
			if credential != nil || credentialErr == nil {
				t.Fatalf("NewNetrcWriter = %v, %v, want wrong-owner initialization failure", credential, credentialErr)
			}
			components := fixture.components(policy)
			components.credential = &pypiComponent{
				name:             "credential",
				ownershipTarget:  PyPICredentialOwnershipTarget,
				ownershipKey:     pypiCredentialOwnershipKey,
				initErr:          credentialErr,
				hasManagedMarker: func() (bool, error) { return hasManagedNetrcMarker(home) },
			}
			return components, nil
		},
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget); ok {
		t.Fatal("empty credential ownership lane remains")
	}
	if state, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || state.AppliedHash != "sibling" {
		t.Fatalf("sibling state = %+v, %v, want preserved", state, ok)
	}
}
