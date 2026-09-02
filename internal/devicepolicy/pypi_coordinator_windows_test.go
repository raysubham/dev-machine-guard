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

func TestGoAndPyPICoordinatorsWindows_MDMUseSeparateNetrcFiles(t *testing.T) {
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

	pypiEffective := coordinatorPolicy(`["pip"]`, "sha256:PYPI-MDM", enforcementMDM)
	pypiPolicy, err := ParsePyPIPolicy(pypiEffective.Policy, "DEVICE-123")
	if err != nil {
		t.Fatal(err)
	}
	pipExpected, err := renderPipSettings(pypiPolicy)
	if err != nil {
		t.Fatal(err)
	}
	goEffective := goCoordinatorPolicy("sha256:GO-MDM", enforcementMDM)
	goPolicy, err := ParseGoPolicy(goEffective.Policy, "DEVICE-123")
	if err != nil {
		t.Fatal(err)
	}
	goExpected, err := renderGoEnvSettings(goPolicy)
	if err != nil {
		t.Fatal(err)
	}
	credentialExpected := renderNetrcEntry(pypiPolicy.RegistryHost(), pypiPolicy.DeviceToken())
	dotInitial := []byte(mdmNetrcBegin + "\r\n" + strings.ReplaceAll(credentialExpected, "\n", "\r\n") + "\r\n" + mdmNetrcEnd + "\r\n")
	underscoreInitial := append([]byte(nil), dotInitial...)
	pipInitial := []byte(mdmPipBegin + "\r\n# [stepsecurity-pypi-pip-mdm] created=true\r\n[global]\r\n" + strings.ReplaceAll(pipExpected, "\n", "\r\n") + "\r\n" + mdmPipEnd + "\r\n")
	goInitial := []byte(mdmGoEnvBegin + "\r\n" + strings.ReplaceAll(goExpected, "\n", "\r\n") + "\r\n" + goEnvEnd + "\r\n")
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
	pipPath := writeSecure(filepath.Join("AppData", "Roaming", "pip", "pip.ini"), pipBackupPrefix, pipInitial)
	goPath := writeSecure(filepath.Join("AppData", "Roaming", "go", "env"), goEnvBackupPrefix, goInitial)

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
		pipPath:        snapshot(pipPath),
		goPath:         snapshot(goPath),
	}

	pypiReporter := &coordinatorReporter{}
	pypiCoordinator := &PyPICoordinator{
		Fetcher: &coordinatorFetcher{policy: pypiEffective}, Reporter: pypiReporter, Exec: exec,
		CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := pypiCoordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	goReporter := &coordinatorReporter{}
	goCoordinator := &GoCoordinator{
		Fetcher: &goCoordinatorFetcher{policy: goEffective}, Reporter: goReporter, Exec: exec,
		CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := goCoordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, reports := range map[string][]ComplianceReport{"PyPI": pypiReporter.reports, "Go": goReporter.reports} {
		if len(reports) != 1 {
			t.Fatalf("%s reports = %d, want 1", name, len(reports))
		}
		if reports[0].State != StateMDMManaged {
			t.Fatalf("%s state = %q, want %q", name, reports[0].State, StateMDMManaged)
		}
		if reports[0].AppliedHash != "" {
			t.Fatalf("%s applied hash = %q, want empty", name, reports[0].AppliedHash)
		}
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

func TestGoAndPyPICoordinatorsWindows_DMGIgnoresAlternateMDMMarker(t *testing.T) {
	tests := []struct {
		name      string
		selected  string
		alternate string
		hash      string
		reconcile func(executor.Executor, *coordinatorReporter) error
	}{
		{
			name:      "PyPI ignores Go MDM marker",
			selected:  ".netrc",
			alternate: "_netrc",
			hash:      "sha256:PYPI-DMG",
			reconcile: func(exec executor.Executor, reporter *coordinatorReporter) error {
				coordinator := &PyPICoordinator{
					Fetcher: &coordinatorFetcher{policy: coordinatorPolicy(`["pip"]`, "sha256:PYPI-DMG", enforcementDMG)}, Reporter: reporter, Exec: exec,
					CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
				}
				return coordinator.Reconcile(context.Background())
			},
		},
		{
			name:      "Go ignores PyPI MDM marker",
			selected:  "_netrc",
			alternate: ".netrc",
			hash:      "sha256:GO-DMG",
			reconcile: func(exec executor.Executor, reporter *coordinatorReporter) error {
				coordinator := &GoCoordinator{
					Fetcher: &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:GO-DMG", enforcementDMG)}, Reporter: reporter, Exec: exec,
					CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
				}
				return coordinator.Reconcile(context.Background())
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withTempCache(t)
			current, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			homeDir := t.TempDir()
			current.HomeDir = homeDir
			normalizeSecureTestUser(t, current)
			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformWindows)
			mock.SetUsername(current.Username)
			mock.SetHomeDir(homeDir)
			mock.SetEnv("APPDATA", filepath.Join(homeDir, "AppData", "Roaming"))
			exec := &coordinatorUserExecutor{Mock: mock, user: current}
			home, err := secureuserfile.OpenUserHome(exec)
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()

			writeSecure := func(name string, data []byte) string {
				t.Helper()
				file, err := home.Open(name, netrcBackupPrefix, secureuserfile.MaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if err := home.EnsureParent(name); err != nil {
					t.Fatal(err)
				}
				if err := file.Commit(data, secureuserfile.FileMode); err != nil {
					t.Fatal(err)
				}
				return file.Location()
			}
			selectedPath := writeSecure(tc.selected, []byte("machine unrelated.example login user password keep\r\n"))
			credential := renderNetrcEntry("registry.stepsecurity.io", "tenant-secret::dev:DEVICE-123")
			alternateInitial := []byte(mdmNetrcBegin + "\r\n" + strings.ReplaceAll(credential, "\n", "\r\n") + "\r\n" + mdmNetrcEnd + "\r\n")
			alternatePath := writeSecure(tc.alternate, alternateInitial)

			reporter := &coordinatorReporter{}
			if err := tc.reconcile(exec, reporter); err != nil {
				t.Fatal(err)
			}
			if got, want := len(reporter.reports), 1; got != want {
				t.Fatalf("reports = %d, want %d", got, want)
			}
			if got, want := reporter.reports[0].State, StateDriftDetected; got != want {
				t.Fatalf("state = %q, want %q", got, want)
			}
			if got, want := reporter.reports[0].AppliedHash, tc.hash; got != want {
				t.Fatalf("applied hash = %q, want %q", got, want)
			}
			selectedData, err := os.ReadFile(selectedPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(selectedData, []byte(dmgNetrcBegin)) {
				t.Fatalf("selected file does not contain DMG marker:\n%s", selectedData)
			}
			alternateData, err := os.ReadFile(alternatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(alternateData, alternateInitial) {
				t.Fatalf("alternate file = %q, want unchanged %q", alternateData, alternateInitial)
			}
		})
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
