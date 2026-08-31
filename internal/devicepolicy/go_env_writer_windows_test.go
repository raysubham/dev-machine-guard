//go:build windows

package devicepolicy

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

func TestGoEnvWriterWindowsACLCRLFAndRollback(t *testing.T) {
	homeDir := t.TempDir()
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	path := filepath.Join(appData, "go", "env")
	initial := []byte("# keep\r\nGOPROXY=https://proxy.golang.org\r\nGOPRIVATE=corp.example/*\r\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetEnv("APPDATA", appData)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	weakenGoEnvTestACL(t, path)
	if secure, err := w.file.MetadataSecure(secureuserfile.FileMode); err != nil || secure {
		t.Fatalf("fixture metadata = %v, %v, want insecure", secure, err)
	}
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ReplaceAll(content, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatalf("writer introduced LF into CRLF file: %q", content)
	}
	secure, err := w.file.MetadataSecure(secureuserfile.FileMode)
	if err != nil || !secure {
		t.Fatalf("secure metadata = %v, %v", secure, err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("rollback restored %q, want %q", restored, initial)
	}
	secure, err = w.file.MetadataSecure(secureuserfile.FileMode)
	if err != nil || !secure {
		t.Fatalf("rollback metadata = %v, %v", secure, err)
	}
}

func TestGoEnvWriterWindowsRepairsOnlyACLForCompliantContent(t *testing.T) {
	homeDir := t.TempDir()
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	path := filepath.Join(appData, "go", "env")
	initial := []byte(dmgGoEnvBegin + "\r\n" + goEnvExpected + "\r\n" + goEnvEnd + "\r\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetEnv("APPDATA", appData)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	weakenGoEnvTestACL(t, path)
	if secure, err := w.file.MetadataSecure(secureuserfile.FileMode); err != nil || secure {
		t.Fatalf("fixture metadata = %v, %v, want insecure", secure, err)
	}

	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, initial) {
		t.Fatalf("ACL repair changed content: %q", content)
	}
	if secure, err := w.file.MetadataSecure(secureuserfile.FileMode); err != nil || !secure {
		t.Fatalf("secure metadata = %v, %v", secure, err)
	}
}

func weakenGoEnvTestACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	targetSID, _, err := descriptor.Owner()
	if err != nil || targetSID == nil {
		t.Fatalf("target owner: %v", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		goEnvTestExplicitAccess(targetSID, windows.GENERIC_READ, windows.TRUSTEE_IS_USER),
		goEnvTestExplicitAccess(systemSID, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestGoCoordinatorWindowsMDMNilCredentialWriterReportsVerificationFailed(t *testing.T) {
	homeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(homeDir, ".netrc"), 0o700); err != nil {
		t.Fatal(err)
	}
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetEnv("APPDATA", appData)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	mdm := []byte(mdmGoEnvBegin + "\r\n" + goEnvExpected + "\r\n" + goEnvEnd + "\r\n")
	if err := home.EnsureParent(w.file.RelativePath()); err != nil {
		t.Fatal(err)
	}
	if err := w.file.Commit(mdm, secureuserfile.FileMode); err != nil {
		t.Fatal(err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = homeDir
	normalizeSecureTestUser(t, current)
	mock.SetHomeDir(homeDir)
	exec := &coordinatorUserExecutor{Mock: mock, user: current}
	reporter := &coordinatorReporter{}
	coordinator := &GoCoordinator{
		Fetcher: &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:H", enforcementMDM)}, Reporter: reporter,
		Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := coordinator.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile error = nil")
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StateVerificationFailed {
		t.Fatalf("reports = %+v", reporter.reports)
	}
}

func goEnvTestExplicitAccess(sid *windows.SID, permissions windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
