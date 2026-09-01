//go:build windows

package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

func TestGoEnvWriter_WindowsNormalizesCRLFAndRollsBack(t *testing.T) {
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
	if bytes.Contains(content, []byte("\r")) || !bytes.Contains(content, []byte(dmgGoEnvRestoreCRLF)) {
		t.Fatalf("writer did not normalize CRLF with restoration metadata: %q", content)
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

func TestGoEnvWriter_WindowsACLRepairPreservesCompliantBytes(t *testing.T) {
	homeDir := t.TempDir()
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	path := filepath.Join(appData, "go", "env")
	initial := []byte(dmgGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n")
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

func TestGoEnvWriter_WindowsGoCommandReadsValuesWithoutCarriageReturns(t *testing.T) {
	withTempCache(t)
	homeDir := t.TempDir()
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	path := filepath.Join(appData, "go", "env")
	initial := []byte("# keep\r\n" +
		"GOPROXY=https://proxy.golang.org,direct\r\n" +
		"GOPRIVATE=corp.example/*\r\n" +
		"GONOPROXY=noproxy.example/*\r\n" +
		"GONOSUMDB=nosum.example/*\r\n" +
		"GOSUMDB=sum.golang.org\r\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = homeDir
	normalizeSecureTestUser(t, current)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetUsername(current.Username)
	mock.SetHomeDir(homeDir)
	mock.SetEnv("APPDATA", appData)
	userExec := &coordinatorUserExecutor{Mock: mock, user: current}
	fetcher := &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:H", enforcementDMG)}
	coordinator := &GoCoordinator{
		Fetcher: fetcher, Reporter: &coordinatorReporter{}, Exec: userExec,
		CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("\r")) {
		t.Fatalf("enforced Go env contains carriage returns: %q", first)
	}
	firstInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, "go", "env", "-json", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOSUMDB")
	blocked := map[string]bool{
		"GOENV": true, "GOPROXY": true, "GOPRIVATE": true, "GONOPROXY": true, "GONOSUMDB": true, "GOSUMDB": true,
	}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !blocked[strings.ToUpper(key)] {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GOENV="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	var values map[string]string
	if err := json.Unmarshal(out, &values); err != nil {
		t.Fatalf("decode go env output: %v", err)
	}
	want := map[string]string{
		"GOPROXY":   goTestPolicy(t).RegistryURL,
		"GOPRIVATE": "corp.example/*", "GONOPROXY": "noproxy.example/*",
		"GONOSUMDB": "nosum.example/*", "GOSUMDB": "sum.golang.org",
	}
	for key, expected := range want {
		if values[key] != expected || strings.Contains(values[key], "\r") {
			t.Errorf("go env %s = %q, want %q without carriage return", key, values[key], expected)
		}
	}

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secondInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, first) || !os.SameFile(firstInfo, secondInfo) || !secondInfo.ModTime().Equal(firstInfo.ModTime()) {
		t.Fatal("repeated enforcement rewrote the converged Go env file")
	}

	fetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("clear restored %q, want %q", restored, initial)
	}
}

func TestGoCoordinator_WindowsClearWithoutCredentialStateRetainsSharedCredential(t *testing.T) {
	withTempCache(t)
	homeDir := t.TempDir()
	appData := filepath.Join(homeDir, "AppData", "Roaming")
	dotPath := filepath.Join(homeDir, ".netrc")
	underscorePath := filepath.Join(homeDir, "_netrc")
	dotInitial := []byte("machine dot.example login user password keep\r\n")
	underscoreInitial := []byte("machine underscore.example login user password keep\r\n")
	if err := os.WriteFile(dotPath, dotInitial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(underscorePath, underscoreInitial, 0o600); err != nil {
		t.Fatal(err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = homeDir
	normalizeSecureTestUser(t, current)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetUsername(current.Username)
	mock.SetHomeDir(homeDir)
	mock.SetEnv("APPDATA", appData)
	exec := &coordinatorUserExecutor{Mock: mock, user: current}
	pypi := &PyPICoordinator{
		Fetcher: &coordinatorFetcher{policy: coordinatorPolicy(`["pip"]`, "sha256:P", enforcementDMG)}, Reporter: &coordinatorReporter{},
		Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	goFetcher := &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:G", enforcementDMG)}
	goCoordinator := &GoCoordinator{
		Fetcher: goFetcher, Reporter: &coordinatorReporter{}, Exec: exec,
		CustomerID: "cust", DeviceID: "DEVICE-123", Platform: model.PlatformWindows,
	}
	if err := pypi.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := goCoordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	dot, err := os.ReadFile(dotPath)
	if err != nil || !bytes.Equal(dot, dotInitial) {
		t.Fatalf(".netrc = %q, %v, want unchanged %q", dot, err, dotInitial)
	}
	managed, err := os.ReadFile(underscorePath)
	if err != nil || !bytes.Contains(managed, []byte(dmgNetrcBegin)) {
		t.Fatalf("managed _netrc = %q, %v", managed, err)
	}
	if err := ClearAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget); err != nil {
		t.Fatal(err)
	}

	goFetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	if err := goCoordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(underscorePath)
	if err != nil || !bytes.Equal(got, managed) {
		t.Fatalf("shared _netrc changed: %q, %v", got, err)
	}
	dot, err = os.ReadFile(dotPath)
	if err != nil || !bytes.Equal(dot, dotInitial) {
		t.Fatalf(".netrc changed: %q, %v", dot, err)
	}
	if _, err := os.Stat(filepath.Join(appData, "go", "env")); !os.IsNotExist(err) {
		t.Fatalf("Go env remains after clear: %v", err)
	}
	for _, target := range []string{GoCredentialOwnershipTarget, GoEnvOwnershipTarget} {
		if _, ok := ReadAppliedState(CategoryPackageConfig, target); ok {
			t.Fatalf("clear retained %s state", target)
		}
	}
	if _, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget); !ok {
		t.Fatal("clear removed PyPI credential state")
	}
}

func TestGoCoordinator_WindowsMDMNilCredentialWriterReportsVerificationFailed(t *testing.T) {
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
