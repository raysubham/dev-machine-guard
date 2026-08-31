//go:build windows

package devicepolicy

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

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
