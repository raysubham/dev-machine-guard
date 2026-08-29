//go:build windows

package devicepolicy

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

func TestAppliedStateWindowsUsesTargetUserSecurity(t *testing.T) {
	homeDir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	target, restore, err := ConfigureCacheTarget(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	home, err := secureuserfile.OpenUserHome(target)
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	path := CachePath()

	for _, hash := range []string{"first", "replacement"} {
		if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: hash}); err != nil {
			t.Fatal(err)
		}
	}
	for _, object := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(path), secureuserfile.ParentMode},
		{path + stateLockSuffix, secureuserfile.FileMode},
		{path, secureuserfile.FileMode},
	} {
		file, err := os.Open(object.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := home.VerifyOwner(file, filepath.Base(object.path)); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		secure, err := home.MetadataSecure(file, object.mode)
		_ = file.Close()
		if err != nil || !secure {
			t.Fatalf("metadata %q = %v, %v", object.path, secure, err)
		}
	}
}
