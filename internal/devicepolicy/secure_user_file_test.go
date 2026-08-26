package devicepolicy

import (
	"os"
	"os/user"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

type secureTestExecutor struct {
	executor.Executor
	user *user.User
}

func (e secureTestExecutor) LoggedInUser() (*user.User, error) { return e.user, nil }
func (e secureTestExecutor) IsRoot() bool                      { return false }
func (e secureTestExecutor) GOOS() string                      { return "test" }

func newSecureTestHome(t *testing.T, home string) *secureuserfile.Home {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return newSecureTestHomeAs(t, home, u.Username)
}

func newSecureTestHomeAs(t *testing.T, home, username string) *secureuserfile.Home {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	u.HomeDir = home
	u.Username = username
	normalizeSecureTestUser(t, u)
	h, err := secureuserfile.OpenUserHome(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatalf("OpenUserHome: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func hardenSecureTestFile(t *testing.T, f *secureuserfile.File) {
	t.Helper()
	data, err := os.ReadFile(f.Location())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.Location()); err != nil {
		t.Fatal(err)
	}
	if err := f.Commit(data, secureuserfile.FileMode); err != nil {
		t.Fatal(err)
	}
}

func TestPythonWriterBackupPrefixes(t *testing.T) {
	for name, got := range map[string]string{
		"netrc": netrcBackupPrefix,
		"pip":   pipBackupPrefix,
		"uv":    uvBackupPrefix,
	} {
		if got != ".dmg-" {
			t.Errorf("%s backup prefix = %q, want .dmg-", name, got)
		}
	}
}
