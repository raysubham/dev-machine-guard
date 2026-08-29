//go:build unix

package secureuserfile

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
)

func normalizeSecureTestUser(t *testing.T, _ *user.User) {
	t.Helper()
}

type fakeOwner struct {
	uid, gid uint32
	enforced bool
	err      error
}

func (f fakeOwner) ownerUIDGID(_ *os.File) (uint32, uint32, bool, error) {
	return f.uid, f.gid, f.enforced, f.err
}

func TestSecureUserFile_RejectsFIFOAndWrongOwner(t *testing.T) {
	t.Run("FIFO", func(t *testing.T) {
		home := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(home, "config"), 0o600); err != nil {
			t.Skipf("mkfifo unsupported: %v", err)
		}
		f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
		if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
		}
	})

	t.Run("wrong-owner leaf", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "config"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := newSecureTestHome(t, home)
		h.owners = fakeOwner{uid: uint32(h.uid + 1), enforced: true}
		f := openSecureTestFile(t, h, "config")
		if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
		}
		if found, err := f.ContainsAny("x"); err != nil || !found {
			t.Fatalf("ContainsAny = %v, %v, want content-blind marker detection", found, err)
		}
	})

	t.Run("wrong-owner parent", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, ".config"), 0o700); err != nil {
			t.Fatal(err)
		}
		h := newSecureTestHome(t, home)
		h.owners = fakeOwner{uid: uint32(h.uid + 1), enforced: true}
		if err := h.EnsureParent(filepath.Join(".config", "tool", "config")); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("ensureParent error = %v, want ErrTargetUnusable", err)
		}
	})
}

func TestSecureUserFile_AppliesTargetOwnership(t *testing.T) {
	home := t.TempDir()
	h := newSecureTestHome(t, home)
	if err := h.EnsureParent(filepath.Join(".config", "tool", "config")); err != nil {
		t.Fatalf("ensureParent: %v", err)
	}
	f := openSecureTestFile(t, h, filepath.Join(".config", "tool", "config"))
	if err := f.Commit([]byte("managed"), 0o600); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, ".config"),
		filepath.Join(home, ".config", "tool"),
		filepath.Join(home, ".config", "tool", "config"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%q has no unix stat", path)
		}
		if int(st.Uid) != h.uid || int(st.Gid) != h.gid {
			t.Fatalf("%q owner = %d:%d, want %d:%d", path, st.Uid, st.Gid, h.uid, h.gid)
		}
	}
}
