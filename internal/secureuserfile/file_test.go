package secureuserfile

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newSecureTestHome(t *testing.T, home string) *Home {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	u.HomeDir = home
	normalizeSecureTestUser(t, u)
	h, err := openHome(u)
	if err != nil {
		t.Fatalf("openHome: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func openSecureTestFile(t *testing.T, h *Home, relativePath string) *File {
	t.Helper()
	f, err := h.Open(relativePath, ".dmg-", MaxBytes)
	if err != nil {
		t.Fatalf("open(%q): %v", relativePath, err)
	}
	return f
}

func TestSecureUserFile_CreatesPinnedParentsAndCommits(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"nested parents", filepath.Join(".config", "tool", "config")},
		{"alternate parents", filepath.Join(".local", "tool", "settings")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			h := newSecureTestHome(t, home)
			if err := h.EnsureParent(tc.path); err != nil {
				t.Fatalf("ensureParent: %v", err)
			}
			f := openSecureTestFile(t, h, tc.path)
			if err := f.Commit([]byte("managed\n"), 0o600); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			got, existed, mode, err := f.Read()
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !existed || string(got) != "managed\n" {
				t.Fatalf("Read = (%q, %v), want (%q, true)", got, existed, "managed\\n")
			}
			if enforcePOSIXMetadata && mode.Perm() != 0o600 {
				t.Fatalf("file mode = %v, want 0600", mode.Perm())
			}
			for dir := filepath.Dir(tc.path); dir != "."; dir = filepath.Dir(dir) {
				info, err := os.Stat(filepath.Join(home, dir))
				if err != nil {
					t.Fatalf("stat parent %q: %v", dir, err)
				}
				if enforcePOSIXMetadata && info.Mode().Perm() != 0o700 {
					t.Fatalf("parent %q mode = %v, want 0700", dir, info.Mode().Perm())
				}
			}
		})
	}
}

func TestSecureUserFile_ParentRefusals(t *testing.T) {
	tests := []struct {
		name string
		seed func(t *testing.T, home string)
		path string
	}{
		{
			name: "symlinked component",
			seed: func(t *testing.T, home string) {
				t.Helper()
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(home, ".config")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
			path: filepath.Join(".config", "tool", "config"),
		},
		{
			name: "non-directory component",
			seed: func(t *testing.T, home string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(home, ".config"), []byte("x"), 0o600); err != nil {
					t.Fatalf("seed file: %v", err)
				}
			},
			path: filepath.Join(".config", "tool", "config"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.seed(t, home)
			h := newSecureTestHome(t, home)
			if err := h.EnsureParent(tc.path); !errors.Is(err, ErrTargetUnusable) {
				t.Fatalf("ensureParent error = %v, want ErrTargetUnusable", err)
			}
		})
	}

	home := t.TempDir()
	h := newSecureTestHome(t, home)
	if err := h.EnsureParent(filepath.Join("..", "outside", "config")); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("escaping path error = %v, want ErrTargetUnusable", err)
	}
}

func TestSecureUserFile_ParentHardeningFailureRemovesNewDirectory(t *testing.T) {
	home := t.TempDir()
	h := newSecureTestHome(t, home)
	h.applyMetadata = func(*Home, *os.File, os.FileMode, bool) error {
		return errors.New("hardening failed")
	}
	path := filepath.Join(".config", "tool", "config")
	if err := h.EnsureParent(path); err == nil {
		t.Fatal("ensureParent error = nil, want hardening failure")
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); !os.IsNotExist(err) {
		t.Fatalf("unsafe created parent remains: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // Azure Run Command runs as SYSTEM; active-session retry is covered by VM validation.
	}
	h.applyMetadata = func(*Home, *os.File, os.FileMode, bool) error { return nil }
	if err := h.EnsureParent(path); err != nil {
		t.Fatalf("safe retry failed: %v", err)
	}
}

func TestSecureUserFile_ParentSwapDuringCreationRejected(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	h := newSecureTestHome(t, home)
	h.afterParentCreate = func(relativePath string) {
		if relativePath != ".config" {
			return
		}
		if err := os.Rename(filepath.Join(home, relativePath), filepath.Join(home, ".config-original")); err != nil {
			t.Fatalf("rename created parent: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(home, relativePath)); err != nil {
			t.Fatalf("swap created parent: %v", err)
		}
	}
	if err := h.EnsureParent(filepath.Join(".config", "tool", "config")); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("ensureParent error = %v, want ErrTargetUnusable", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "tool")); !os.IsNotExist(err) {
		t.Fatalf("escaped parent was modified, stat error = %v", err)
	}
}

func TestSecureUserFile_RemoveAndRestoreRelativeSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relative symlink setup requires elevated Windows privileges")
	}
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "credentials", "auth")
	original := []byte("original credential\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("credentials", "auth"), filepath.Join(home, "credential")); err != nil {
		t.Fatal(err)
	}

	file := openSecureTestFile(t, newSecureTestHome(t, home), "credential")
	if err := file.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := file.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("restored bytes = %q, want %q", got, original)
	}
}

func TestSecureUserFile_RestoreRemovedSymlinkRejectsChangedChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relative symlink setup requires elevated Windows privileges")
	}
	tests := []struct {
		name   string
		mutate func(t *testing.T, home, link, target string)
	}{
		{
			name: "retargeted",
			mutate: func(t *testing.T, home, link, _ string) {
				other := filepath.Join(home, "credentials", "other")
				if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("credentials", "other"), link); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "leaf recreated",
			mutate: func(t *testing.T, _, _, target string) {
				if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "escape",
			mutate: func(t *testing.T, _, link, _ string) {
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("..", "outside"), link); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "link removed",
			mutate: func(t *testing.T, _, link, _ string) {
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, "credentials"), 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, "credentials", "auth")
			if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(home, "credential")
			if err := os.Symlink(filepath.Join("credentials", "auth"), link); err != nil {
				t.Fatal(err)
			}
			file := openSecureTestFile(t, newSecureTestHome(t, home), "credential")
			if err := file.Remove(); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, home, link, target)
			if err := file.RestoreSnapshot(); !errors.Is(err, ErrTargetUnusable) {
				t.Fatalf("RestoreSnapshot error = %v, want ErrTargetUnusable", err)
			}
		})
	}
}

func TestSecureUserFile_SymlinkPolicy(t *testing.T) {
	t.Run("relative in-home leaf", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, "dotfiles"), 0o700); err != nil {
			t.Fatal(err)
		}
		leaf := filepath.Join(home, "dotfiles", "config")
		if err := os.WriteFile(leaf, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("dotfiles", "config"), filepath.Join(home, "config")); err != nil {
			t.Fatal(err)
		}
		f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
		if err := f.Commit([]byte("after"), 0o600); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if got, err := os.ReadFile(leaf); err != nil || string(got) != "after" {
			t.Fatalf("resolved leaf = %q, %v, want after", got, err)
		}
		if info, err := os.Lstat(filepath.Join(home, "config")); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("original symlink not preserved: %v, %v", info, err)
		}
	})

	t.Run("relative in-home clear purges resolved backups", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, "dotfiles"), 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(home, "dotfiles", "credentials")
		if err := os.WriteFile(target, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("dotfiles", "credentials"), filepath.Join(home, "credential")); err != nil {
			t.Fatal(err)
		}
		f := openSecureTestFile(t, newSecureTestHome(t, home), "credential")
		if err := f.Commit([]byte("managed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := f.Remove(); err != nil {
			t.Fatal(err)
		}
		if err := f.PurgeBackups(); err != nil {
			t.Fatalf("PurgeBackups after symlink target removal: %v", err)
		}
		backups, err := filepath.Glob(target + ".dmg-*.bak")
		if err != nil || len(backups) != 0 {
			t.Fatalf("credential backups remain: %v, %v", backups, err)
		}
	})

	tests := []struct {
		name   string
		target string
	}{
		{"absolute", string(filepath.Separator) + filepath.Join("etc", "hosts")},
		{"escaping", filepath.Join("..", "outside")},
		{"dangling", "missing"},
		{"directory-shaped", "leaf" + string(filepath.Separator)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.name == "directory-shaped" {
				if err := os.WriteFile(filepath.Join(home, "leaf"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(tc.target, filepath.Join(home, "config")); err != nil {
				t.Fatal(err)
			}
			f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
			if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
				t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
			}
		})
	}

	t.Run("deep chain", func(t *testing.T) {
		home := t.TempDir()
		for i := 0; i <= maxSymlinkDepth; i++ {
			from := filepath.Join(home, "link"+string(rune('a'+i)))
			to := "link" + string(rune('a'+i+1))
			if err := os.Symlink(to, from); err != nil {
				t.Fatal(err)
			}
		}
		f := openSecureTestFile(t, newSecureTestHome(t, home), "linka")
		if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
		}
	})
}

func TestSecureUserFile_RejectsDirectoryAndOversize(t *testing.T) {
	t.Run("directory leaf", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, "config"), 0o700); err != nil {
			t.Fatal(err)
		}
		f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
		if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
		}
	})

	t.Run("oversize leaf", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "config"), []byte(strings.Repeat("x", 17)), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := newSecureTestHome(t, home).Open("config", ".dmg-", 16)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.Read(); !errors.Is(err, ErrTargetUnusable) {
			t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
		}
	})
}

func TestSecureUserFile_ExclusiveTempCollisionAndAtomicReplace(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows resolves os.Stat file identity lazily from the path.
	if !os.SameFile(before, before) {
		t.Fatal("could not capture original file identity")
	}
	collision := filepath.Join(home, "config.dmg-tmp-collision")
	if err := os.WriteFile(collision, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newSecureTestHome(t, home)
	// The existing leaf is backed up first; the next name exercises the temp
	// collision and the final name proves the exclusive-create retry succeeds.
	names := []string{"backup", "collision", "unique"}
	h.randomSuffix = func() (string, error) {
		name := names[0]
		names = names[1:]
		return name, nil
	}
	f := openSecureTestFile(t, h, "config")
	if err := f.Commit([]byte("after"), 0o600); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got, err := os.ReadFile(collision); err != nil || string(got) != "planted" {
		t.Fatalf("collision file = %q, %v, want planted", got, err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("Commit must atomically replace the leaf inode")
	}
	if _, err := os.Stat(filepath.Join(home, "config.dmg-tmp-unique")); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains after commit: %v", err)
	}
}

func TestSecureUserFile_SnapshotBackupRotationAndCleanup(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
	if err := f.Commit([]byte("managed"), 0o600); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := f.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "original" {
		t.Fatalf("restored file = %q, %v, want original", got, err)
	}
	if enforcePOSIXMetadata {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("restored mode = %v, want 0640", info.Mode().Perm())
		}
	}
	if err := f.RestoreSnapshot(); err == nil {
		t.Fatal("second RestoreSnapshot must fail")
	}

	for i := 0; i < maxBackups+3; i++ {
		if err := f.Commit([]byte{byte('a' + i)}, 0o600); err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
	}
	backups, err := filepath.Glob(path + ".dmg-*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) == 0 || len(backups) > maxBackups {
		t.Fatalf("backup count = %d, want 1..%d", len(backups), maxBackups)
	}
	for _, backup := range backups {
		if info, err := os.Stat(backup); err != nil {
			t.Fatal(err)
		} else if enforcePOSIXMetadata && info.Mode().Perm() != 0o600 {
			t.Fatalf("backup %q mode = %v, want 0600", backup, info.Mode().Perm())
		}
	}
	if err := f.PurgeBackups(); err != nil {
		t.Fatalf("PurgeBackups: %v", err)
	}
	if backups, err = filepath.Glob(path + ".dmg-*.bak"); err != nil || len(backups) != 0 {
		t.Fatalf("backups after purge = %v, %v, want none", backups, err)
	}
}

func TestSecureUserFile_RemoveAndRestoreSnapshot(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := openSecureTestFile(t, newSecureTestHome(t, home), "config")
	if err := f.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removed file still exists: %v", err)
	}
	if err := f.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
		t.Fatalf("restored file = %q, %v, want original", got, err)
	}
}
