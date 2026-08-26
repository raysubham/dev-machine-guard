//go:build windows

package secureuserfile

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func normalizeSecureTestUser(t *testing.T, u *user.User) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(u.HomeDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("temporary home owner: %v", err)
	}
	u.Uid = owner.String()
}

func TestReopenSecurityHandle_FromRootFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile("config", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	handle, err := reopenSecurityHandle(file, windows.READ_CONTROL)
	if err != nil {
		t.Fatalf("reopenSecurityHandle: %v", err)
	}
	windows.CloseHandle(handle)
}

func TestSecureUserFile_CreatedParentsHaveRestrictedACL(t *testing.T) {
	home := t.TempDir()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = home
	normalizeSecureTestUser(t, current)
	h, err := openHome(current)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.EnsureParent(filepath.Join(".config", "tool", "config")); err != nil {
		t.Fatalf("ensureParent: %v", err)
	}

	targetSID, err := windows.StringToSid(current.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "tool")} {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("GetNamedSecurityInfo(%q): %v", path, err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%q inherits a broad parent ACL", path)
		}
		acl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if acl == nil || acl.AceCount < 2 {
			t.Fatalf("%q ACL = %v, want target user and SYSTEM entries", path, acl)
		}
		seenTarget, seenSystem := false, false
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
				t.Fatalf("%q contains a non-explicit allow ACE", path)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			switch {
			case sid.Equals(targetSID):
				seenTarget = true
			case sid.Equals(systemSID):
				seenSystem = true
			default:
				t.Fatalf("%q ACL grants access to unexpected SID %s", path, sid.String())
			}
		}
		if !seenTarget || !seenSystem {
			t.Fatalf("%q ACL does not contain only target user and SYSTEM", path)
		}
	}
}
