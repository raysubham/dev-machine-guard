//go:build windows

package devicepolicy

import (
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

func TestSecureUserFile_CreatedParentsHaveRestrictedACL(t *testing.T) {
	home := t.TempDir()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = home
	h, err := openSecureUserHome(current)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.ensureParent(filepath.Join(".config", "pip", "pip.ini"), 0o700); err != nil {
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
	for _, path := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "pip")} {
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
		if acl == nil || acl.AceCount != 2 {
			t.Fatalf("%q ACE count = %v, want exactly target user and SYSTEM", path, acl)
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
			seenTarget = seenTarget || sid.Equals(targetSID)
			seenSystem = seenSystem || sid.Equals(systemSID)
		}
		if !seenTarget || !seenSystem {
			t.Fatalf("%q ACL does not contain only target user and SYSTEM", path)
		}
	}
}
