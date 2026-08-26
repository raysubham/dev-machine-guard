//go:build windows

package devicepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNPMRCWriter_WindowsPreservesLegacyMetadataBehavior(t *testing.T) {
	homePath := t.TempDir()
	home := newSecureTestHome(t, homePath)
	targetSID, err := windows.StringToSid(home.targetUser.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	enterpriseSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	inheritance := uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		secureExplicitAccess(targetSID, windows.GENERIC_ALL, inheritance, windows.TRUSTEE_IS_USER),
		secureExplicitAccess(systemSID, windows.GENERIC_ALL, inheritance, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		secureExplicitAccess(enterpriseSID, windows.GENERIC_READ, inheritance, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		homePath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(homePath, ".npmrc")
	initial := []byte("fund=false\r\n")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := home.open(".npmrc", ".dmg-", npmrcMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	writer := &NPMRCWriter{file: file}
	if _, err := writer.Write(stdBody); err != nil {
		t.Fatalf("Write rejected legacy Windows owner/DACL: %v", err)
	}
	if ok, err := windowsFileAllowsSID(path, enterpriseSID); err != nil || !ok {
		t.Fatalf("enterprise ACL missing after write: %v, %v", ok, err)
	}
	if err := writer.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(initial) {
		t.Fatalf("restored bytes = %q, %v, want %q", got, err, initial)
	}
	if ok, err := windowsFileAllowsSID(path, enterpriseSID); err != nil || !ok {
		t.Fatalf("enterprise ACL missing after rollback: %v, %v", ok, err)
	}
}

func windowsFileAllowsSID(path string, want *windows.SID) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	handle, err := reopenSecurityHandle(file, windows.READ_CONTROL)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil {
		return false, err
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return true, nil
		}
	}
	return false, nil
}
