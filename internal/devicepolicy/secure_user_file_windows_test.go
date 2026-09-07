//go:build windows

package devicepolicy

import (
	"os/user"
	"testing"

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
