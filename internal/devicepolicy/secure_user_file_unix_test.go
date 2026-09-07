//go:build unix

package devicepolicy

import (
	"os/user"
	"testing"
)

func normalizeSecureTestUser(t *testing.T, _ *user.User) {
	t.Helper()
}
