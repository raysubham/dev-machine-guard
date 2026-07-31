//go:build darwin || linux

package devicepolicy

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestLockUnavailableIsTheOnlyUnlockedPath(t *testing.T) {
	// The single waiver of the cross-process guarantee: a filesystem that cannot
	// lock at all. Nothing there can hold a lock, so there is no race to lose, and
	// failing closed would make state permanently unpersistable on such a mount — a
	// network or FUSE home directory. Every other errno is a real fault and must
	// fail the operation instead of quietly running the read-modify-write unlocked.
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"filesystem does not implement flock", syscall.ENOTSUP, true},
		{"wrapped, not bare", fmt.Errorf("flock: %w", syscall.ENOTSUP), true},
		// The two near misses. Neither means "cannot lock here": ENOLCK is exhausted
		// kernel lock records on a mount where peers may already hold locks, and EINVAL
		// is an invalid request. Treating either as unavailable would run the
		// read-modify-write unlocked in exactly the case a peer exists.
		{"exhausted lock records is a real fault", syscall.ENOLCK, false},
		{"an invalid lock request is a real fault", syscall.EINVAL, false},
		{"bad descriptor is a real fault", syscall.EBADF, false},
		{"io error is a real fault", syscall.EIO, false},
		{"permission denied is a real fault", syscall.EPERM, false},
		{"contention is not an error at all", syscall.EWOULDBLOCK, false},
		{"a non-errno error is a real fault", errors.New("something else"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockUnavailable(tc.err); got != tc.want {
				t.Fatalf("lockUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
