//go:build windows

package devicepolicy

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// The POSIX counterpart of this test lives in statelock_unix_test.go. Keep the two
// in step: the pair is what documents that the carve-out is a deliberate,
// identically-shaped exception on both platforms rather than whatever each one's
// locking API happened to return during development. This file compiles only on
// Windows, so a POSIX `go test` run never exercises it — the assertions come from
// the native windows job. `GOOS=windows go vet ./internal/devicepolicy/`
// typechecks it from any host.
func TestLockUnavailableIsTheOnlyUnlockedPath(t *testing.T) {
	// The single waiver of the cross-process guarantee: a volume that cannot lock at
	// all. Nothing there can hold a lock, so there is no race to lose, and failing
	// closed would make state permanently unpersistable on such a volume — a network
	// redirector or a third-party filesystem filter that declines locks. Every other
	// error is a real fault and must fail the operation instead of quietly running
	// the read-modify-write unlocked.
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"volume does not implement byte-range locking", windows.ERROR_NOT_SUPPORTED, true},
		{"a driver with no implementation for the operation", windows.ERROR_INVALID_FUNCTION, true},
		{"wrapped, not bare", fmt.Errorf("LockFileEx: %w", windows.ERROR_NOT_SUPPORTED), true},
		// The near misses, mirroring ENOLCK and EINVAL in the POSIX carve-out. Neither
		// means "cannot lock here": the first two are a lock record the kernel could not
		// allocate on a volume where peers may already hold locks, and the third is a
		// malformed request. Waiving any of them would run the read-modify-write
		// unlocked in exactly the case a peer exists.
		{"exhausted lock resources is a real fault", windows.ERROR_NO_SYSTEM_RESOURCES, false},
		{"no memory for the lock record is a real fault", windows.ERROR_NOT_ENOUGH_MEMORY, false},
		{"an invalid lock request is a real fault", windows.ERROR_INVALID_PARAMETER, false},
		// Contention is filtered by tryLockHandle before it can reach here, and it is
		// the one error that proves a peer holds the lock — the worst possible thing to
		// waive. Asserted so the two classifications can never be merged.
		{"contention is not unavailability", windows.ERROR_LOCK_VIOLATION, false},
		{"sharing violation is a real fault", windows.ERROR_SHARING_VIOLATION, false},
		{"access denied is a real fault", windows.ERROR_ACCESS_DENIED, false},
		{"bad handle is a real fault", windows.ERROR_INVALID_HANDLE, false},
		{"a non-errno error is a real fault", errors.New("something else"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockUnavailable(tc.err); got != tc.want {
				t.Fatalf("lockUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
