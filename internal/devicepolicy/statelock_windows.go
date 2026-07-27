//go:build windows

package devicepolicy

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// stateLockSupported: byte-range locking via LockFileEx. Like flock the lock is
// tied to the handle, so it is released when the process exits or is killed.
const stateLockSupported = true

// stateLockRegionLen is how many bytes of the (always empty) lock file the range
// covers. One byte is enough: every participant locks the same range, and a lock
// may extend past end-of-file.
const stateLockRegionLen = 1

// tryLockHandle takes an exclusive byte-range lock without blocking.
// LOCKFILE_FAIL_IMMEDIATELY turns contention into ERROR_LOCK_VIOLATION instead of
// a wait, which the caller polls against its own deadline.
func tryLockHandle(f *os.File) (bool, error) {
	var ol windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, stateLockRegionLen, 0, &ol,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

// lockUnavailable reports whether the error means the volume does not implement
// byte-range locking at all, as opposed to an actionable failure. It is the only
// error class that still runs the read-modify-write unlocked: where nothing can
// lock, no peer holds a lock either, so there is no lost update to prevent —
// while failing closed would leave the agent permanently unable to persist state
// on such a volume. Local NTFS always locks; a network redirector or a
// third-party filesystem filter may not.
//
// ERROR_NOT_SUPPORTED and ERROR_INVALID_FUNCTION — the latter being what a driver
// returns for an operation it has no implementation for — are the whole list.
// Everything else fails the operation, including the errors that look like they
// belong here and do not: ERROR_NO_SYSTEM_RESOURCES and ERROR_NOT_ENOUGH_MEMORY
// mean the kernel could not allocate a lock record on a volume where peers may
// well already HOLD locks this call cannot join, and ERROR_INVALID_PARAMETER means
// the request itself was malformed, which says nothing about whether the volume
// can lock. All three are transient or local faults where locking works, exactly
// the case in which running unlocked loses a record. ERROR_LOCK_VIOLATION never
// reaches here at all — tryLockHandle turns contention into ok=false with no error
// — and must never be added: it is the one error that proves a peer holds the
// lock.
func lockUnavailable(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION)
}

// unlockHandle releases the byte-range lock. Unlike flock this is not implied by
// closing the handle in every case, so it is always issued explicitly.
func unlockHandle(f *os.File) {
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, stateLockRegionLen, 0, &ol)
}
