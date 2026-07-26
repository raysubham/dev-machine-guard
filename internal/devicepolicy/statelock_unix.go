//go:build darwin || linux

package devicepolicy

import (
	"errors"
	"os"
	"syscall"
)

// stateLockSupported: POSIX advisory locking via flock(2). The lock is owned by
// the open file description, so the kernel drops it when the process exits or
// crashes — a dead agent can never wedge the state file.
const stateLockSupported = true

// tryLockHandle takes an exclusive flock without blocking. ok=false with a nil
// error means another open description holds it (EWOULDBLOCK) and the caller
// should retry within its budget. A non-nil error fails the operation closed
// unless lockUnavailable classifies it as "this filesystem cannot lock at all".
func tryLockHandle(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return false, err
}

// unlockHandle releases the flock. Closing the handle would release it anyway;
// doing it explicitly keeps the release path symmetric with Windows, where the
// unlock is not implied.
func unlockHandle(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// lockUnavailable reports whether the error means this filesystem does not
// implement flock at all, as opposed to an actionable failure. It is the only
// error class that still runs the read-modify-write unlocked: where nothing can
// lock, no peer holds a lock either, so there is no lost update to prevent —
// while failing closed would leave the agent permanently unable to persist state
// on, say, a network or FUSE-mounted home directory.
//
// ENOTSUP/EOPNOTSUPP — "this filesystem does not implement flock" — is the whole
// list. Everything else fails the operation, including two errnos that look like
// they belong here and do not: ENOLCK means the kernel's lock records are
// exhausted, so peers may well already HOLD locks this call just cannot join, and
// EINVAL means the request itself was invalid, which says nothing about whether
// the filesystem can lock. Both are transient or local faults on a mount where
// locking works, exactly the case where running unlocked loses a record.
func lockUnavailable(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	// Not a switch: ENOTSUP and EOPNOTSUPP are the same value on Linux (distinct on
	// Darwin), which a switch rejects as a duplicate case.
	return errno == syscall.ENOTSUP || errno == syscall.EOPNOTSUPP
}
