//go:build !darwin && !linux && !windows

package devicepolicy

import "os"

// stateLockSupported is false on platforms the agent does not ship to, so no lock
// file is created and no wait budget is spent, and a read-modify-write runs on the
// atomic temp+rename alone. This is the one place the cross-process guarantee is
// waived rather than enforced — nothing here can lock, so no peer holds a lock to
// race against, and failing closed would only make state unpersistable.
const stateLockSupported = false

func tryLockHandle(*os.File) (bool, error) { return false, nil }

func unlockHandle(*os.File) {}

func lockUnavailable(error) bool { return true }
