package devicepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// stateLockSuffix names the lock artifact guarding the state file's
// read-modify-write. It sits beside the state file (device-policy-state.json ->
// device-policy-state.json.lock) and carries NO policy state whatsoever — it
// exists only to hold an OS advisory lock, so every category's ownership record
// still lives in exactly one JSON file.
const stateLockSuffix = ".lock"

// stateLockWait bounds how long a read-modify-write waits for a concurrent agent
// process to finish its own before giving up and failing the operation. The
// critical section is a small read, an in-memory map edit and an atomic rename —
// microseconds — so the budget is deliberately orders of magnitude larger than
// honest contention needs: it has to absorb a rename serialized behind on-access
// antivirus, a slow network home directory, or a descheduled peer without ever
// mistaking one for a wedged process. Anything still holding it after this is not
// contention, and proceeding anyway would be the lost update the lock exists to
// prevent.
//
// stateLockRetryDelay is the poll interval. The lock is taken non-blocking and
// retried rather than waited on in the kernel so the budget is enforceable on
// both platforms with the same code.
var (
	stateLockWait       = 10 * time.Second
	stateLockRetryDelay = 5 * time.Millisecond
)

// stateLockPath returns the lock artifact's path, or "" when the state file's own
// path is unresolvable (no home directory). Derived by suffixing CachePath() so a
// test override redirects the lock with the file it guards.
func stateLockPath() string {
	p := CachePath()
	if p == "" {
		return ""
	}
	return p + stateLockSuffix
}

// withStateLock runs fn holding an exclusive cross-process lock on the state
// file, then releases it. It is what makes a read-modify-write safe between
// separate agent PROCESSES: the in-process cacheMu cannot see a second agent, and
// without it an IDE reconcile in one process and an npm reconcile in another could
// each read the file, add their own category, and have the later atomic rename
// drop the earlier one's record — a silent loss of ownership that strands whatever
// that category wrote on disk, since the agent will not later remove a value it
// has no record of writing.
//
// Acquisition FAILS CLOSED: if the lock cannot be taken, fn does not run and the
// error is returned. The one file holding every category's ownership is an
// invariant, not a best effort, and "the lock was busy" is precisely the state in
// which a concurrent writer is proven to exist — proceeding there is the one case
// that can actually lose a record. The cost is accepted deliberately: the caller
// classifies the failure write_failed, which for npm rolls the ~/.npmrc block back
// and reports a failure the next cycle retries. A reported, recoverable failure is
// preferable to silently dropping another category's ownership.
//
// The single exception is a platform or filesystem with no advisory locking at all
// (see lockUnavailable): there fn runs unlocked, because no peer can hold a lock
// either — there is no race to lose, and failing closed would permanently break
// state persistence on that machine instead of protecting anything.
//
// Callers hold cacheMu first and this second, always in that order, so the two
// can never deadlock against each other. Neither lock is reentrant: fn must use
// the unlocked readStateFile / persistStateFile, never the public accessors.
func withStateLock(fn func() error) error {
	release, err := acquireStateLock()
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// acquireStateLock takes the exclusive lock. On success the returned release is
// non-nil and safe to call (a no-op when nothing was locked because locking is
// unavailable). On error release is nil and the caller must not proceed.
func acquireStateLock() (release func(), err error) {
	if !stateLockSupported {
		return func() {}, nil
	}
	path := stateLockPath()
	if path == "" {
		return nil, errNoHomeDir
	}
	// The parent may not exist yet on a first write; persistStateFile creates it
	// too, but the lock has to be opened before that runs.
	if err := os.MkdirAll(filepath.Dir(path), cacheParentDirMode); err != nil {
		return nil, fmt.Errorf("devicepolicy: state lock dir: %w", err)
	}
	// #nosec G304 -- path is CachePath() (a test override, or the resolved home
	// joined with the package constant CacheFilename) plus a constant suffix.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, cacheFileMode)
	if err != nil {
		// Not openable is actionable, not benign: an existing lock file this process
		// cannot open (one left owner-only by a root or SYSTEM-context run over the
		// same home) is exactly the mixed-privilege setup where a peer CAN lock and
		// this process would be the one silently clobbering it.
		return nil, fmt.Errorf("devicepolicy: open state lock %s: %w", path, err)
	}
	// The lock file is a rendezvous point, never a record: it is created empty and
	// left empty, and it is deliberately NOT unlinked on release. Unlinking would
	// let a peer that already opened the old inode hold a lock nobody else can see.
	deadline := time.Now().Add(stateLockWait)
	for {
		ok, lerr := tryLockHandle(f)
		if ok {
			return func() {
				unlockHandle(f)
				_ = f.Close()
			}, nil
		}
		if lerr != nil {
			_ = f.Close()
			if lockUnavailable(lerr) {
				return func() {}, nil
			}
			return nil, fmt.Errorf("devicepolicy: lock %s: %w", path, lerr)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w after %s", errStateLockBusy, stateLockWait)
		}
		time.Sleep(stateLockRetryDelay)
	}
}
