//go:build !windows

package browserext

import "golang.org/x/sys/unix"

// mkfifo plants a named pipe, which is the hostile object a state-file read has to
// survive: opening one the ordinary way blocks until a writer appears, and no
// deadline interrupts a blocked open.
func mkfifo(path string) error { return unix.Mkfifo(path, 0o644) }
