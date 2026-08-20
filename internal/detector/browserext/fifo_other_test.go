//go:build windows

package browserext

import "errors"

// mkfifo has no counterpart here; the caller skips.
func mkfifo(string) error {
	return errors.New("named pipes are not directory entries on this platform")
}
