//go:build linux

package executor

import "syscall"

func statfsFragmentSize(s *syscall.Statfs_t) uint64 {
	if s.Frsize > 0 {
		return uint64(s.Frsize)
	}
	if s.Bsize > 0 {
		return uint64(s.Bsize)
	}
	return 0
}
