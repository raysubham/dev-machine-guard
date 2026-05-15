//go:build windows

package executor

import (
	"context"
	"strings"

	"golang.org/x/sys/windows"
)

func (r *Real) IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (r *Real) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := r.Run(ctx, "cmd", "/c", command)
	return strings.TrimSpace(stdout), err
}

func (r *Real) DiskCapacityBytes(path string) uint64 {
	if path == "" {
		return 0
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var freeBytesAvail, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvail, &totalBytes, &totalFreeBytes); err != nil {
		return 0
	}
	return totalBytes
}
