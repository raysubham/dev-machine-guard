//go:build !windows

package device

import (
	"context"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Non-Windows tests exercise the Windows code path via SetGOOS("windows").
// This file provides command-stubbed implementations matching that pattern.

// Non-Windows builds of the agent never gather Windows resources at runtime
// (the dispatcher in gatherResources uses GOOS), but tests on a Linux/macOS
// host exercise the Windows code path by calling SetGOOS("windows") on the
// mock. The stubs below let those tests run by routing through exec.Run with
// command stubs for wmic / PowerShell, mirroring the pattern in
// device_other.go for serial/OS version.

func getCPUInfoWindows(ctx context.Context, exec executor.Executor) (cpuModel string, physical, logical int) {
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List")
	if err != nil {
		return "", 0, 0
	}
	return parseCIMProcessorList(stdout)
}

func getMemoryBytesWindows(ctx context.Context, exec executor.Executor) uint64 {
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(stdout), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func getDiskTotalBytesWindows(exec executor.Executor) uint64 {
	return exec.DiskCapacityBytes(windowsSystemDrive(exec))
}

func windowsSystemDrive(exec executor.Executor) string {
	drive := strings.TrimSpace(exec.Getenv("SystemDrive"))
	if drive == "" {
		drive = "C:"
	}
	return drive + `\`
}
