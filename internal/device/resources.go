package device

import (
	"context"
	"runtime"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// gatherResources collects static hardware capacity (CPU model/cores, RAM,
// disk capacity, architecture). Best-effort: missing values are zero/empty
// rather than fatal — a partial answer is still useful.
func gatherResources(ctx context.Context, exec executor.Executor) model.MachineResources {
	res := model.MachineResources{
		CPUArchitecture: runtime.GOARCH,
		LogicalCores:    runtime.NumCPU(),
	}

	switch exec.GOOS() {
	case model.PlatformWindows:
		cpuModel, physical, logical := getCPUInfoWindows(ctx, exec)
		res.CPUModel = cpuModel
		if physical > 0 {
			res.PhysicalCores = physical
		}
		if logical > 0 {
			res.LogicalCores = logical
		}
		res.MemoryBytes = getMemoryBytesWindows(ctx, exec)
		res.DiskTotalBytes = getDiskTotalBytesWindows(exec)
	case model.PlatformDarwin:
		res.CPUModel = getCPUModelDarwin(ctx, exec)
		if n := sysctlInt(ctx, exec, "hw.physicalcpu"); n > 0 {
			res.PhysicalCores = n
		}
		if n := sysctlInt(ctx, exec, "hw.logicalcpu"); n > 0 {
			res.LogicalCores = n
		}
		if n := sysctlUint64(ctx, exec, "hw.memsize"); n > 0 {
			res.MemoryBytes = n
		}
		res.DiskTotalBytes = exec.DiskCapacityBytes("/")
	default: // linux and other unix
		cpuModel, physicalCores := parseProcCPUInfo(readFileOrEmpty(exec, "/proc/cpuinfo"))
		res.CPUModel = cpuModel
		if physicalCores > 0 {
			res.PhysicalCores = physicalCores
		}
		if mem := parseProcMemInfo(readFileOrEmpty(exec, "/proc/meminfo")); mem > 0 {
			res.MemoryBytes = mem
		}
		res.DiskTotalBytes = exec.DiskCapacityBytes("/")
	}

	return res
}

func readFileOrEmpty(exec executor.Executor, path string) []byte {
	data, err := exec.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// parseProcCPUInfo extracts the human-readable CPU model and the physical core
// count from /proc/cpuinfo on Linux. Returns ("", 0) if not parseable.
//
// On x86 the file contains repeated blocks separated by blank lines, with
// "model name" and "cpu cores" keys. On ARM there is typically no "model name";
// callers should treat an empty model as best-effort missing data.
func parseProcCPUInfo(data []byte) (model string, physicalCores int) {
	if len(data) == 0 {
		return "", 0
	}
	// Track unique (physical id, core id) pairs to count physical cores
	// across multi-socket systems. Falls back to first "cpu cores" value
	// when physical id is absent (single-socket).
	seenCores := make(map[string]struct{})
	var firstCPUCores int
	var currentPhysID string

	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := splitCPUInfoLine(line)
		if !ok {
			if strings.TrimSpace(line) == "" {
				currentPhysID = ""
			}
			continue
		}
		switch key {
		case "model name":
			if model == "" {
				model = value
			}
		case "Hardware", "Model": // ARM fallbacks
			if model == "" {
				model = value
			}
		case "physical id":
			currentPhysID = value
		case "core id":
			seenCores[currentPhysID+":"+value] = struct{}{}
		case "cpu cores":
			if firstCPUCores == 0 {
				if n, err := strconv.Atoi(value); err == nil {
					firstCPUCores = n
				}
			}
		}
	}

	switch {
	case len(seenCores) > 0:
		physicalCores = len(seenCores)
	case firstCPUCores > 0:
		physicalCores = firstCPUCores
	}
	return model, physicalCores
}

func splitCPUInfoLine(line string) (key, value string, ok bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

// parseProcMemInfo returns total memory in bytes from /proc/meminfo on Linux.
// The MemTotal line is "MemTotal:       16277124 kB". Returns 0 if missing.
func parseProcMemInfo(data []byte) uint64 {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func getCPUModelDarwin(ctx context.Context, exec executor.Executor) string {
	stdout, _, _, err := exec.Run(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(stdout)
}

func sysctlInt(ctx context.Context, exec executor.Executor, key string) int {
	stdout, _, _, err := exec.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		return 0
	}
	return n
}

func sysctlUint64(ctx context.Context, exec executor.Executor, key string) uint64 {
	stdout, _, _, err := exec.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(stdout), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// parseCIMProcessorList parses one-field-per-line CIM/WMI output for the
// Win32_Processor class. Accepts both PowerShell Format-List ("Key : Value")
// and legacy wmic /format:list ("Key=Value") shapes. Multi-socket systems
// sum NumberOfCores / NumberOfLogicalProcessors across CPUs.
func parseCIMProcessorList(out string) (cpuModel string, physical, logical int) {
	for _, line := range strings.Split(out, "\n") {
		key, value := splitKVLine(line)
		if key == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "name":
			if cpuModel == "" {
				cpuModel = value
			}
		case "numberofcores":
			if n, err := strconv.Atoi(value); err == nil {
				physical += n
			}
		case "numberoflogicalprocessors":
			if n, err := strconv.Atoi(value); err == nil {
				logical += n
			}
		}
	}
	return cpuModel, physical, logical
}

func splitKVLine(line string) (key, value string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if idx := strings.Index(line, "="); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	if idx := strings.Index(line, ":"); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	return "", ""
}
