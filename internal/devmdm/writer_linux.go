//go:build linux

package devmdm

// defaultLinuxPolicyPath is VS Code's managed-policy file on Linux, read by
// FilePolicyService (VS Code >= 1.106; older builds ignore it). The agent runs
// as root to write here. The read/modify/write logic is the OS-agnostic
// fileWriter (writer_file.go).
const defaultLinuxPolicyPath = "/etc/vscode/policy.json"

// NewWriter returns the Linux native-policy writer. ok is always true on Linux
// (privilege is checked at write time, surfacing as write_failed).
func NewWriter() (Writer, bool) { return newFileWriterAt(defaultLinuxPolicyPath), true }
