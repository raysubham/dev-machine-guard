package executor

import (
	"os/exec"

	"github.com/step-security/dev-machine-guard/internal/winproc"
)

// HardenCommand applies the process-level safeguards every command this agent
// spawns needs: no console window on Windows, and a cancellation that reaches
// the whole process group rather than only the immediate child.
//
// Exported for callers that build their own *exec.Cmd because they need stream
// or environment handling this package's Run methods do not express. Those
// callers still need the teardown, and this is where it is defined rather than
// re-derived, correctly or otherwise, beside each such command. Run and
// RunInDir apply the same pair inline.
func HardenCommand(cmd *exec.Cmd) {
	winproc.HideWindow(cmd)
	setupKillgroupOnCancel(cmd)
}
