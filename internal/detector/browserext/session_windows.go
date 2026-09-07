//go:build windows

package browserext

import "golang.org/x/sys/windows"

// serviceSession reports whether this process runs in session 0, the non-interactive
// services session. It is the primary refusal predicate on Windows because a service
// under a custom or domain account carries an ordinary SID that no allowlist can
// enumerate, while its session is always 0.
//
// A failed lookup answers yes: a wrong "no" scans the service profile, finds no
// browser, and reports every browser missing, an authoritative answer that would
// retire the device's real inventory.
func serviceSession() bool {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return true
	}
	return session == 0
}
