//go:build !windows

package browserext

// serviceSession has no meaning off Windows: no session concept separates a service
// from a login, so a daemon is caught by its account identity instead.
func serviceSession() bool { return false }
