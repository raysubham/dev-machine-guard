//go:build !windows

package browserext

// serviceSession has no meaning off Windows: no session concept separates a
// service from a login, and the account check covers what does. A daemon there is
// caught by its identity rather than by its session.
func serviceSession() bool { return false }
