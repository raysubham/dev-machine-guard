package devmdm

// Writer writes, reads back, and clears VS Code's `AllowedExtensions` managed
// policy at the OS-native location. It is a thin per-OS primitive: it manages
// ONLY the AllowedExtensions value — any other VS Code policy at the same
// location (other registry values, or other keys in policy.json) is preserved,
// which is what lets on-device and MDM-pushed policies coexist. Value-based
// ownership (deciding whether the agent may clear/overwrite) lives in the
// reconciler, not here, so it stays pure and fake-testable.
//
// The value written and read back is the compiled extensions.allowed object as
// a JSON STRING — the same shape VS Code reads on every platform (Windows
// REG_SZ, Linux policy.json string value, macOS profile <string>). VS Code then
// JSON-parses that string. The agent writes the backend's canonical-JSON bytes
// verbatim as this string.
type Writer interface {
	// Read returns the current on-disk AllowedExtensions value and whether it is
	// present. (present=false, err=nil) means the location is readable but the
	// value is unset.
	Read() (value string, present bool, err error)

	// Write sets AllowedExtensions to value, then reads it back and returns the
	// read-back value. The reconciler compares it to value to detect a silent
	// non-apply (policy_not_applied). An error means the write itself failed
	// (e.g. insufficient privilege) → write_failed.
	Write(value string) (readback string, err error)

	// Clear removes the AllowedExtensions value, leaving any other policies at
	// the location intact. Clearing an already-absent value is a no-op.
	Clear() error

	// Location is a human-readable description of the target, for logs.
	Location() string
}

// allowedExtensionsName — VS Code's registered policy name for the
// `extensions.allowed` setting (the registry value name on Windows, the JSON
// key in policy.json on Linux) — is defined in writer_file.go, which is
// untagged and compiled on every platform, so the constant is never an unused
// symbol on hosts that build neither OS writer (e.g. the macOS dev/CI host).
// See writer_file.go for the policy-NAME-vs-setting-id rationale.
