//go:build windows

package devmdm

import (
	"strings"
	"testing"
)

func TestWindowsWriterFactory(t *testing.T) {
	w, ok := NewWriter()
	if !ok || w == nil {
		t.Fatal("NewWriter should return a writer on Windows")
	}
	loc := w.Location()
	if !strings.Contains(loc, windowsPolicyKeyPath) || !strings.Contains(loc, allowedExtensionsName) {
		t.Fatalf("Location %q should reference the policy key and value name", loc)
	}
}

// TestWindowsWriterReadAbsentIsClean exercises the ErrNotExist handling without
// mutating the registry: when the policy key/value is absent, Read returns
// (present=false, nil) rather than an error. Safe in CI (read-only).
func TestWindowsWriterReadAbsentIsClean(t *testing.T) {
	w, _ := NewWriter()
	if _, _, err := w.Read(); err != nil {
		// A present value is fine too; we only assert that a missing key/value is
		// not surfaced as an error. If the key happens to exist on the CI box this
		// still passes (err==nil).
		t.Fatalf("Read of (likely absent) policy must not error, got %v", err)
	}
}
