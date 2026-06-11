//go:build windows

package devmdm

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// windowsPolicyKeyPath is the VS Code machine-policy key (relative to HKLM).
// VS Code reads policies from Software\Policies\Microsoft\<productName>; the
// stable build's productName is "VSCode". The agent runs as SYSTEM to write
// under HKLM.
const windowsPolicyKeyPath = `SOFTWARE\Policies\Microsoft\VSCode`

// foreignNonStringRegistryValue is returned by Read when AllowedExtensions
// exists but with a non-string registry type (e.g. a REG_DWORD a human set).
// The agent only ever writes JSON-object strings, so this sentinel can never
// equal a recorded WrittenValue or a desired policy — the reconciler treats it
// as foreign and yields (defense in depth on top of the reconciler's
// no-ownership-record-means-foreign rule).
const foreignNonStringRegistryValue = "\x00devmdm:non-string-registry-value"

// windowsWriter manages the AllowedExtensions REG_SZ value, leaving any other
// values under the policy key intact.
type windowsWriter struct{}

// NewWriter returns the Windows native-policy writer. ok is always true on
// Windows (privilege is checked at write time, surfacing as write_failed).
func NewWriter() (Writer, bool) { return &windowsWriter{}, true }

func (w *windowsWriter) Location() string {
	return `HKLM\` + windowsPolicyKeyPath + ` [` + allowedExtensionsName + `]`
}

func (w *windowsWriter) Read() (string, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsPolicyKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil // policy key not created yet
		}
		return "", false, err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(allowedExtensionsName)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil // value unset
		}
		// A wrong-typed value (e.g. a REG_DWORD a human set) is present but
		// foreign — return a sentinel that can never match an agent-written
		// value so the reconciler leaves it alone.
		if errors.Is(err, registry.ErrUnexpectedType) {
			return foreignNonStringRegistryValue, true, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (w *windowsWriter) Write(value string) (string, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsPolicyKeyPath,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	if err := k.SetStringValue(allowedExtensionsName, value); err != nil {
		return "", err
	}
	rb, _, err := k.GetStringValue(allowedExtensionsName)
	if err != nil {
		return "", err
	}
	return rb, nil
}

func (w *windowsWriter) Clear() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsPolicyKeyPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil // nothing to clear
		}
		return err
	}
	defer k.Close()

	if err := k.DeleteValue(allowedExtensionsName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
