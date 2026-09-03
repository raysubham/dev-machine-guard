//go:build windows

package devicepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNetrcWriter_WindowsPathSelectionAndAlternateConflict(t *testing.T) {
	t.Run("PyPI uses dot file when only underscore exists", func(t *testing.T) {
		home := t.TempDir()
		dot := filepath.Join(home, ".netrc")
		underscore := filepath.Join(home, "_netrc")
		initial := []byte("machine other.example login u password p\r\n")
		if err := os.WriteFile(underscore, initial, 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := NewNetrcWriter(newSecureTestHome(t, home), netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if w.Location() != dot {
			t.Fatalf("Location = %q, want %q", w.Location(), dot)
		}
		if _, err := w.Write(netrcExpected); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got, err := os.ReadFile(underscore)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, initial) {
			t.Fatalf("_netrc = %q, want unchanged %q", got, initial)
		}
	})

	t.Run("dot file wins when both exist", func(t *testing.T) {
		home := t.TempDir()
		for _, name := range []string{".netrc", "_netrc"} {
			if err := os.WriteFile(filepath.Join(home, name), []byte("machine other.example login u password p\r\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		w, err := NewNetrcWriter(newSecureTestHome(t, home), netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(w.Location()) != ".netrc" {
			t.Fatalf("Location = %q, want preferred .netrc", w.Location())
		}
	})

	t.Run("unused alternate exact host fails closed", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte("machine other.example login u password p\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "_netrc"), []byte("machine registry.stepsecurity.io login stale password old-secret\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := NewNetrcWriter(newSecureTestHome(t, home), netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(netrcExpected); err == nil {
			t.Fatal("Write error = nil, want alternate-file conflict")
		} else if strings.Contains(err.Error(), "old-secret") {
			t.Fatalf("alternate conflict leaked credential: %v", err)
		}
	})
}

func TestNetrcWriter_WindowsGoUsesCmdGoNetrcPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		dot        []byte
		underscore []byte
		selected   string
	}{
		{name: "neither file", selected: ".netrc"},
		{name: "dot file only", dot: []byte("machine dot.example login user password keep\r\n"), selected: ".netrc"},
		{name: "underscore file only", underscore: []byte("machine underscore.example login user password keep\r\n"), selected: "_netrc"},
		{
			name:       "both files",
			dot:        []byte("machine dot.example login user password keep\r\n"),
			underscore: []byte("machine underscore.example login user password keep\r\n"),
			selected:   "_netrc",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			homeDir := t.TempDir()
			dotPath := filepath.Join(homeDir, ".netrc")
			underscorePath := filepath.Join(homeDir, "_netrc")
			assertFile := func(path string, want []byte) {
				t.Helper()
				got, err := os.ReadFile(path)
				if want == nil {
					if !os.IsNotExist(err) {
						t.Fatalf("%s exists, want absent: %q, %v", path, got, err)
					}
					return
				}
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s = %q, %v, want %q", path, got, err, want)
				}
			}
			if tc.dot != nil {
				if err := os.WriteFile(dotPath, tc.dot, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.underscore != nil {
				if err := os.WriteFile(underscorePath, tc.underscore, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			policy := goTestPolicy(t)
			writer, err := newGoNetrcWriter(newSecureTestHome(t, homeDir), policy.RegistryHost(), policy.DeviceToken())
			if err != nil {
				t.Fatal(err)
			}
			selectedPath := filepath.Join(homeDir, tc.selected)
			if writer.Location() != selectedPath {
				t.Fatalf("Location = %q, want %q", writer.Location(), selectedPath)
			}
			if _, err := writer.Write(writer.expected); err != nil {
				t.Fatal(err)
			}
			first, err := os.ReadFile(selectedPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(writer.expected); err != nil {
				t.Fatal(err)
			}
			second, err := os.ReadFile(selectedPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(second, first) {
				t.Fatalf("repeated write changed %s: %q, want %q", tc.selected, second, first)
			}
			if tc.selected == ".netrc" {
				assertFile(underscorePath, tc.underscore)
			} else {
				assertFile(dotPath, tc.dot)
			}

			changed, err := writer.Clear()
			if err != nil || !changed {
				t.Fatalf("Clear = %v, %v, want true", changed, err)
			}
			assertFile(dotPath, tc.dot)
			assertFile(underscorePath, tc.underscore)
		})
	}
}

func TestNetrcWriter_WindowsSeparateManagedFilesClearInEitherOrder(t *testing.T) {
	for _, first := range []string{"go", "pypi"} {
		t.Run(first+" first", func(t *testing.T) {
			homeDir := t.TempDir()
			dotPath := filepath.Join(homeDir, ".netrc")
			underscorePath := filepath.Join(homeDir, "_netrc")
			dotInitial := []byte("machine dot.example login user password keep\r\n")
			underscoreInitial := []byte("machine underscore.example login user password keep\r\n")
			if err := os.WriteFile(dotPath, dotInitial, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(underscorePath, underscoreInitial, 0o600); err != nil {
				t.Fatal(err)
			}
			home := newSecureTestHome(t, homeDir)
			pypi, err := NewNetrcWriter(home, netrcTestPolicy(t))
			if err != nil {
				t.Fatal(err)
			}
			policy := goTestPolicy(t)
			goWriter, err := newGoNetrcWriter(home, policy.RegistryHost(), policy.DeviceToken())
			if err != nil {
				t.Fatal(err)
			}
			for _, writer := range []*NetrcWriter{pypi, goWriter} {
				if _, err := writer.Write(writer.expected); err != nil {
					t.Fatal(err)
				}
			}
			single, err := hasSingleManagedNetrc(home)
			if err != nil {
				t.Fatal(err)
			}
			if single {
				t.Fatal("hasSingleManagedNetrc = true, want false")
			}

			writers := map[string]*NetrcWriter{"go": goWriter, "pypi": pypi}
			changed, err := writers[first].Clear()
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("first Clear = false, want true")
			}
			single, err = hasSingleManagedNetrc(home)
			if err != nil {
				t.Fatal(err)
			}
			if !single {
				t.Fatal("hasSingleManagedNetrc after first clear = false, want true")
			}
			second := "go"
			if first == second {
				second = "pypi"
			}
			changed, err = writers[second].Clear()
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("second Clear = false, want true")
			}
			for path, want := range map[string][]byte{dotPath: dotInitial, underscorePath: underscoreInitial} {
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("restored %s = %q, want %q", path, got, want)
				}
			}
		})
	}
}

func TestNetrcWriter_WindowsClearFindsOwnedFile(t *testing.T) {
	t.Run("managed dot file survives Go selection change", func(t *testing.T) {
		home := t.TempDir()
		dot := filepath.Join(home, ".netrc")
		initial := []byte("machine other.example login u password p\r\n")
		if err := os.WriteFile(dot, initial, 0o600); err != nil {
			t.Fatal(err)
		}
		policy := netrcTestPolicy(t)
		writer, err := newGoNetrcWriter(newSecureTestHome(t, home), policy.RegistryHost(), policy.DeviceToken())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(netrcExpected); err != nil {
			t.Fatal(err)
		}
		underscore := filepath.Join(home, "_netrc")
		underscoreContent := []byte("machine underscore.example login u password p\r\n")
		if err := os.WriteFile(underscore, underscoreContent, 0o600); err != nil {
			t.Fatal(err)
		}
		writer, err = newGoNetrcWriter(newSecureTestHome(t, home), policy.RegistryHost(), policy.DeviceToken())
		if err != nil {
			t.Fatal(err)
		}
		changed, err := writer.Clear()
		if err != nil || !changed {
			t.Fatalf("Clear = %v, %v, want managed alternate cleared", changed, err)
		}
		got, err := os.ReadFile(dot)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(initial) {
			t.Fatalf("dot file = %q, want restored %q", got, initial)
		}
		got, err = os.ReadFile(underscore)
		if err != nil || string(got) != string(underscoreContent) {
			t.Fatalf("underscore file changed: %q, %v", got, err)
		}
	})

	t.Run("alternate exact host blocks clear", func(t *testing.T) {
		home := t.TempDir()
		underscore := filepath.Join(home, "_netrc")
		if err := os.WriteFile(underscore, []byte("machine other.example login u password p\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writer, err := NewNetrcWriter(newSecureTestHome(t, home), netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(netrcExpected); err != nil {
			t.Fatal(err)
		}
		dot := filepath.Join(home, ".netrc")
		conflict := []byte("machine registry.stepsecurity.io login other password keep\r\n")
		if err := os.WriteFile(dot, conflict, 0o600); err != nil {
			t.Fatal(err)
		}
		writer, err = NewNetrcWriter(newSecureTestHome(t, home), netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Clear(); err == nil {
			t.Fatal("Clear error = nil, want alternate exact-host conflict")
		}
		got, err := os.ReadFile(dot)
		if err != nil || string(got) != string(conflict) {
			t.Fatalf("conflicting file changed: %q, %v", got, err)
		}
	})

}

func TestNetrcWriter_WindowsACLRejectsUnexpectedReader(t *testing.T) {
	w, path := newNetrcTestWriter(t, nil)
	if _, err := w.Write(netrcExpected); err != nil {
		t.Fatal(err)
	}
	if converged, err := w.Converged(netrcExpected); err != nil || !converged {
		t.Fatalf("Converged after secure write = %v, %v, want true", converged, err)
	}

	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	targetSID, _, err := descriptor.Owner()
	if err != nil || targetSID == nil {
		t.Fatalf("target owner: %v", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		netrcTestExplicitAccess(targetSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
		netrcTestExplicitAccess(systemSID, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		netrcTestExplicitAccess(everyoneSID, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	if converged, err := w.Converged(netrcExpected); err != nil || converged {
		t.Fatalf("Converged with unexpected reader = %v, %v, want false", converged, err)
	}
	if status, err := w.Observation(netrcExpected); err != nil || status != authTokenMismatch {
		t.Fatalf("Observation with unexpected reader = %q, %v, want mismatch", status, err)
	}
}

func netrcTestExplicitAccess(sid *windows.SID, permissions windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
