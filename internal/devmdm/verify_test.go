package devmdm

import "testing"

func TestVerify(t *testing.T) {
	cases := []struct {
		name string
		in   VerifyInput
		want string
	}{
		{"compliant: write+readback ok, version at floor",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.96.0", MinVSCodeVersion: "1.96.0"}, StateCompliant},
		{"compliant: version above floor",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.106.2", MinVSCodeVersion: "1.106.0"}, StateCompliant},
		{"compliant: two-part version vs three-part floor",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.106", MinVSCodeVersion: "1.106.0"}, StateCompliant},
		{"compliant: empty floor means no floor",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.0.0", MinVSCodeVersion: ""}, StateCompliant},

		{"vscode_unsupported: below floor wins over write/readback",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.95.9", MinVSCodeVersion: "1.96.0"}, StateVSCodeUnsupported},
		{"vscode_unsupported: linux floor not met",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "1.105.0", MinVSCodeVersion: "1.106.0"}, StateVSCodeUnsupported},
		{"vscode_unsupported: empty version (not installed)",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "", MinVSCodeVersion: "1.96.0"}, StateVSCodeUnsupported},
		{"vscode_unsupported: unknown version",
			VerifyInput{WriteOK: true, ReadbackMatch: true, VSCodeVersion: "unknown", MinVSCodeVersion: "1.96.0"}, StateVSCodeUnsupported},
		{"vscode_unsupported precedence even if write failed",
			VerifyInput{WriteOK: false, ReadbackMatch: false, VSCodeVersion: "1.0.0", MinVSCodeVersion: "1.96.0"}, StateVSCodeUnsupported},

		{"write_failed: version ok but write errored",
			VerifyInput{WriteOK: false, ReadbackMatch: false, VSCodeVersion: "1.96.0", MinVSCodeVersion: "1.96.0"}, StateWriteFailed},
		{"write_failed wins over readback",
			VerifyInput{WriteOK: false, ReadbackMatch: true, VSCodeVersion: "1.96.0", MinVSCodeVersion: "1.96.0"}, StateWriteFailed},

		{"policy_not_applied: wrote ok but readback mismatch",
			VerifyInput{WriteOK: true, ReadbackMatch: false, VSCodeVersion: "1.96.0", MinVSCodeVersion: "1.96.0"}, StatePolicyNotApplied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Verify(c.in); got != c.want {
				t.Fatalf("Verify(%+v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v, min string
		want   bool
	}{
		{"1.96.0", "1.96.0", true},
		{"1.96.2", "1.96.0", true},
		{"1.95.9", "1.96.0", false},
		{"1.106.0", "1.106.0", true},
		{"1.105.0", "1.106.0", false},
		{"v1.96.0", "1.96.0", true},        // leading v ignored
		{"1.96", "1.96.0", true},           // missing patch == 0
		{"1.106-insider", "1.106.0", true}, // non-numeric suffix ignored
		{"", "1.96.0", false},              // empty version
		{"unknown", "1.96.0", false},       // unparseable
		{"1.0.0", "", true},                // empty floor never blocks
	}
	for _, c := range cases {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q,%q) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}
