package credentials

import (
	"strings"
	"testing"
)

func TestValidEnvName(t *testing.T) {
	tests := map[string]bool{
		"XDG_CONFIG_HOME":   true,
		"KUBECONFIG":        true,
		"_LEADING":          true,
		"WITH1DIGIT":        true,
		"1LEADING":          false,
		"":                  false,
		"HAS-DASH":          false,
		"HAS SPACE":         false,
		"HAS;SEMICOLON":     false,
		"HAS$DOLLAR":        false,
		"HAS`BACKTICK":      false,
		"HAS\nNEWLINE":      false,
		"HAS(PAREN)":        false,
		"HAS/SLASH":         false,
		"$(id)":             false,
		"NAME\"WITH\"QUOTE": false,
	}
	for name, want := range tests {
		if got := validEnvName(name); got != want {
			t.Errorf("validEnvName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestEnvProbeCommand_AsksOnlyForTheNamedVariables holds the reason this is one
// invocation printing a fixed list rather than a dump: nothing else from that
// session, including any secret it exports, enters this process.
func TestEnvProbeCommand_AsksOnlyForTheNamedVariables(t *testing.T) {
	got := envProbeCommand([]string{"XDG_CONFIG_HOME", "KUBECONFIG"})
	want := `printf '%s=%s\n' XDG_CONFIG_HOME "$XDG_CONFIG_HOME" KUBECONFIG "$KUBECONFIG"`
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"env", "set", "export", "printenv"} {
		if strings.Contains(got, forbidden+" ") {
			t.Errorf("command dumps the environment: %q", got)
		}
	}
}

func TestParseEnvProbeOutput(t *testing.T) {
	names := []string{"XDG_CONFIG_HOME", "KUBECONFIG"}
	out := "XDG_CONFIG_HOME=/opt/config\r\n" +
		"KUBECONFIG=\n" +
		"GH_TOKEN=a-token-this-probe-never-asked-for\n" +
		"not a pair\n"

	got := parseEnvProbeOutput(out, names)
	if got["XDG_CONFIG_HOME"] != "/opt/config" {
		t.Errorf("value = %q, want the carriage return trimmed", got["XDG_CONFIG_HOME"])
	}
	// A variable set to an empty value and one that is unset mean the same thing to
	// every caller: no relocation.
	if _, ok := got["KUBECONFIG"]; ok {
		t.Error("an empty value must not be recorded")
	}
	// Only what was asked for is kept, so a shell that prints more cannot smuggle a
	// value into the map.
	if _, ok := got["GH_TOKEN"]; ok {
		t.Error("a variable that was not asked for must not be kept")
	}
	if len(got) != 1 {
		t.Errorf("values = %v, want one entry", got)
	}
}

func TestParseEnvProbeOutput_ValueContainingASeparator(t *testing.T) {
	got := parseEnvProbeOutput("KUBECONFIG=/a/config=1:/b/config\n", []string{"KUBECONFIG"})
	if got["KUBECONFIG"] != "/a/config=1:/b/config" {
		t.Errorf("value = %q, want everything after the first separator", got["KUBECONFIG"])
	}
}
