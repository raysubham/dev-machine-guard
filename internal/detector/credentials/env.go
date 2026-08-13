package credentials

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// resolveEnv reads the developer's values for the variables that can relocate a
// credential file. The second return says whether the read succeeded, which is not
// the same as finding nothing: a machine can genuinely have none set, but a probe
// that failed has established nothing, and reporting the default path as an
// authoritative absence would hide a relocated credential.
func (d *Detector) resolveEnv(ctx context.Context, paths userPaths) (userEnv, bool) {
	declared := EnvVars()
	names := make([]string, 0, len(declared))
	for _, name := range declared {
		// Bounds what may be interpolated into the probe command below. The names
		// come from the catalog, so nothing reaching here is attacker-supplied
		// today, and this check is what keeps that true when an entry is added.
		if validEnvName(name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return userEnv{Values: map[string]string{}}, true
	}
	if d.exec.GOOS() == model.PlatformWindows {
		return readUserEnvironment(paths.Username, names)
	}
	return d.readShellEnvironment(ctx, paths, names)
}

// readShellEnvironment asks the developer's login shell for the values in one
// invocation. One is the whole design: the agent cannot read another account's
// session, so the values have to come from a shell started as that account, and one
// per variable would multiply the most expensive thing this phase does. Only the
// named variables are printed, so nothing else from that session — including any
// secret it exports — enters this process. Values arrive already expanded.
func (d *Detector) readShellEnvironment(ctx context.Context, paths userPaths, names []string) (userEnv, bool) {
	if paths.Username == "" {
		return userEnv{}, false
	}
	out, err := d.exec.RunAsUser(ctx, paths.Username, envProbeCommand(names))
	if err != nil {
		// The error text is discarded rather than reported: it carries the
		// shell's own diagnostics, which can quote the session it came from.
		return userEnv{}, false
	}
	return userEnv{Values: parseEnvProbeOutput(out, names)}, true
}

// envProbeCommand builds the one-shot print. The format string is reused for
// each pair, so one command prints every value.
func envProbeCommand(names []string) string {
	var b strings.Builder
	b.WriteString(`printf '%s=%s\n'`)
	for _, name := range names {
		b.WriteString(" ")
		b.WriteString(name)
		b.WriteString(` "$`)
		b.WriteString(name)
		b.WriteString(`"`)
	}
	return b.String()
}

// parseEnvProbeOutput keeps only the values that were asked for. A variable set
// to an empty value and a variable that is unset are indistinguishable here and
// mean the same thing to every caller: no relocation.
func parseEnvProbeOutput(out string, names []string) map[string]string {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	values := make(map[string]string, len(names))
	for line := range strings.SplitSeq(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok || !wanted[name] {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			values[name] = value
		}
	}
	return values
}
