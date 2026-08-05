package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Tokenised path roots. A reported location is written with its root replaced by
// one of these, and the same string is both what a reader sees and what identifies
// the file across scans: two spellings of one path become two rows for one file.
const (
	tokenHome      = "$HOME"
	tokenAppData   = "$APPDATA"
	tokenXDGConfig = "$XDG_CONFIG_HOME"
	// The fallback for a path matching no root: the directories above the file
	// become a short identifier of themselves and only the final element is kept.
	// Such a path is not one this inventory can describe, and its full spelling
	// can name directories that have nothing to do with credentials.
	tokenAbsolute = "$ABS"
)

// userPaths is the resolved developer's trusted root set, derived from the
// operating system's record of the account rather than an inherited variable: a
// root set taken from a value the scanned session controls is no boundary at all.
type userPaths struct {
	Username string
	Home     string
	// The roaming application data directory, derived from the home rather than
	// read from the environment for the same reason.
	AppData string
	// The configuration directory for the tools that honour the variable,
	// defaulted below the home when the developer has not set it.
	XDGConfig string
}

// newUserPaths derives the root set from a resolved account.
func newUserPaths(username, home, platform string) userPaths {
	p := userPaths{
		Username:  username,
		Home:      home,
		XDGConfig: filepath.Join(home, ".config"),
	}
	if platform == model.PlatformWindows {
		p.AppData = filepath.Join(home, "AppData", "Roaming")
	}
	return p
}

// withXDGConfig applies the developer's own setting, if the environment probe
// established one.
func (p userPaths) withXDGConfig(value string) userPaths {
	if value != "" {
		p.XDGConfig = value
	}
	return p
}

// candidatesFor expands one source into the locations to try, overrides first.
// Each is absolute and unresolved. Overrides are not an edge case: relocating these
// files is how monorepos, multi-account setups and CI parity are configured, so
// probing the default alone would report such a machine as holding nothing.
func candidatesFor(s source, paths userPaths, env map[string]string, platform string) []string {
	var out []string
	for _, o := range s.Overrides {
		value := strings.TrimSpace(env[o.Var])
		if value == "" {
			continue
		}
		switch o.Kind {
		case overrideFile:
			out = append(out, value)
		case overrideDir:
			out = append(out, filepath.Join(value, filepath.FromSlash(o.Rel)))
		case overrideList:
			// The value is every path the tool reads, not a replacement for one.
			for _, element := range filepath.SplitList(value) {
				if element = strings.TrimSpace(element); element != "" {
					out = append(out, element)
				}
			}
		case overridePrefix:
			// A prefix override rewrites paths arriving from elsewhere, so
			// there is nothing here for it to expand. Only a delegated source
			// may declare one, which a catalog invariant enforces.
		}
	}
	for _, l := range s.Locations {
		if !l.appliesTo(platform) {
			continue
		}
		root := paths.root(l.Root)
		if root == "" {
			continue
		}
		out = append(out, filepath.Join(root, filepath.FromSlash(l.Rel)))
	}
	return out
}

// root resolves a catalog path root.
func (p userPaths) root(r pathRoot) string {
	switch r {
	case rootHome:
		return p.Home
	case rootAppData:
		return p.AppData
	case rootXDGConfig:
		return p.XDGConfig
	}
	return ""
}

// applyPrefixOverrides rewrites a path whose leading directory a variable has
// moved — how relocation variables reach locations another component declares. The
// second return says a variable moved this path, which decides how it is read: a
// declared location is one of a reviewed set, a rewritten one is not.
func applyPrefixOverrides(path string, s source, paths userPaths, env map[string]string) (string, bool) {
	for _, o := range s.Overrides {
		if o.Kind != overridePrefix {
			continue
		}
		value := strings.TrimSpace(env[o.Var])
		if value == "" {
			continue
		}
		prefix := filepath.Join(paths.Home, filepath.FromSlash(o.Rel))
		rest, ok := trimPathPrefix(path, prefix)
		if !ok {
			continue
		}
		return filepath.Join(value, rest), true
	}
	return path, false
}

// tokenise rewrites an absolute path with its root replaced by a token. Roots are
// tried longest first: the roaming and configuration directories sit below the
// home, so matching the home first would label every path with the least
// specific root it happens to be under.
func (p userPaths) tokenise(path string) string {
	if path == "" {
		return ""
	}
	for _, r := range p.tokenRoots() {
		rest, ok := trimPathPrefix(path, r.dir)
		if !ok {
			continue
		}
		if rest == "" {
			return r.token
		}
		return r.token + "/" + filepath.ToSlash(rest)
	}
	// An opaque root still carries an identifier segment before the remainder, so
	// it keeps the shape every other location has: a reader that has to
	// special-case one root's segment count will eventually get it wrong.
	return tokenAbsolute + "/" + opaqueParent(path) + "/" + filepath.Base(path)
}

// opaqueParent identifies the directories above a path without naming them. Stable
// across scans, or one unchanged file would arrive under a new location every run
// and count as new. Truncated: it identifies rather than authenticates.
func opaqueParent(path string) string {
	sum := sha256.Sum256([]byte(filepath.ToSlash(filepath.Dir(path))))
	return hex.EncodeToString(sum[:6])
}

// rootToken is one trusted root and the token that stands in for it.
type rootToken struct {
	dir   string
	token string
}

// tokenRoots returns the roots to try, longest first, so the most specific one
// wins regardless of declaration order.
func (p userPaths) tokenRoots() []rootToken {
	roots := make([]rootToken, 0, 3)
	for _, r := range []rootToken{{p.AppData, tokenAppData}, {p.Home, tokenHome}} {
		if r.dir != "" {
			roots = append(roots, r)
		}
	}
	// The configuration root earns its own token only where the developer moved it.
	// At its default below the home it is not a separate place, and several tools
	// keep files there while ignoring the variable, so labelling them with its name
	// would give one unchanged file two identities.
	if p.XDGConfig != "" && !pathsEqual(filepath.Clean(p.XDGConfig), filepath.Join(p.Home, ".config")) {
		roots = append(roots, rootToken{p.XDGConfig, tokenXDGConfig})
	}
	slices.SortStableFunc(roots, func(a, b rootToken) int { return len(b.dir) - len(a.dir) })
	return roots
}

// trimPathPrefix reports whether path lies at or below prefix and returns the
// remainder, comparing whole elements so a sibling whose name merely starts with
// the prefix is not treated as inside it. Casing follows the platform, and the
// remainder keeps its own: folding it would produce a string that does not resolve.
func trimPathPrefix(path, prefix string) (string, bool) {
	cleanPath := filepath.Clean(path)
	cleanPrefix := filepath.Clean(prefix)
	if pathsEqual(cleanPath, cleanPrefix) {
		return "", true
	}
	if len(cleanPath) <= len(cleanPrefix) {
		return "", false
	}
	if !pathsEqual(cleanPath[:len(cleanPrefix)], cleanPrefix) {
		return "", false
	}
	if !os.IsPathSeparator(cleanPath[len(cleanPrefix)]) {
		return "", false
	}
	return cleanPath[len(cleanPrefix)+1:], true
}

// pathsEqual compares two path fragments with the case rules of the machine being
// described, always the one this runs on: the build's target is the authority, so a
// caller cannot ask for rules the filesystem would not agree with.
func pathsEqual(a, b string) bool {
	if runtime.GOOS == model.PlatformWindows {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// gitCheckTimeout bounds the tracked-file check. It only runs for a file already
// inside a repository, which is rare, but a repository on a stalled network
// mount would otherwise hold the phase open.
const gitCheckTimeout = 5 * time.Second

// permissionMode renders the permission bits a reader can act on. Empty on Windows,
// where bits are synthesised from one read-only attribute, so every file reports one
// of two values whatever its access control says — and that looks like a measurement.
func permissionMode(info os.FileInfo, platform string) string {
	if platform == model.PlatformWindows {
		return ""
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

// broadTrustees are the security-descriptor abbreviations for principals that
// mean "more than this account".
var broadTrustees = map[string]bool{
	"WD": true, // everyone
	"AU": true, // authenticated users
	"BU": true, // built-in users group
	"IU": true, // interactively logged-on users
	"AN": true, // anonymous
}

// readRights are the rights abbreviations that include reading contents.
var readRights = map[string]bool{
	"FA": true, // full access
	"FR": true, // file read
	"GA": true, // generic all
	"GR": true, // generic read
	"KA": true, // key all, appears on descriptors copied from registry templates
	"KR": true, // key read, same
}

// Right bits checked when an entry spells its rights as a number rather than an
// abbreviation.
const (
	fileReadData = 0x0001
	genericRead  = 0x80000000
	genericAll   = 0x10000000
)

// descriptorGrantsBroadRead classifies the discretionary section of a Windows
// security descriptor, which is where access is described on the platform with no
// permission bits to render above. Read from the descriptor's textual form rather
// than by walking entry structures: the form is platform-produced and stable, and
// reading it needs no pointer arithmetic inside a security-sensitive path. Because
// it is text, only the call that asks for the descriptor is Windows-only.
func descriptorGrantsBroadRead(sddl string) bool {
	section, ok := discretionarySection(sddl)
	if !ok {
		return false
	}
	for _, entry := range splitACEs(section) {
		if aceGrantsBroadRead(entry) {
			return true
		}
	}
	return false
}

// discretionarySection extracts the discretionary list, which runs from its own
// marker to the start of the next section.
func discretionarySection(sddl string) (string, bool) {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return "", false
	}
	rest := sddl[i+2:]
	for _, marker := range []string{"S:", "O:", "G:"} {
		if j := strings.Index(rest, marker); j >= 0 {
			rest = rest[:j]
		}
	}
	return rest, true
}

// splitACEs returns the parenthesised entries of a list.
func splitACEs(section string) []string {
	var entries []string
	for {
		open := strings.IndexByte(section, '(')
		if open < 0 {
			return entries
		}
		end := strings.IndexByte(section[open:], ')')
		if end < 0 {
			return entries
		}
		entries = append(entries, section[open+1:open+end])
		section = section[open+end+1:]
	}
}

// aceGrantsBroadRead classifies one entry. Its fields are type, flags, rights,
// two object identifiers, and the principal.
func aceGrantsBroadRead(entry string) bool {
	fields := strings.Split(entry, ";")
	if len(fields) < 6 {
		return false
	}
	// Only an allow entry grants anything. A conditional-allow entry carries
	// extra terms deciding whether it applies at all, so it is not counted:
	// reporting it as a grant would assert access that may never be in effect.
	if strings.ToUpper(strings.TrimSpace(fields[0])) != "A" {
		return false
	}
	if !broadTrustees[strings.ToUpper(strings.TrimSpace(fields[5]))] {
		return false
	}
	return rightsIncludeRead(strings.TrimSpace(fields[2]))
}

// rightsIncludeRead reports whether a rights field allows reading contents. The
// field is either a sequence of two-letter abbreviations or a hexadecimal
// number.
func rightsIncludeRead(rights string) bool {
	if after, ok := cutHexPrefix(rights); ok {
		mask, err := strconv.ParseUint(after, 16, 64)
		if err != nil {
			return false
		}
		return mask&fileReadData != 0 || mask&genericRead != 0 || mask&genericAll != 0
	}
	upper := strings.ToUpper(rights)
	for i := 0; i+2 <= len(upper); i += 2 {
		if readRights[upper[i:i+2]] {
			return true
		}
	}
	return false
}

// cutHexPrefix reports whether a rights field is spelled as a number and returns
// its digits.
func cutHexPrefix(rights string) (string, bool) {
	if len(rights) > 2 && (rights[0] == '0') && (rights[1] == 'x' || rights[1] == 'X') {
		return rights[2:], true
	}
	return "", false
}

// inGitRepo reports whether a path sits inside a repository working tree, caching
// per directory: the answer depends only on the directory, and a key directory
// holds many keys, so without the cache every key repeats the same walk.
func (s *scanState) inGitRepo(path string) bool {
	dir := filepath.Dir(path)
	if answer, known := s.gitRepos[dir]; known {
		return answer
	}
	answer := inGitRepo(path, s.paths.Home)
	s.gitRepos[dir] = answer
	return answer
}

// inGitRepo reports whether a path sits inside a repository working tree, evaluated
// against the resolved location: a symlink farm pointing a home dotfile into a
// checked-out dotfiles repository is precisely the arrangement that puts a
// credential under version control while the path the tool reads looks innocent.
// The search stops at the trusted root — a repository above a home is not it.
func inGitRepo(path, root string) bool {
	dir := filepath.Dir(path)
	for {
		// Containment is tested before the directory is looked at, so a
		// repository beside or above the home is never inspected and never
		// claims a file inside it.
		if _, ok := trimPathPrefix(dir, root); !ok {
			return false
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// gitTracked reports whether a file is under version control, only for one already
// known to be inside a repository. It asks the repository rather than reading the
// index: ignore rules, sparse checkouts and worktrees all change the answer.
func gitTracked(ctx context.Context, exec executor.Executor, path string) bool {
	dir, base := filepath.Split(path)
	if dir == "" || base == "" {
		return false
	}
	_, _, exitCode, err := exec.RunWithTimeout(ctx, gitCheckTimeout, "git", "-C", filepath.Clean(dir), "ls-files", "--error-unmatch", base)
	return err == nil && exitCode == 0
}
