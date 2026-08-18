// Package browserext inventories the extensions installed in a developer's
// browsers.
//
// The unit of collection is a browser: one set of data directories, one parser
// family, one coverage status. A browser's status answers whether the set of
// extension identities reported for it is complete, because the state it feeds is
// stored per extension and only a complete list can authorise deleting the rows it
// leaves out. Anything else, an unresolved name or a permission list too long to
// ship whole, degrades the browser without casting doubt on membership.
//
// Every location is an exact path under the target user's home rather than a tree
// to walk, every read has a byte cap and goes through descriptors that follow no
// symlink, and nothing executes: no browser is launched, no store is called, and
// the browsers' SQLite stores (cookies, history, passwords) are never opened.
//
// Adding a browser of a family already here is a table row. A new family is a
// parser.
package browserext

import (
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// catalogVersion is the revision of the browser list below. It travels with every
// scan so a reader can tell a list narrower than it expects from a browser that ran
// and found nothing. A string because a revision is an identifier.
const catalogVersion = "1"

// Browser identifiers. Coverage entries key on them and fleet views group by them,
// so renaming one splits that browser's history in two.
const (
	browserChrome  = "chrome"
	browserEdge    = "edge"
	browserFirefox = "firefox"
)

// engine names the browser family, which decides which parser runs and which
// engine-specific fields a finding carries. A classification and never an identity:
// Chrome and Edge are two browsers sharing one family, and grouping is always per
// (browser, extension). It stays inside this package, because the value is a pure
// function of the browser id and a reader derives it from its own catalog.
type engine int

const (
	engineChromium engine = iota
	engineGecko
)

// browserSpec is one browser's definition: an id, a family, and the data directory
// candidates to try per platform.
//
// Candidate paths are home-relative and joined onto the target user's home, never
// read from the environment. $HOME, %LOCALAPPDATA% and %APPDATA% describe whichever
// account the agent process runs as, a service account under an unattended deploy,
// so a path built from them would scan the wrong home and report every browser
// missing, which a reader honours by deleting the device's real inventory.
//
// A browser launched with a custom data directory, or one whose config root moved
// with $XDG_CONFIG_HOME, stores its state outside every candidate here and reports
// as not present. The only rows that answer can retire are rows a scan of those
// same default directories wrote.
type browserSpec struct {
	ID     string
	Engine engine

	// Slash-separated, home-relative. Multiple candidates per platform are normal:
	// a native install and a snap or flatpak of the same browser are both scanned.
	Darwin  []string
	Windows []string
	Linux   []string
}

// catalog is the browser list. A browser without a row here is absent from the
// payload entirely, which is what "not attempted" means to a reader.
//
// A candidate marked unconfirmed comes from vendor documentation rather than from a
// machine running that packaging. A wrong one costs nothing: a directory that does
// not exist reports the browser as not present, the same answer as not carrying the
// candidate at all.
//
// Iteration order is the order below. Caps cut at browser boundaries, so a fixed
// order is what makes two runs over an unchanged machine produce the same payload.
var catalog = []browserSpec{
	{
		ID:      browserChrome,
		Engine:  engineChromium,
		Darwin:  []string{"Library/Application Support/Google/Chrome"},
		Windows: []string{"AppData/Local/Google/Chrome/User Data"},
		Linux:   []string{".config/google-chrome"},
	},
	{
		ID:      browserEdge,
		Engine:  engineChromium,
		Darwin:  []string{"Library/Application Support/Microsoft Edge"},
		Windows: []string{"AppData/Local/Microsoft/Edge/User Data"},
		Linux: []string{
			".config/microsoft-edge",
			".var/app/com.microsoft.Edge/config/microsoft-edge", // flatpak, unconfirmed
		},
	},
	{
		// One id covers every channel: release, beta, Nightly, ESR and Developer
		// Edition share this directory and separate themselves by profile. The
		// profile-name suffix hints at the channel but is not identity, so the
		// channel is not reported.
		ID:      browserFirefox,
		Engine:  engineGecko,
		Darwin:  []string{"Library/Application Support/Firefox"},
		Windows: []string{"AppData/Roaming/Mozilla/Firefox"},
		Linux: []string{
			".mozilla/firefox",
			"snap/firefox/common/.mozilla/firefox",
			".var/app/org.mozilla.firefox/.mozilla/firefox",
		},
	},
}

// roots returns this browser's data directory candidates on one platform, as
// absolute paths under home.
func (s browserSpec) roots(platform, home string) []string {
	var rel []string
	switch platform {
	case model.PlatformDarwin:
		rel = s.Darwin
	case model.PlatformWindows:
		rel = s.Windows
	case model.PlatformLinux:
		rel = s.Linux
	}
	if home == "" || len(rel) == 0 {
		return nil
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(home, filepath.FromSlash(r)))
	}
	return out
}

// List caps. Every one cuts at a browser boundary rather than inside a browser's
// extension list, because a reported browser's membership is read as complete: a
// list silently cut in half would retire the extensions below the cut.
const (
	maxProfilesPerBrowser    = 20 // counted across all of a browser's candidates
	maxExtensionsPerBrowser  = 500
	maxExtensionsTotal       = 2000
	maxPermissionsPerFinding = 64 // API permissions and host patterns each
)

// broadHostPatterns, with the http/https pair handled below, is the same rule the
// reader applies to decide broad host access, so a pattern added on one side is a
// disagreement about what breadth means until it is added on the other. Exact
// equality, never a judgment about equivalent patterns, because a host pattern is
// matched literally.
//
// file://*/* is not here: reach over local files is not reach over websites, and
// the browser gates it behind a separate per-extension setting.
var broadHostPatterns = map[string]struct{}{
	allURLsPattern: {},
	"*://*/*":      {},
}

// allURLsPattern is the one whole-web form that also reaches schemes other than
// http and https, local files among them.
const allURLsPattern = "<all_urls>"

// hasBroadHosts reports whether granted host patterns amount to whole-web reach.
func hasBroadHosts(hosts []string) bool {
	var http, https bool
	for _, pattern := range hosts {
		if _, ok := broadHostPatterns[pattern]; ok {
			return true
		}
		switch pattern {
		case "http://*/*":
			http = true
		case "https://*/*":
			https = true
		}
	}
	return http && https
}

// String caps in bytes, not runes, because the wire and the reader's caps are
// byte-denominated. Truncation backs up to a rune boundary so a capped string is
// still valid UTF-8.
const (
	maxNameBytes        = 256
	maxVersionBytes     = 64
	maxExtensionIDBytes = 256 // gecko ids are e-mail or UUID shaped; chromium is 32
	maxPermissionBytes  = 256 // per entry
	// An unpacked extension's load path, omitted rather than shortened when it
	// exceeds this: half a path names a directory nobody has.
	maxInstallPathBytes = 1024
)

// File read caps, validated against the descriptor the bytes come from. A read one
// byte past the cap refuses rather than handing the parser a prefix, because a
// truncated JSON document either fails to parse for the wrong reason or, worse,
// parses.
const (
	maxLocalStateBytes     = 4 << 20
	maxPrefsBytes          = 10 << 20 // heavy profiles reach megabytes
	maxManifestBytes       = 1 << 20
	maxMessagesBytes       = 512 << 10
	maxExtensionsJSONBytes = 10 << 20
	maxProfilesINIBytes    = 256 << 10
)

// Directory listing bounds. These directories are exactly the ones a local process
// can fill, so an overlong listing is refused rather than measured.
const (
	maxRootEntries    = 512
	maxProfileEntries = 512
	maxVersionEntries = 64
)

// browserExtPhaseBudget is the detector's own deadline, inside the phase budget the
// orchestrator applies. It bounds the work this phase takes on; it cannot interrupt
// a blocked syscall, which is why no read is allowed to block.
const browserExtPhaseBudget = 60 * time.Second
