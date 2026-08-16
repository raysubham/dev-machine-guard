// Package browserext inventories the extensions installed in a developer's
// browsers.
//
// The unit of collection is a browser: one set of data directories with its own
// parser family and its own coverage status. What a browser's status answers is
// deliberately narrow — is the set of extension identities reported for it
// complete? — because the state this feeds is stored per extension, and only a
// complete list can authorise deleting the rows it leaves out. Everything else
// (a name that would not resolve, a permission list too long to ship whole) is an
// attribute problem and degrades the browser without casting doubt on membership.
//
// Three properties hold for every read and are what keep the phase bounded,
// consent-safe and honest. Every location is an exact path under the target
// user's home rather than a tree to walk. Every read has a byte cap and goes
// through descriptors that follow no symlink, so a link planted anywhere on the
// path refuses instead of redirecting a privileged read. And nothing executes: no
// browser is launched, no store is called, no helper binary runs, and the
// browsers' SQLite stores — cookies, history, passwords — are never opened.
//
// Adding a browser of a family already here is a table row. A new family is a
// parser, by definition.
package browserext

import (
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// catalogVersion is the revision of the browser list below, travelling with
// every scan so a reader can tell a list narrower than it expects from a browser
// that ran and found nothing. A string because a revision is an identifier:
// nothing compares two arithmetically.
const catalogVersion = "1"

// Browser identifiers. Stable strings: coverage entries key on them and fleet
// views group by them, so renaming one splits that browser's history in two.
const (
	browserChrome  = "chrome"
	browserEdge    = "edge"
	browserBrave   = "brave"
	browserFirefox = "firefox"
)

// engine names the browser family, which decides which parser runs and which
// engine-specific fields a finding carries. It is a classification and never an
// identity: Chrome, Edge and Brave are three browsers sharing one family, and
// grouping is always per (browser, extension). It stays inside this package —
// the value is a pure function of the browser id, so a reader derives it from
// its own copy of the catalog rather than being sent a second opinion.
type engine int

const (
	engineChromium engine = iota
	engineGecko
)

// browserSpec is one browser's whole definition: an id, a family, and the data
// directory candidates to try per platform.
//
// Candidate paths are relative to the target user's home and are joined onto it,
// never read from the environment. $HOME, %LOCALAPPDATA% and %APPDATA% describe
// whichever account the agent process runs as — under an unattended deploy that
// is a service account — so a path built from them would scan the wrong home and
// report every browser missing. That answer is authoritative to a reader, which
// would then delete the device's real inventory.
//
// The consequence is documented rather than hidden: a browser launched with a
// custom data directory, or one whose config root moved with $XDG_CONFIG_HOME,
// stores its state outside every candidate here and reports as not present. That
// is honestly "no default directory exists", and the only rows it can retire are
// rows a scan of those same default directories wrote.
type browserSpec struct {
	ID     string
	Engine engine

	// Slash-separated, home-relative. Multiple candidates per platform are
	// normal: a native install and a snap or flatpak of the same browser both
	// count, and both are scanned.
	Darwin  []string
	Windows []string
	Linux   []string
}

// catalog is the browser list: the head of the desktop share distribution. A
// browser covered by a row costs no parser work; one that is not covered is
// absent from the payload entirely, which is what "not attempted" means to a
// reader.
//
// A candidate marked unconfirmed comes from vendor documentation rather than from
// a machine running that packaging. The cost of a wrong one is bounded: a
// directory that does not exist reports the browser as not present, which is the
// same answer as not carrying the candidate at all.
//
// Iteration order is the order below and matters: caps cut at browser
// boundaries, so a deterministic order is what makes two runs over an unchanged
// machine produce the same payload.
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
		ID:      browserBrave,
		Engine:  engineChromium,
		Darwin:  []string{"Library/Application Support/BraveSoftware/Brave-Browser"},
		Windows: []string{"AppData/Local/BraveSoftware/Brave-Browser/User Data"},
		// The snap packaging is absent deliberately. Its data directory sits under
		// a `current` link that snapd repoints on every revision, and a path
		// through a link is refused rather than followed — so carrying it would
		// report a permanent failure, and take a native install alongside it down
		// with it. Covering that packaging means enumerating revisions, not adding
		// a row.
		Linux: []string{
			".config/BraveSoftware/Brave-Browser",
			".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser", // flatpak, unconfirmed
		},
	},
	{
		// One id covers every channel: release, beta, Nightly, ESR and Developer
		// Edition share this directory and separate themselves by profile. The
		// profile-name suffix hints at the channel but is not reliable identity,
		// so the channel is not reported.
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

// List caps. Every one of them cuts at a browser boundary rather than inside a
// browser's extension list, because a reported browser's membership is taken as
// complete: a list silently cut in half would retire the extensions below the cut.
const (
	maxProfilesPerBrowser    = 20 // counted across all of a browser's candidates
	maxExtensionsPerBrowser  = 500
	maxExtensionsTotal       = 2000
	maxPermissionsPerFinding = 64 // API permissions and host patterns each
)

// String caps in BYTES, not runes: the wire and the reader's caps are
// byte-denominated, so the producer's have to be too. Truncation backs up to a
// rune boundary so a capped string is still valid UTF-8.
const (
	maxNameBytes        = 256
	maxVersionBytes     = 64
	maxExtensionIDBytes = 256 // gecko ids are e-mail or UUID shaped; chromium is 32
	maxPermissionBytes  = 256 // per entry
)

// File read caps. Validated against the descriptor the bytes come from, and a
// read of one byte past the cap means the file outgrew it — that refuses rather
// than handing the parser a prefix, because a truncated JSON document either
// fails to parse for the wrong reason or, worse, parses.
const (
	maxLocalStateBytes     = 4 << 20
	maxPrefsBytes          = 10 << 20 // heavy profiles reach megabytes
	maxManifestBytes       = 1 << 20
	maxMessagesBytes       = 512 << 10
	maxExtensionsJSONBytes = 10 << 20
	maxProfilesINIBytes    = 256 << 10
)

// Directory listing bounds. The directories below are exactly the ones a local
// process can fill, so an overlong listing is refused rather than measured.
const (
	maxRootEntries    = 512
	maxProfileEntries = 512
	maxVersionEntries = 64
)

// browserExtPhaseBudget is the detector's own deadline, well inside the phase
// budget the orchestrator applies. It bounds the work this phase chooses to do;
// it cannot interrupt a blocked syscall, which is why no read is allowed to be
// able to block in the first place.
const browserExtPhaseBudget = 60 * time.Second
