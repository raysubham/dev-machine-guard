package model

// Browser extension inventory wire types.
//
// A finding says which extension is installed in which browser, whether it is
// enabled and why not, where it came from, whether its store still lists it, and
// what it is permitted to touch. It carries no browsing state: no history, no
// cookies, no passwords, no page content and no profile identity. Two things do
// ship that name a place: host-access patterns, because they are what an
// extension can reach and can name an internal hostname, and the load path of an
// unpacked extension, because an unreviewed extension running out of a user
// directory is the signal and the path is the legible part of it. Neither is
// ever opened.
//
// Two things make the shape what it is. The first is that state is stored per
// extension rather than as one replaceable snapshot, so the payload has to say
// which browsers it speaks for — that is browsers[], and a reader deletes stored
// rows only for a browser whose entry claims a complete membership list. The
// second is that a browser whose extension set could not be fully enumerated
// ships no findings at all: half a list that read as complete would delete the
// unlisted half.

// Coverage statuses, one per browser attempted. The distinction they draw is
// membership completeness — whether the set of extension identities reported for
// that browser is the whole set — and not whether every attribute parsed.
const (
	// Membership complete, every attribute parsed. Zero extensions is a real
	// answer, not a missing one.
	BrowserCoverageScanned = "scanned"
	// Membership complete, one or more attributes degraded. Still authoritative,
	// because an attribute is not an identity.
	BrowserCoveragePartial = "partial"
	// Membership NOT known complete. Findings for this browser are dropped before
	// the payload is built, and a reader keeps whatever it already stored.
	BrowserCoverageFailed = "failed"
	// No data directory for this browser exists, or one exists holding no
	// installation. Stored rows for it describe a browser that is gone.
	BrowserCoverageNotPresent = "not_present"
)

// Reason codes for a browser that could not be fully read. Typed rather than
// free text because a decoder's own message quotes the document it choked on,
// and these documents are the browser's private state.
const (
	BrowserExtReasonRefusedTCC          = "refused_tcc"
	BrowserExtReasonPermissionDenied    = "permission_denied"
	BrowserExtReasonParseError          = "parse_error"
	BrowserExtReasonUnsupportedEncoding = "unsupported_encoding"
	BrowserExtReasonSymlinkRejected     = "symlink_rejected"
	BrowserExtReasonManifestUnavailable = "manifest_unavailable"
	BrowserExtReasonCapped              = "capped"
	BrowserExtReasonTimedOut            = "timed_out"
)

// Enabled state. Enabled in any one profile counts as enabled: the extension can
// run on this machine.
const (
	BrowserExtEnabled      = "enabled"
	BrowserExtDisabled     = "disabled"
	BrowserExtStateUnknown = "unknown"
)

// Who disabled it. Present exactly when the state is disabled, because the
// interesting case is not that an extension is off but that the browser turned
// it off. "Cannot tell" is spelled unknown rather than left out.
const (
	BrowserExtDisabledByUser    = "user"
	BrowserExtDisabledByBrowser = "browser"
	BrowserExtDisabledByPolicy  = "policy"
	BrowserExtDisabledByUnknown = "unknown"
)

// Whether the extension's store still lists it. Independent of enabled state:
// an extension the store has pulled while the machine still runs it, with its
// permissions granted, is the case this exists for. The browser's own cached
// belief, refreshed on its update ping, so delisted is a strong positive and
// listed is a weak negative.
const (
	BrowserExtStoreListingListed   = "listed"
	BrowserExtStoreListingDelisted = "delisted"
	BrowserExtStoreListingUnknown  = "unknown"
)

// Whether the store recorded a policy violation against it.
const (
	BrowserExtStoreViolationNone    = "none"
	BrowserExtStoreViolationFlagged = "flagged"
	BrowserExtStoreViolationUnknown = "unknown"
)

// How the extension got installed. unpacked and sideload are the highest-signal
// values in the whole record and are never excluded.
const (
	BrowserExtInstallUser     = "user"
	BrowserExtInstallSideload = "sideload"
	BrowserExtInstallRegistry = "registry"
	BrowserExtInstallUnpacked = "unpacked"
	BrowserExtInstallPolicy   = "policy"
	BrowserExtInstallUnknown  = "unknown"
)

// Which store the extension is attributed to. An enum and never a URL: a
// self-hosted update server's hostname is internal infrastructure.
const (
	BrowserExtStoreChromeWebStore = "chrome_web_store"
	BrowserExtStoreEdgeAddons     = "edge_addons"
	BrowserExtStoreAMO            = "amo"
	BrowserExtStoreSelfHosted     = "self_hosted"
	BrowserExtStoreNone           = "none"
	BrowserExtStoreUnknown        = "unknown"
)

// Signing state, gecko only. An unsigned extension that is enabled is the
// headline security signal on that engine.
const (
	BrowserExtSignedBroken       = "broken"
	BrowserExtSignedUnknownChain = "unknown_chain"
	BrowserExtSignedMissing      = "missing"
	BrowserExtSignedPreliminary  = "preliminary"
	BrowserExtSignedSigned       = "signed"
	BrowserExtSignedSystem       = "system"
	BrowserExtSignedPrivileged   = "privileged"
)

// Why the result was cut short. Set exactly when Truncated is, and never for a
// file that failed its own byte cap — that fails one browser rather than
// shortening the payload.
const (
	BrowserExtTruncatedFindingCap = "finding_cap"
	BrowserExtTruncatedDeadline   = "deadline"
)

// CurrentBrowserExtensionSchemaVersion is this block's own shape version, so a
// reader can reject a shape it does not know instead of silently dropping the
// fields it has no home for.
const CurrentBrowserExtensionSchemaVersion = 1

// BrowserExtensionScanInfo is the browser extension inventory for one run. Its
// presence is the "scan ran" sentinel and that is load-bearing: nil means no
// information at all, while non-nil with zero findings and authoritative
// coverage means the machine really holds no extensions. A reader reconciles
// stored rows against a non-nil section, so an eagerly initialised struct where
// nil was meant erases a device's inventory.
type BrowserExtensionScanInfo struct {
	PayloadSchemaVersion int `json:"payload_schema_version"`

	// The revision of the browser list probed. An identifier, not a quantity:
	// nothing compares two arithmetically.
	CatalogVersion string `json:"catalog_version"`

	CollectedAt int64 `json:"collected_at"`

	DurationMs int64 `json:"duration_ms"`

	// False when any browser failed or a cap cut the result. A degraded
	// attribute does not clear it: partial coverage describes an attribute, and
	// one extension whose metadata went missing must not mark the whole scan
	// incomplete.
	ScanComplete bool `json:"scan_complete"`

	Truncated bool `json:"truncated,omitempty"`

	TruncatedReason string `json:"truncated_reason,omitempty"`

	// One entry per catalog browser attempted on this platform. A browser this
	// platform's catalog does not carry appears nowhere: not attempted is
	// silence.
	Browsers []BrowserCoverage `json:"browsers"`

	// One entry per (browser, extension). The same extension in three profiles
	// is one finding.
	Findings []BrowserExtensionFinding `json:"findings"`
}

// BrowserCoverage is what one browser's attempt produced. It exists so stored
// rows can be reconciled per browser: without it a payload could not say
// whether zero findings for a browser means "nothing installed" or "could not
// look".
type BrowserCoverage struct {
	BrowserID string `json:"browser_id"`

	Status string `json:"status"`

	// The browser's headline reason for being degraded, required for partial and
	// failed and empty otherwise. One reason per browser: a browser that
	// degraded twice reports the first cause rather than a list nothing reads.
	ReasonCode string `json:"reason_code"`

	// Profiles enumerated across every data directory this browser has. The
	// profiles themselves stay inside the detector — their names are
	// user-chosen text and their identity was never the ask.
	ProfileCount int `json:"profile_count"`

	// Extensions reported for this browser, after exclusions and deduplication.
	// Zero for failed and not_present. It must equal the findings carrying this
	// browser_id: a count that decorates rather than describes is worse than no
	// count.
	ExtensionCount int `json:"extension_count"`
}

// BrowserExtensionFinding describes one extension in one browser.
type BrowserExtensionFinding struct {
	BrowserID string `json:"browser_id"`

	// 32 characters of [a-p] on the Chromium family, the addon id on gecko. Never
	// truncated: a shortened identity is a different identity, and a reader would
	// treat it as a different extension.
	ExtensionID string `json:"extension_id"`

	// May be empty. An extension whose metadata could not be recovered still has
	// an identity, and reporting it without a name beats not reporting it.
	Name string `json:"name"`

	Version string `json:"version"`

	// The manifest revision the browser recorded. A version 2 extension can hold
	// blocking request interception, which version 3 removed, so this is a risk
	// class rather than trivia. Zero where the browser recorded none.
	ManifestVersion int `json:"manifest_version,omitempty"`

	EnabledState string `json:"enabled_state"`

	// Present exactly when EnabledState is disabled.
	DisabledBy string `json:"disabled_by,omitempty"`

	// Present on Chromium-family findings only; gecko has no store-listing
	// concept here.
	StoreListing   string `json:"store_listing,omitempty"`
	StoreViolation string `json:"store_violation,omitempty"`

	InstallSource string `json:"install_source"`

	// Where an unpacked extension was loaded from, as the user pointed the
	// browser at it. Empty for every other install source. Never opened and never
	// resolved: it is reported because an unreviewed extension running out of a
	// user directory is the signal, and a blank name is not.
	InstallPath string `json:"install_path,omitempty"`

	Store string `json:"store"`

	// The browser shipped it as a default. Still a real extension with real
	// permissions, so it is reported; the flag is here so a console can
	// de-emphasize it.
	Preinstalled bool `json:"preinstalled"`

	// gecko only.
	SignedState string `json:"signed_state,omitempty"`

	// The API permissions and host patterns the browser recorded as granted,
	// including what the user granted at runtime, rather than what the manifest
	// asked for. Hosts the user has since withheld are left out, because the
	// browser has taken them back. An entry too long for its cap is omitted
	// rather than shortened: these strings are matched, so a shortened one is a
	// different grant.
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`

	// The hosts the extension declared content scripts for, which the browser
	// injects into automatically at page load. Not the limit of what it can
	// inject into: with host access and the scripting, userScripts or debugger
	// permission it can inject programmatically anywhere it holds a host. Nil
	// where the engine does not record the distinction, so an empty list means
	// "declared no content scripts" and an absent one means "cannot tell".
	ScriptableHostPermissions *[]string `json:"scriptable_host_permissions,omitempty"`

	// What the extension declared it collects, as far as the user's grant records
	// it. Written by gecko, the only engine that records the concept, though the
	// wire carries it on any engine. A list holding "none" is a positive
	// declaration that it
	// collects nothing, which is not the same answer as an empty list, where
	// nothing was declared at all.
	DataCollection []string `json:"data_collection,omitempty"`
}
