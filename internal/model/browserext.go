package model

// Browser extension inventory wire types. A finding names one extension in one
// browser: whether it is enabled and why not, where it came from, whether its
// store still lists it, and what it is permitted to touch. It carries no browsing
// state: no history, cookies, passwords, page content or profile names.
//
// Extension state is stored per extension, so a payload has to say which browsers
// it speaks for. That is browsers[]: a reader retires stored rows only for a
// browser whose entry claims a complete membership list, and a browser whose
// extension set could not be fully enumerated ships no findings at all.

// Coverage statuses, one per browser attempted. They answer whether the set of
// extension identities reported for that browser is the whole set, not whether
// every attribute parsed.
const (
	// Membership complete, every attribute parsed. Zero extensions is a real
	// answer, not a missing one.
	BrowserCoverageScanned = "scanned"
	// Membership complete, one or more attributes degraded. Still authoritative.
	BrowserCoveragePartial = "partial"
	// Membership not known complete. Findings for this browser are dropped before
	// the payload is built, and a reader keeps whatever it already stored.
	BrowserCoverageFailed = "failed"
	// No data directory for this browser exists, or one exists holding no
	// installation.
	BrowserCoverageNotPresent = "not_present"
)

// Reason codes for a browser that could not be fully read. Typed rather than free
// text: a decoder's own message quotes the document it choked on, and these
// documents are the browser's private state.
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

// Who disabled it, set exactly when the state is disabled. The interesting case is
// not that an extension is off but that the browser turned it off.
const (
	BrowserExtDisabledByUser    = "user"
	BrowserExtDisabledByBrowser = "browser"
	BrowserExtDisabledByPolicy  = "policy"
	BrowserExtDisabledByUnknown = "unknown"
)

// Whether the extension's store still lists it, from the browser's own cached
// belief refreshed on its update ping. Independent of enabled state, and delisted
// is a strong positive where listed is a weak negative.
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

// How the extension got installed.
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

// Signing state, gecko only.
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
// file that failed its own byte cap: that fails one browser rather than
// shortening the payload.
const (
	BrowserExtTruncatedFindingCap = "finding_cap"
	BrowserExtTruncatedDeadline   = "deadline"
)

// CurrentBrowserExtensionSchemaVersion is this block's own shape version, so a
// reader can reject a shape it does not know instead of dropping the fields it has
// no home for.
const CurrentBrowserExtensionSchemaVersion = 1

// BrowserExtensionScanInfo is the browser extension inventory for one run. Nil
// means no information at all; non-nil with zero findings and authoritative
// coverage means the machine really holds no extensions. A reader reconciles
// stored rows against a non-nil section, so an eagerly initialised struct where
// nil was meant erases a device's inventory.
type BrowserExtensionScanInfo struct {
	PayloadSchemaVersion int `json:"payload_schema_version"`

	// The revision of the browser list probed. An identifier, not a quantity.
	CatalogVersion string `json:"catalog_version"`

	CollectedAt int64 `json:"collected_at"`

	DurationMs int64 `json:"duration_ms"`

	// False when any browser failed or a cap cut the result. A degraded attribute
	// does not clear it: one extension whose metadata went missing must not mark
	// the whole scan incomplete.
	ScanComplete bool `json:"scan_complete"`

	Truncated bool `json:"truncated,omitempty"`

	TruncatedReason string `json:"truncated_reason,omitempty"`

	// One entry per catalog browser attempted on this platform. A browser this
	// platform's catalog does not carry appears nowhere.
	Browsers []BrowserCoverage `json:"browsers"`

	// One entry per (browser, extension). The same extension in three profiles is
	// one finding.
	Findings []BrowserExtensionFinding `json:"findings"`
}

// BrowserCoverage is what one browser's attempt produced. Stored rows are
// reconciled per browser, so without it a payload could not say whether zero
// findings for a browser means nothing installed or could not look.
type BrowserCoverage struct {
	BrowserID string `json:"browser_id"`

	Status string `json:"status"`

	// The browser's headline reason for being degraded, required for partial and
	// failed and empty otherwise. One reason per browser: a browser that degraded
	// twice reports the first cause.
	ReasonCode string `json:"reason_code"`

	// Profiles enumerated across every data directory this browser has. The
	// profiles themselves stay inside the detector: their names are user-chosen
	// text.
	ProfileCount int `json:"profile_count"`

	// Extensions reported for this browser, after exclusions and deduplication.
	// Zero for failed and not_present, and otherwise equal to the findings
	// carrying this browser_id.
	ExtensionCount int `json:"extension_count"`
}

// BrowserExtensionFinding describes one extension in one browser.
type BrowserExtensionFinding struct {
	BrowserID string `json:"browser_id"`

	// 32 characters of [a-p] on the Chromium family, the addon id on gecko. Never
	// truncated: a shortened identity is a different identity.
	ExtensionID string `json:"extension_id"`

	// May be empty. An extension whose metadata could not be recovered still has
	// an identity.
	Name string `json:"name"`

	Version string `json:"version"`

	// The manifest revision the browser recorded, zero where it recorded none.
	// Version 2 can hold blocking request interception, which version 3 removed.
	ManifestVersion int `json:"manifest_version,omitempty"`

	EnabledState string `json:"enabled_state"`

	// Present exactly when EnabledState is disabled.
	DisabledBy string `json:"disabled_by,omitempty"`

	// Present on Chromium-family findings only; gecko has no store-listing
	// concept here.
	StoreListing   string `json:"store_listing,omitempty"`
	StoreViolation string `json:"store_violation,omitempty"`

	InstallSource string `json:"install_source"`

	// Where an unpacked extension was loaded from, as the user pointed the browser
	// at it. Empty for every other install source, and never opened or resolved.
	InstallPath string `json:"install_path,omitempty"`

	Store string `json:"store"`

	// The browser shipped it as a default. Still a real extension with real
	// permissions, so it is reported; the flag lets a console de-emphasize it.
	Preinstalled bool `json:"preinstalled"`

	// gecko only.
	SignedState string `json:"signed_state,omitempty"`

	// The API permissions and host patterns the browser is honouring now, rather
	// than what the manifest asked for or what the extension has held at some
	// point. Hosts the user has since withheld are left out. An entry too long for
	// its cap is omitted rather than shortened: these strings are matched, so a
	// shortened one is a different grant. Empty where the browser's record of
	// present access could not be read, with the browser reported partial to say
	// so.
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`

	// The hosts the extension declared content scripts for, which the browser
	// injects into automatically at page load. Not the limit of what it can inject
	// into: with host access and the scripting, userScripts or debugger permission
	// it can inject programmatically anywhere it holds a host. Nil where the engine
	// does not record the distinction, so an empty list means it declared no
	// content scripts and an absent one means this cannot tell.
	ScriptableHostPermissions *[]string `json:"scriptable_host_permissions,omitempty"`

	// What the extension declared it collects, as far as the user's grant records
	// it. Written by gecko, the only engine that records the concept, though the
	// wire carries it on any engine. A list holding "none" is a positive
	// declaration that it collects nothing, which is not the same answer as an
	// empty list, where nothing was declared at all.
	DataCollection []string `json:"data_collection,omitempty"`
}
