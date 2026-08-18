package browserext

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// The Chromium family: one parser for Chrome and Edge, whose data
// directories have the same shape on every desktop platform — a `Local State`
// file naming the profiles, and one directory per profile holding that profile's
// preferences.

// Update servers, matched by prefix because a real update URL carries query
// parameters. The URL itself never leaves the machine: a self-hosted update
// server's hostname is internal infrastructure, so only the label ships.
const (
	chromeWebStoreUpdateURL = "https://clients2.google.com/service/update2/crx"
	edgeAddonsUpdateURL     = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
)

// Install locations, as the browser records them. Component extensions are the
// browser's own parts and are not reported at all; every other value is, including
// the ones the browser cannot classify.
const (
	locationInternal               = 1
	locationExternalPref           = 2
	locationExternalRegistry       = 3
	locationUnpacked               = 4
	locationComponent              = 5
	locationExternalPrefDownload   = 6
	locationExternalPolicyDownload = 7
	locationCommandLine            = 8
	locationExternalPolicy         = 9
	locationExternalComponent      = 10
)

// Disable reasons as the browser's own enumeration numbers them, mapped to the
// actor a console should name. Membership here is recognition: a value absent
// from the table is a fork's own or a newer release's, and the browser itself
// collapses those to "unknown" rather than interpreting them. Bits 6, 7, 12, 17
// and 18 do not exist. The two reasons that mean "we do not know why" are absent
// deliberately, so they fall to the same answer as an unrecognised value.
var disableReasonActor = map[int]string{
	1 << 0:  model.BrowserExtDisabledByUser,    // user action
	1 << 1:  model.BrowserExtDisabledByBrowser, // permissions increase
	1 << 2:  model.BrowserExtDisabledByBrowser, // reload
	1 << 3:  model.BrowserExtDisabledByBrowser, // unsupported requirement
	1 << 4:  model.BrowserExtDisabledByBrowser, // sideload wipeout
	1 << 8:  model.BrowserExtDisabledByBrowser, // not verified
	1 << 9:  model.BrowserExtDisabledByBrowser, // greylist
	1 << 10: model.BrowserExtDisabledByBrowser, // corrupted
	1 << 11: model.BrowserExtDisabledByBrowser, // remote install
	1 << 13: model.BrowserExtDisabledByBrowser, // external extension
	1 << 14: model.BrowserExtDisabledByPolicy,  // update required by policy
	// Custodian approval is family supervision rather than administrative
	// policy: reading it as policy would point a fleet console at an
	// administrator who did nothing.
	1 << 15: model.BrowserExtDisabledByBrowser,
	1 << 16: model.BrowserExtDisabledByPolicy,  // blocked by policy
	1 << 19: model.BrowserExtDisabledByBrowser, // reinstall
	// Not allowlisted is the browser's own safety machinery, and it exempts
	// policy-allowed extensions, so an administrator is the one actor it
	// cannot be.
	1 << 20: model.BrowserExtDisabledByBrowser,
	1 << 21: model.BrowserExtDisabledByBrowser, // keeplist
	1 << 22: model.BrowserExtDisabledByPolicy,  // store publication required by policy
	1 << 23: model.BrowserExtDisabledByBrowser, // unsupported manifest version
	1 << 24: model.BrowserExtDisabledByBrowser, // unsupported developer extension
	1 << 26: model.BrowserExtDisabledByPolicy,  // blocked by cloud policy check
}

// scanChromiumRoot reads one Chromium-family data directory and reports whether
// it held an installation.
func (d *Detector) scanChromiumRoot(ctx context.Context, scan *scanState, root string, b *browserScan) bool {
	data, missing, reason := scan.readState(filepath.Join(root, "Local State"), maxLocalStateBytes)
	if reason != "" {
		b.fail(reason)
		return true
	}
	if missing {
		return d.classifyChromiumRoot(scan, root, b)
	}

	profiles, ok := parseProfileDirs(data)
	if !ok {
		// The profile list is what makes the extension list complete, so an
		// unreadable one means membership is unknowable: an unknown profile can
		// hold extensions. Guessing the layout instead — globbing for `Profile *`,
		// or reading `Default` alone — would ship a partial list under a status
		// that reads as complete.
		b.fail(model.BrowserExtReasonParseError)
		return true
	}
	for _, profile := range profiles {
		if ctx.Err() != nil {
			b.failPayload(model.BrowserExtReasonTimedOut, model.BrowserExtTruncatedDeadline)
			return true
		}
		if b.profiles >= maxProfilesPerBrowser {
			// An unscanned profile can hide extensions, so a bounded profile list
			// is a membership question and fails the browser rather than
			// degrading it.
			b.failBounded(model.BrowserExtReasonCapped, model.BrowserExtTruncatedFindingCap)
			return true
		}
		b.profiles++
		d.scanChromiumProfile(scan, root, profile, b)
		if b.failure != "" {
			return true
		}
	}
	return true
}

// classifyChromiumRoot decides what a data directory with no `Local State` is. A
// directory can exist while the browser never has — installers leave one behind
// holding nothing but an empty native-messaging folder — and calling that a
// failure would paint a permanent red row for a browser nobody installed, on
// every scan, which is how a coverage list stops being read.
//
// It reads directory entries only; no file is opened. Reporting the directory as
// absent is authoritative, and safely so: the only rows it can retire are rows a
// previous scan of this same empty directory wrote, and that scan cannot have
// found anything either.
func (d *Detector) classifyChromiumRoot(scan *scanState, root string, b *browserScan) bool {
	names, missing, reason := scan.listNames(root, maxRootEntries)
	if reason != "" {
		b.fail(reason)
		return true
	}
	if missing {
		return false
	}
	for _, name := range names {
		if name == "Default" || name == "Secure Preferences" || name == "Preferences" ||
			strings.HasPrefix(name, "Profile ") {
			// A profile is here but the file naming the profiles is not: this is
			// a broken installation, not an absent one.
			b.fail(model.BrowserExtReasonParseError)
			return true
		}
	}
	return false
}

// parseProfileDirs returns the profile directory names from `Local State`.
//
// The values beside those names carry the profile's display label, the signed-in
// account's name and its e-mail address. They are decoded as raw bytes and never
// looked at: the directory basename is the only part this reads, and even that
// stays inside the detector.
func parseProfileDirs(data []byte) ([]string, bool) {
	var state struct {
		Profile struct {
			InfoCache map[string]json.RawMessage `json:"info_cache"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	if len(state.Profile.InfoCache) == 0 {
		// A data directory that names no profile tells us nothing about which
		// profiles exist, which is not the same as telling us there are none.
		return nil, false
	}
	names := make([]string, 0, len(state.Profile.InfoCache))
	for name := range state.Profile.InfoCache {
		if !isDirName(name) {
			// A key that is not a directory basename would move the read
			// somewhere else entirely. The file is not trustworthy, so nothing
			// derived from it is.
			return nil, false
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

// isDirName reports whether name can be one directory entry: not empty, not a
// traversal, and carrying no separator of either flavour.
func isDirName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

// hasParentComponent reports whether a relative path steps above its base. A
// component test rather than a substring one: a version directory is free to
// contain dots, and "1..0" walks nowhere.
func hasParentComponent(path string) bool {
	for _, c := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if c == ".." {
			return true
		}
	}
	return false
}

// scanChromiumProfile reads one profile's extension records.
//
// `Secure Preferences` is read first on every platform, because that is where the
// extension map lives on all of them — the belief that Linux keeps it in plain
// `Preferences` is wrong: what differs per platform is whether the browser
// enforces the file's integrity, not where it writes it. Plain `Preferences` fills
// in ids the first file does not carry, which split preference tracking makes
// possible. The integrity fields beside them are skipped: this reads, and the
// browser's own tamper detection is not its business.
func (d *Detector) scanChromiumProfile(scan *scanState, root, profile string, b *browserScan) {
	dir := filepath.Join(root, profile)
	settings := map[string]json.RawMessage{}
	for _, name := range []string{"Secure Preferences", "Preferences"} {
		data, missing, reason := scan.readState(filepath.Join(dir, name), maxPrefsBytes)
		if reason != "" {
			b.fail(reason)
			return
		}
		if missing {
			continue
		}
		entries, ok := parseExtensionSettings(data)
		if !ok {
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		for id, raw := range entries {
			if _, seen := settings[id]; !seen {
				settings[id] = raw
			}
		}
	}

	ids := make([]string, 0, len(settings))
	for id := range settings {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		occ, ok := d.chromiumOccurrence(scan, dir, id, settings[id], b)
		if !ok {
			continue
		}
		// The data directory and profile together order the occurrences of one
		// extension seen in several places.
		occ.sortKey = dir
		if !b.add(id, occ) {
			return
		}
	}
}

// parseExtensionSettings returns the per-extension map from a preferences file.
// Values stay raw so one corrupt record cannot cost the whole file.
func parseExtensionSettings(data []byte) (map[string]json.RawMessage, bool) {
	var prefs struct {
		Extensions struct {
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(data, &prefs); err != nil {
		return nil, false
	}
	return prefs.Extensions.Settings, true
}

// chromiumEntry is one record under the extension map. Every field is optional:
// the file is written by a browser whose shape changes between releases, and a
// missing field degrades one attribute rather than the record.
type chromiumEntry struct {
	Location       *int            `json:"location"`
	DisableReasons json.RawMessage `json:"disable_reasons"`
	// The pre-list form of the same fact, read only when disable_reasons is
	// absent: current browsers do not write it.
	State *int `json:"state"`
	// Relative to the profile's own Extensions directory for a store install,
	// absolute for an unpacked one. An absolute path is never opened and never
	// resolved. It does reach the wire for an unpacked extension, whose load
	// location is the most useful thing its record holds.
	Path                  string            `json:"path"`
	Manifest              *chromiumManifest `json:"manifest"`
	FromWebstore          *bool             `json:"from_webstore"`
	WasInstalledByDefault bool              `json:"was_installed_by_default"`
	WasInstalledByOEM     bool              `json:"was_installed_by_oem"`
	// What the extension holds now, and the only set the wire is built from.
	// granted_permissions has no field here at all: Chromium defines it as the
	// maximum the extension has ever held and not had globally revoked, so a
	// permission a later version stopped asking for, or one handed back through
	// the permissions API, stays there after the browser stopped honouring it.
	// Leaving it out also means a browser version that writes the historical
	// record differently cannot cost us a row we can otherwise read.
	//
	// Held raw and decoded on its own so that a permission block in a shape this
	// parser cannot read costs the permissions rather than the record: the
	// identity, install source, store disposition and enabled state are all
	// still there to report.
	Active json.RawMessage `json:"active_permissions"`
	// An additional store behind runtime host controls, read only when
	// withholding is set below. Its patterns can be broader than the extension
	// ever asked for, so it narrows the request and never widens it.
	RuntimeGranted json.RawMessage `json:"runtime_granted_permissions"`
	// Set when the user restricted the extension's site access. The active set
	// keeps listing every host the extension requested, and the runtime store
	// records what the user left it, so the hosts the browser honours have to be
	// worked out from both. API permissions are never withheld.
	WithholdingHostPermissions bool             `json:"withholding_permissions"`
	CWSInfo                    *chromiumCWSInfo `json:"cws-info"`
}

// chromiumManifest is the copy of the extension's manifest the browser keeps
// inside its own preferences. It covers almost every extension, which is what
// keeps this phase to two file reads per profile.
type chromiumManifest struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	DefaultLocale string `json:"default_locale"`
	UpdateURL     string `json:"update_url"`
	// Version 2 can hold blocking request interception, which version 3 removed,
	// so two extensions doing the same job differ here in what they are able to
	// do to a page.
	ManifestVersion int `json:"manifest_version"`
	// Presence alone is the test: a manifest with either key is a theme or a
	// legacy packaged app rather than an extension.
	Theme json.RawMessage `json:"theme"`
	App   json.RawMessage `json:"app"`
}

// chromiumPermissions is one grant record. The active set is read in place of what
// the manifest declared, because a declaration is a request and this is what the
// browser is honouring right now.
type chromiumPermissions struct {
	API            []string `json:"api"`
	ExplicitHost   []string `json:"explicit_host"`
	ScriptableHost []string `json:"scriptable_host"`
}

// chromiumCWSInfo is the browser's cached belief about the store's listing. It is
// the highest-value pair in the record: an extension the store has pulled while
// the machine still runs it, with its permissions granted, is exactly the shape of
// a compromised extension, and nothing else on disk says so.
type chromiumCWSInfo struct {
	IsLive        *bool `json:"is-live"`
	ViolationType *int  `json:"violation-type"`
}

// chromiumOccurrence turns one preference record into one occurrence, or reports
// that the record does not describe an installed extension.
func (d *Detector) chromiumOccurrence(scan *scanState, profileDir, id string, raw json.RawMessage, b *browserScan) (occurrence, bool) {
	if !chromiumIDShape(id) {
		// The browser generates every extension id — store, sideload, policy and
		// unpacked alike — as thirty-two letters from the first sixteen of the
		// alphabet, so a key of another shape cannot name an extension and the
		// browser's own loader could not load it. A classification filter, not a
		// degradation: what this key names is not in the extension set at all.
		return occurrence{}, false
	}

	var e chromiumEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		// The map key is the identity, so a corrupt record costs the metadata
		// and not the extension. Reported with what survived, which keeps
		// membership complete while the browser goes partial.
		b.degrade(model.BrowserExtReasonManifestUnavailable)
		return reducedOccurrence(), true
	}
	if e.Manifest == nil && e.Path == "" && e.Location == nil {
		// Bookkeeping residue: an update-ping or allowlist stub with nothing the
		// browser could load. It is not listed as an extension by the browser
		// either, so reporting it would invent one — and, having no manifest, it
		// would also degrade the browser on every scan for ever. Any one of the
		// three fields present means there was something real to record, and the
		// reduced-finding path below covers it.
		return occurrence{}, false
	}

	source, reported := installSource(e.Location)
	if !reported {
		// A part of the browser itself rather than something installed into it.
		return occurrence{}, false
	}

	manifest := e.Manifest
	// Only a store install's path is relative, which is what makes it safe to
	// resolve: it lands inside the browser's own tree. An unpacked extension's
	// path is an arbitrary user location, so it is never opened and never
	// resolved, and nothing about it is read beyond what the preferences recorded.
	extDir := ""
	unpackedLocation := filepath.IsAbs(e.Path)
	if e.Path != "" && !unpackedLocation && !hasParentComponent(e.Path) {
		extDir = filepath.Join(profileDir, "Extensions", filepath.FromSlash(e.Path))
	}
	if manifest == nil && extDir != "" {
		data, missing, reason := scan.readState(filepath.Join(extDir, "manifest.json"), maxManifestBytes)
		if reason != "" {
			// Membership came from the preference map, which has already been read
			// whole. Nothing this file could have said would add or remove an
			// extension, so a refusal costs the metadata and the browser goes
			// partial rather than losing a list that is known complete.
			b.degrade(reason)
		}
		if !missing && reason == "" {
			var m chromiumManifest
			if json.Unmarshal(data, &m) == nil {
				manifest = &m
			}
		}
	}
	if manifest != nil && (len(manifest.Theme) > 0 || len(manifest.App) > 0) {
		// A theme or a legacy packaged app. Neither runs code against pages, so
		// neither is what this inventory is about.
		return occurrence{}, false
	}

	name, version, manifestVersion := "", "", 0
	if manifest == nil {
		if !unpackedLocation {
			// An unpacked extension's manifest was never going to be read, so
			// nothing failed to read: reporting one as degraded would paint the
			// browser partial on every scan for as long as a developer keeps a
			// build loaded. Every other route to a nil manifest is a document this
			// scan could not recover.
			b.degrade(model.BrowserExtReasonManifestUnavailable)
		}
	} else {
		name = d.resolveExtensionName(scan, extDir, manifest, b)
		version = manifest.Version
		manifestVersion = manifest.ManifestVersion
	}

	// The location an unpacked extension was loaded from is the most useful thing
	// its record holds, and the only one that survives having no manifest. An
	// over-long path is left out rather than shortened: half a path names a
	// directory nobody has.
	installPath := ""
	if source == model.BrowserExtInstallUnpacked && len(e.Path) <= maxInstallPathBytes {
		installPath = e.Path
	}

	state, disabledBy := chromiumEnabledState(e)
	listing, violation := storeDisposition(e.CWSInfo)
	perms, hosts, scriptable, capped, permsUnavailable, hostsUnknown := permissionLists(e.Active, e.RuntimeGranted, e.WithholdingHostPermissions)
	if capped {
		b.degrade(model.BrowserExtReasonCapped)
	}
	// The record is here and the extension is real; one attribute of it could
	// not be recovered, which is the same shape as a record whose manifest is
	// missing and carries the same reason.
	scriptableList := &scriptable
	if permsUnavailable || hostsUnknown {
		b.degrade(model.BrowserExtReasonManifestUnavailable)
		scriptableList = nil
	}
	return occurrence{
		enabled:    state,
		disabledBy: disabledBy,
		block: model.BrowserExtensionFinding{
			Name:            capBytes(name, maxNameBytes),
			Version:         capBytes(version, maxVersionBytes),
			ManifestVersion: manifestVersion,
			EnabledState:    state,
			StoreListing:    listing,
			StoreViolation:  violation,
			InstallSource:   source,
			InstallPath:     installPath,
			Store:           chromiumStore(manifest, e),
			Preinstalled:    e.WasInstalledByDefault || e.WasInstalledByOEM,
			Permissions:     perms,
			HostPermissions: hosts,
			// Answered on this family whenever the active set was read: it names
			// the scriptable hosts separately, so an empty list is "injects
			// nowhere". With no active set to read there is no answer, and nil
			// is how the wire says so.
			ScriptableHostPermissions: scriptableList,
		},
	}, true
}

// reducedOccurrence is what a record whose value could not be read produces: an
// identity, and everything else spelled as unknown rather than left out. A reader
// requires the two store fields on this family, and "cannot tell" is a value.
//
// The scriptable host list is the one field left absent rather than empty. Empty
// would claim the extension injects nowhere, and no grant record was read to say
// so.
func reducedOccurrence() occurrence {
	return occurrence{
		enabled: model.BrowserExtStateUnknown,
		block: model.BrowserExtensionFinding{
			EnabledState:    model.BrowserExtStateUnknown,
			StoreListing:    model.BrowserExtStoreListingUnknown,
			StoreViolation:  model.BrowserExtStoreViolationUnknown,
			InstallSource:   model.BrowserExtInstallUnknown,
			Store:           model.BrowserExtStoreUnknown,
			Permissions:     []string{},
			HostPermissions: []string{},
		},
	}
}

// chromiumIDShape reports whether id has the shape this family generates: exactly
// thirty-two characters from a through p.
func chromiumIDShape(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 'a' || id[i] > 'p' {
			return false
		}
	}
	return true
}

// installSource maps a recorded location to how the extension got there,
// reporting false for the values that are the browser's own components.
func installSource(location *int) (string, bool) {
	if location == nil {
		return model.BrowserExtInstallUnknown, true
	}
	switch *location {
	case locationInternal:
		return model.BrowserExtInstallUser, true
	case locationExternalPref, locationExternalPrefDownload:
		return model.BrowserExtInstallSideload, true
	case locationExternalRegistry:
		return model.BrowserExtInstallRegistry, true
	case locationUnpacked, locationCommandLine:
		// The highest-signal rows in the whole inventory, and never excluded.
		return model.BrowserExtInstallUnpacked, true
	case locationExternalPolicyDownload, locationExternalPolicy:
		// The installed state is evidence enough of a policy install; the policy
		// sources themselves are not read, which keeps this phase to file reads
		// inside one home.
		return model.BrowserExtInstallPolicy, true
	case locationComponent, locationExternalComponent:
		return "", false
	default:
		return model.BrowserExtInstallUnknown, true
	}
}

// chromiumEnabledState derives whether the extension runs, and who stopped it.
//
// Enabled is the empty disable-reason set — not a flag, and not the absence of
// the record. The reason set names the actor rather than the cause: two very
// different browser decisions carry the same value, which is why the store
// disposition is read separately.
func chromiumEnabledState(e chromiumEntry) (state, disabledBy string) {
	if len(e.DisableReasons) == 0 {
		if e.State != nil {
			// A profile old enough to predate the reason set. Last resort: it
			// says whether, not why.
			if *e.State == 1 {
				return model.BrowserExtEnabled, ""
			}
			return model.BrowserExtDisabled, model.BrowserExtDisabledByUnknown
		}
		return model.BrowserExtEnabled, ""
	}
	reasons, ok := parseDisableReasons(e.DisableReasons)
	if !ok {
		// The field is there and unreadable, so enabled and disabled are
		// indistinguishable. Saying either would be a guess a console would
		// display as fact.
		return model.BrowserExtStateUnknown, ""
	}
	if len(reasons) == 0 {
		return model.BrowserExtEnabled, ""
	}
	actor := ""
	for _, r := range reasons {
		switch disableReasonActor[r] {
		case model.BrowserExtDisabledByUser:
			return model.BrowserExtDisabled, model.BrowserExtDisabledByUser
		case model.BrowserExtDisabledByPolicy:
			actor = model.BrowserExtDisabledByPolicy
		case model.BrowserExtDisabledByBrowser:
			if actor == "" {
				actor = model.BrowserExtDisabledByBrowser
			}
		}
	}
	if actor == "" {
		// Recognised nothing in the set, so the actor is genuinely not known.
		return model.BrowserExtDisabled, model.BrowserExtDisabledByUnknown
	}
	return model.BrowserExtDisabled, actor
}

// parseDisableReasons reads both shapes in the wild: current browsers write a
// list of values, older profiles a single combined bitmask.
func parseDisableReasons(raw json.RawMessage) ([]int, bool) {
	var list []int
	if json.Unmarshal(raw, &list) == nil {
		return list, true
	}
	var mask int
	if json.Unmarshal(raw, &mask) != nil || mask < 0 {
		return nil, false
	}
	var out []int
	for bit := 1; bit > 0 && bit <= mask; bit <<= 1 {
		if mask&bit != 0 {
			out = append(out, bit)
		}
	}
	return out, true
}

// storeDisposition reads the cached store listing. An absent record is unknown
// and never listed: inferring that the store still carries an extension from the
// absence of a record would turn a missing answer into a reassuring one.
//
// It is a cached belief, refreshed on the browser's update ping, so a browser that
// has not run since a takedown still says listed. Delisted is a strong positive
// and listed a weak negative, which is a distinction the copy in front of a
// customer has to keep.
func storeDisposition(info *chromiumCWSInfo) (listing, violation string) {
	listing, violation = model.BrowserExtStoreListingUnknown, model.BrowserExtStoreViolationUnknown
	if info == nil {
		return listing, violation
	}
	if info.IsLive != nil {
		if *info.IsLive {
			listing = model.BrowserExtStoreListingListed
		} else {
			listing = model.BrowserExtStoreListingDelisted
		}
	}
	if info.ViolationType != nil {
		if *info.ViolationType == 0 {
			violation = model.BrowserExtStoreViolationNone
		} else {
			violation = model.BrowserExtStoreViolationFlagged
		}
	}
	return listing, violation
}

// chromiumStore attributes the extension to a store, as a label and never a URL.
// The label follows the update URL the install itself carries, which is the right
// answer from where the code came from: an Edge install of an extension published
// to the Chrome Web Store still points at that store.
func chromiumStore(manifest *chromiumManifest, e chromiumEntry) string {
	url := ""
	if manifest != nil {
		url = strings.TrimSpace(manifest.UpdateURL)
	}
	switch {
	case url == "":
		if e.FromWebstore != nil && *e.FromWebstore {
			return model.BrowserExtStoreChromeWebStore
		}
		return model.BrowserExtStoreUnknown
	case strings.HasPrefix(url, chromeWebStoreUpdateURL):
		return model.BrowserExtStoreChromeWebStore
	case strings.HasPrefix(url, edgeAddonsUpdateURL):
		return model.BrowserExtStoreEdgeAddons
	default:
		return model.BrowserExtStoreSelfHosted
	}
}

// resolveExtensionName resolves a localized name to the string a person would
// see. Store installs only, on the same grounds as the manifest read: the message
// table sits inside the browser's own tree.
func (d *Detector) resolveExtensionName(scan *scanState, extDir string, manifest *chromiumManifest, b *browserScan) string {
	key, localized := messageKey(manifest.Name)
	if !localized || extDir == "" {
		return manifest.Name
	}
	for _, locale := range localeCandidates(manifest.DefaultLocale) {
		data, missing, reason := scan.readState(
			filepath.Join(extDir, "_locales", locale, "messages.json"), maxMessagesBytes)
		if reason != "" {
			// A name is an attribute. The identity is already known, so an
			// unreadable message table degrades the browser and leaves the
			// placeholder standing.
			b.degrade(reason)
			return manifest.Name
		}
		if missing {
			continue
		}
		if value := lookupMessage(data, key); value != "" {
			return value
		}
	}
	// Nothing resolved it. The placeholder is still the closest thing to a name
	// this extension has, and an empty one would read as metadata never recorded.
	return manifest.Name
}

// messageKey extracts the message name from a localized manifest value.
func messageKey(name string) (string, bool) {
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") || len(name) <= len("__MSG___") {
		return "", false
	}
	return name[len("__MSG_") : len(name)-len("__")], true
}

// localeCandidates returns the message tables to try, in order. The declared
// default locale is read rather than the machine's, so the resolved name is the
// same on every machine holding the same extension. Directory names use
// underscores rather than the hyphen of a language tag.
func localeCandidates(defaultLocale string) []string {
	candidates := make([]string, 0, 3)
	for _, locale := range []string{strings.ReplaceAll(defaultLocale, "-", "_"), "en_US", "en"} {
		if locale == "" || !isDirName(locale) {
			continue
		}
		if !slices.Contains(candidates, locale) {
			candidates = append(candidates, locale)
		}
	}
	return candidates
}

// lookupMessage returns one message's text. Keys are compared case-insensitively,
// which is what the browser itself does on both sides of the lookup.
func lookupMessage(data []byte, key string) string {
	var table map[string]struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		return ""
	}
	want := strings.ToLower(key)
	for name, entry := range table {
		if strings.ToLower(name) == want {
			return entry.Message
		}
	}
	return ""
}

// permissionLists reduces the grant records to the three wire lists.
//
// Only the active set is read. It is what the browser is honouring now, where
// the granted set is everything the extension has ever held: reading it would
// report access the extension no longer has, and there is no fallback to it
// when the active set cannot be read, because a historical grant is not weaker
// evidence of present access - it is evidence of something else.
//
// The runtime store is read only under withholding, and only to work out which
// of the requested hosts survived it. Explicit and scriptable hosts are matched
// against their own side of that store, never against each other: the two mean
// different things to the browser - one is what requests and cookie reads may
// reach, the other is where content scripts run - and the browser writes a
// granted origin into both sides whether or not the extension has any content
// script, so crossing them would invent provenance the extension never declared.
//
// The scriptable list is a subset of the host list and is derived from it after
// the cap rather than beside it, so a host the cap dropped cannot survive in the
// stronger list alone. Injecting code into a page is a larger capability than
// reaching it with a request, and a reader that saw one without the other would
// have to guess which.
//
// unavailable reports that there is no active set to read, and hostsUnknown that
// the runtime store the withheld hosts had to be read from could not be read.
// Either way the caller emits no evidence for what it could not establish and
// marks the browser partial: an empty list is the positive claim that the
// extension holds nothing, and neither of these is that claim.
func permissionLists(activeRaw, runtimeRaw json.RawMessage, withholdingHosts bool) (perms, hosts, scriptable []string, capped, unavailable, hostsUnknown bool) {
	active, present, ok := decodePermissions(activeRaw)
	if !present || !ok {
		// Empty rather than nil: these two lists are always written, and the
		// absent answer is carried by the nil scriptable list and the browser's
		// partial status instead of by a second shape for the same field.
		return []string{}, []string{}, nil, false, true, false
	}
	explicit, script := active.ExplicitHost, active.ScriptableHost
	if withholdingHosts {
		runtime, _, ok := decodePermissions(runtimeRaw)
		if !ok {
			// The API permissions are still good: withholding applies to hosts
			// alone, and they were read from the active set. Only the hosts are
			// unknown, so only they are left out.
			perms, apiCapped := capPermissionList(active.API)
			return perms, []string{}, nil, apiCapped, false, true
		}
		explicit = withheldHosts(explicit, runtime.ExplicitHost)
		script = withheldHosts(script, runtime.ScriptableHost)
	}
	scriptableSet := make(map[string]struct{}, len(script))
	for _, h := range script {
		scriptableSet[h] = struct{}{}
	}
	perms, apiCapped := capPermissionList(active.API)
	hosts, hostCapped := capPermissionList(append(append([]string{}, explicit...), script...))
	scriptable = []string{}
	for _, h := range hosts {
		if _, ok := scriptableSet[h]; ok {
			scriptable = append(scriptable, h)
		}
	}
	return perms, hosts, scriptable, apiCapped || hostCapped, false, false
}

// decodePermissions reads one grant record, reporting whether the browser wrote
// it at all separately from whether it could be read. A record that was never
// written is not the same fact as one written in a shape this parser does not
// know, and the two answers differ: nothing withheld back is a real empty set,
// while an unreadable store leaves the question open.
func decodePermissions(raw json.RawMessage) (p chromiumPermissions, present, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return p, false, true
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, true, false
	}
	return p, true, true
}

// withheldHosts keeps the hosts the browser still honours after the user
// restricted the extension's site access. The browser hands the extension the
// intersection of what it requested and what the runtime store holds, and the
// granted origin is written into the runtime store alone - it is never added to
// the active set - so the answer is drawn from the runtime side.
//
// A runtime pattern counts in one of two cases. The request names it exactly, or
// the request covers the whole web and the pattern is one of the sites it covers:
// an extension asking for <all_urls> and left one site reaches that one site,
// which is the common case. Whole-web authority is the same test the ranking
// applies, so the http and https wildcard pair counts as well as either
// single-pattern form, and the pair carries no reach over local files, so under
// it a granted file pattern is not admitted. <all_urls> does cover them.
//
// Nothing else counts. Working out whether one pattern covers another in the
// general case is the browser's own matching logic, and a producer guessing at it
// would report reach that was never granted, so a mid-width request such as
// *://*.example.internal/* with a narrower grant under it reports no host at all.
// That is a false negative, which is the direction this inventory errs in.
func withheldHosts(requested, runtime []string) []string {
	if len(runtime) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(requested))
	everyScheme := false
	for _, pattern := range requested {
		if pattern == allURLsPattern {
			everyScheme = true
		}
		set[pattern] = struct{}{}
	}
	wholeWeb := hasBroadHosts(requested)
	out := make([]string, 0, len(runtime))
	for _, granted := range runtime {
		_, exact := set[granted]
		if exact || everyScheme || (wholeWeb && isWebPattern(granted)) {
			out = append(out, granted)
		}
	}
	return out
}

// isWebPattern reports whether a host pattern names reach over websites. The
// scheme is the whole test: what a pattern's host part matches is the browser's
// business, but a pattern that cannot name an http or https URL is not website
// reach whatever else it covers.
func isWebPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "http://") ||
		strings.HasPrefix(pattern, "https://") ||
		strings.HasPrefix(pattern, "*://")
}

// capPermissionList sorts, deduplicates and bounds one permission list, reporting
// whether anything was left out.
//
// An over-long entry is dropped rather than shortened. These strings are matched
// and not read — a permission is compared for equality and a host pattern is a
// match expression — so a shortened one is a different grant, and showing whoever
// is auditing a permission the extension never held is worse than showing them
// one fewer.
func capPermissionList(in []string) ([]string, bool) {
	out := make([]string, 0, len(in))
	capped := false
	seen := map[string]bool{}
	for _, entry := range in {
		if entry == "" || seen[entry] {
			continue
		}
		seen[entry] = true
		if len(entry) > maxPermissionBytes {
			capped = true
			continue
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	if len(out) > maxPermissionsPerFinding {
		out = out[:maxPermissionsPerFinding]
		capped = true
	}
	return out, capped
}
