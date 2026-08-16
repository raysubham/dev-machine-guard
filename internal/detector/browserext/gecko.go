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

// The gecko family. Profiles are listed in an INI file and each one keeps its
// add-on database in a single JSON document.

// Add-on classes. A closed vocabulary rather than a permissive filter: an entry
// whose class this build does not recognise may be a real extension, and under a
// status that reads as a complete list, silently skipping it un-reports it. So an
// unrecognised class fails the browser instead, which is a visible gap that one
// vocabulary entry closes rather than a membership list that quietly shrank.
const geckoTypeExtension = "extension"

var geckoNonMemberTypes = map[string]bool{
	"theme":          true,
	"locale":         true,
	"dictionary":     true,
	"sitepermission": true,
}

// Where the add-on is installed from, as the database records it. The builtin
// scopes are the browser's own components and are not reported; the sideload
// scopes are alive on the extended-support channel, which is exactly the
// enterprise population, so they are reported rather than dropped.
var geckoInstallSources = map[string]string{
	"app-profile":       model.BrowserExtInstallUser,
	"winreg-app-user":   model.BrowserExtInstallRegistry,
	"winreg-app-global": model.BrowserExtInstallRegistry,
	"app-system-user":   model.BrowserExtInstallSideload,
	"app-global":        model.BrowserExtInstallSideload,
	"app-system-share":  model.BrowserExtInstallSideload,
	"app-system-local":  model.BrowserExtInstallSideload,
	"app-temporary":     model.BrowserExtInstallUnpacked,
}

var geckoBuiltinScopes = map[string]bool{
	"app-builtin":         true,
	"app-builtin-addons":  true,
	"app-system-addons":   true,
	"app-system-profile":  true,
	"app-system-defaults": true,
}

// The only on-disk discriminator for an administrator-installed add-on: its
// scope is an ordinary profile install and nothing else distinguishes it.
const geckoPolicySource = "enterprise-policy"

// Signing states, as the database numbers them. An unsigned add-on that is
// enabled is the headline security signal on this engine.
var geckoSignedStates = map[int]string{
	-2: model.BrowserExtSignedBroken,
	-1: model.BrowserExtSignedUnknownChain,
	0:  model.BrowserExtSignedMissing,
	1:  model.BrowserExtSignedPreliminary,
	2:  model.BrowserExtSignedSigned,
	3:  model.BrowserExtSignedSystem,
	4:  model.BrowserExtSignedPrivileged,
}

// scanGeckoRoot reads one gecko data directory and reports whether it held an
// installation.
func (d *Detector) scanGeckoRoot(ctx context.Context, scan *scanState, root string, b *browserScan) bool {
	declared, registered, reason := d.geckoDeclaredProfiles(scan, root)
	if reason != "" {
		b.fail(reason)
		return true
	}
	discovered, reason := d.geckoDiscoveredProfiles(scan, root)
	if reason != "" {
		b.fail(reason)
		return true
	}

	candidates := declared
	for _, dir := range discovered {
		if !slices.Contains(candidates, dir) {
			candidates = append(candidates, dir)
		}
	}
	sort.Strings(candidates)

	found := false
	for _, dir := range candidates {
		if ctx.Err() != nil {
			b.failPayload(model.BrowserExtReasonTimedOut, model.BrowserExtTruncatedDeadline)
			return true
		}
		if b.profiles >= maxProfilesPerBrowser {
			b.failBounded(model.BrowserExtReasonCapped, model.BrowserExtTruncatedFindingCap)
			return true
		}
		data, missing, reason := scan.readState(filepath.Join(dir, "extensions.json"), maxExtensionsJSONBytes)
		if reason != "" {
			b.fail(reason)
			return true
		}
		if missing {
			// A directory that is not a profile, or a profile the browser has
			// registered and never opened. Neither is a failure to report.
			continue
		}
		found = true
		b.profiles++
		d.scanGeckoProfile(scan, dir, data, b)
		if b.failure != "" {
			return true
		}
	}
	// An installation is a registered profile list or a profile holding a
	// database, and nothing else. A directory left behind by an uninstall — or by
	// some other installer — is reported as absent rather than as a browser that
	// could not be read, which would paint a permanent failure for a browser
	// nobody has.
	return found || registered
}

// geckoDeclaredProfiles reads the profile list the browser maintains.
//
// A profile may be declared at an absolute path, which is the one location class
// this detector does not fix itself: it is a string a config file handed over, so
// it is checked before it is touched rather than after. A path outside the
// account's own tree, or inside a directory the consent layer gates, is refused
// unread.
func (d *Detector) geckoDeclaredProfiles(scan *scanState, root string) (dirs []string, registered bool, reason string) {
	data, missing, reason := scan.readState(filepath.Join(root, "profiles.ini"), maxProfilesINIBytes)
	if reason != "" {
		return nil, false, reason
	}
	if missing {
		return nil, false, ""
	}
	parsed, ok := parseProfilesINI(data)
	if !ok {
		// This file is the membership list's outer boundary: a profile it declares
		// and this build cannot place is a profile full of add-ons that would go
		// unlisted, under a status claiming the list is complete.
		return nil, false, model.BrowserExtReasonParseError
	}
	for _, p := range parsed {
		path := filepath.FromSlash(p.path)
		if p.relative || !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		dirs = append(dirs, filepath.Clean(path))
	}
	// The file itself is the evidence of an installation: a browser that has
	// registered profiles is installed even if none of them has been opened.
	return dirs, true, ""
}

// geckoDiscoveredProfiles lists the directories that look like profiles, in both
// layouts the platforms use — directly under the root, and under a Profiles
// subdirectory.
//
// The listing is a union with the declared list rather than a replacement for it:
// a profile unregistered from the INI file still holds real extensions, and a
// missing one would be a membership gap under a status that claims completeness.
func (d *Detector) geckoDiscoveredProfiles(scan *scanState, root string) (dirs []string, reason string) {
	for _, base := range []string{root, filepath.Join(root, "Profiles")} {
		names, missing, reason := scan.listNames(base, maxProfileEntries)
		if reason != "" {
			return nil, reason
		}
		if missing {
			continue
		}
		for _, name := range names {
			candidate := filepath.Join(base, name)
			isDir, missing, reason := scan.statEntry(candidate)
			if reason != "" {
				return nil, reason
			}
			if missing || !isDir {
				// The root holds files as well: the INI files themselves, and
				// whatever else the browser keeps beside its profiles.
				continue
			}
			dirs = append(dirs, candidate)
		}
	}
	return dirs, ""
}

// iniProfile is one profile as the INI file declares it.
type iniProfile struct {
	path string
	// Relative to the data directory. The default, and the common case.
	relative bool
}

// parseProfilesINI reads the profile sections, reporting false when a section
// declares a profile this cannot place: no path, or a relative flag outside the
// two values the file uses. Hand-rolled because the file is a flat list of two
// interesting keys, which is not worth a dependency.
func parseProfilesINI(data []byte) ([]iniProfile, bool) {
	var profiles []iniProfile
	current := -1
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Install sections name each installation's default profile and
			// duplicate what the profile sections already say, so only the
			// profile sections are read.
			if strings.HasPrefix(strings.ToLower(line), "[profile") {
				profiles = append(profiles, iniProfile{relative: true})
				current = len(profiles) - 1
			} else {
				current = -1
			}
			continue
		}
		if current < 0 {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "path":
			profiles[current].path = strings.TrimSpace(value)
		case "isrelative":
			switch strings.TrimSpace(value) {
			case "0":
				profiles[current].relative = false
			case "1":
				profiles[current].relative = true
			default:
				return nil, false
			}
		}
	}
	for _, p := range profiles {
		if p.path == "" {
			return nil, false
		}
	}
	return profiles, true
}

// geckoAddon is one record in the add-on database. Every field is optional and
// nothing is gated on the document's schema version, which changes every release
// — but tolerance has a floor: a record whose identity or class cannot be
// recovered is a membership question, and those fail the browser.
type geckoAddon struct {
	ID      *string `json:"id"`
	Version string  `json:"version"`
	Type    *string `json:"type"`
	Active  *bool   `json:"active"`
	// The three ways an add-on can be off. They separate the user's own choice
	// from the browser's.
	UserDisabled *bool  `json:"userDisabled"`
	AppDisabled  *bool  `json:"appDisabled"`
	SoftDisabled *bool  `json:"softDisabled"`
	Location     string `json:"location"`
	SignedState  *int   `json:"signedState"`
	Visible      *bool  `json:"visible"`
	Hidden       *bool  `json:"hidden"`

	DefaultLocale struct {
		Name string `json:"name"`
	} `json:"defaultLocale"`

	UserPermissions struct {
		Permissions []string `json:"permissions"`
		Origins     []string `json:"origins"`
	} `json:"userPermissions"`

	InstallTelemetryInfo struct {
		Source string `json:"source"`
	} `json:"installTelemetryInfo"`
}

// scanGeckoProfile reads one profile's add-on database.
func (d *Detector) scanGeckoProfile(scan *scanState, dir string, data []byte, b *browserScan) {
	var db struct {
		// A pointer so an absent list is told apart from an empty one. A profile
		// with no add-ons still writes the key, so a document without it is one
		// this build cannot read — and reading it as zero add-ons would publish a
		// complete-looking empty list that retires everything stored for the
		// browser.
		Addons *[]json.RawMessage `json:"addons"`
	}
	if err := json.Unmarshal(data, &db); err != nil || db.Addons == nil {
		b.fail(model.BrowserExtReasonParseError)
		return
	}
	for _, raw := range *db.Addons {
		var a geckoAddon
		if err := json.Unmarshal(raw, &a); err != nil {
			// Unlike the other family, there is no map key to fall back on: the
			// identity lives inside the record, so a record that will not decode
			// is an extension whose identity cannot be recovered, and the list is
			// no longer known to be complete.
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		if a.ID == nil || *a.ID == "" {
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		id := *a.ID
		if len(id) > maxExtensionIDBytes {
			// An identity cannot be shortened to fit — a truncated identity is a
			// different extension — and dropping it under a status that claims a
			// complete list would retire the real one's stored row.
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		if a.Type == nil {
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		if geckoNonMemberTypes[*a.Type] {
			continue
		}
		if *a.Type != geckoTypeExtension {
			b.fail(model.BrowserExtReasonParseError)
			return
		}
		if (a.Hidden != nil && *a.Hidden) || (a.Visible != nil && !*a.Visible) {
			// A system add-on, or a duplicate the browser has shadowed.
			continue
		}
		if geckoBuiltinScopes[a.Location] {
			continue
		}

		occ, ok := d.geckoOccurrence(a, b)
		if !ok {
			continue
		}
		occ.sortKey = dir
		if !b.add(id, occ) {
			return
		}
	}
}

// geckoOccurrence turns one add-on record into one occurrence.
func (d *Detector) geckoOccurrence(a geckoAddon, b *browserScan) (occurrence, bool) {
	source := model.BrowserExtInstallUnknown
	if mapped, ok := geckoInstallSources[a.Location]; ok {
		source = mapped
	}
	if a.InstallTelemetryInfo.Source == geckoPolicySource {
		// An administrator install looks like an ordinary profile install
		// everywhere else in the record.
		source = model.BrowserExtInstallPolicy
	}

	state, disabledBy := geckoEnabledState(a)
	perms, permsCapped := capPermissionList(a.UserPermissions.Permissions)
	hosts, hostsCapped := capPermissionList(a.UserPermissions.Origins)
	if permsCapped || hostsCapped {
		b.degrade(model.BrowserExtReasonCapped)
	}
	return occurrence{
		enabled:    state,
		disabledBy: disabledBy,
		block: model.BrowserExtensionFinding{
			Name:         capBytes(a.DefaultLocale.Name, maxNameBytes),
			Version:      capBytes(a.Version, maxVersionBytes),
			EnabledState: state,
			// The store fields have no counterpart on this engine: there is no
			// listing state in the database to read.
			InstallSource:   source,
			Store:           geckoStore(a.SignedState),
			SignedState:     geckoSignedState(a.SignedState),
			Permissions:     perms,
			HostPermissions: hosts,
		},
	}, true
}

// geckoEnabledState derives whether the add-on runs, and who stopped it. A record
// that does not say whether it is active is reported as unknown rather than
// assumed off: an invented cause would be displayed as a fact.
func geckoEnabledState(a geckoAddon) (state, disabledBy string) {
	if a.Active == nil {
		return model.BrowserExtStateUnknown, ""
	}
	if *a.Active {
		return model.BrowserExtEnabled, ""
	}
	switch {
	case a.UserDisabled != nil && *a.UserDisabled:
		return model.BrowserExtDisabled, model.BrowserExtDisabledByUser
	case (a.AppDisabled != nil && *a.AppDisabled) || (a.SoftDisabled != nil && *a.SoftDisabled):
		return model.BrowserExtDisabled, model.BrowserExtDisabledByBrowser
	default:
		return model.BrowserExtDisabled, model.BrowserExtDisabledByUnknown
	}
}

// geckoSignedState maps the recorded state, and omits a value it does not
// recognise rather than inventing a label for it.
func geckoSignedState(signed *int) string {
	if signed == nil {
		return ""
	}
	return geckoSignedStates[*signed]
}

// geckoStore attributes the add-on to a store from its signature alone. The
// download URL would be the honest signal and is dropped unread, because it can
// embed a private address. The cost is recorded rather than hidden: an
// enterprise add-on that is self-hosted but vendor-signed attributes to the public
// store.
func geckoStore(signed *int) string {
	if signed == nil {
		return model.BrowserExtStoreUnknown
	}
	switch *signed {
	case 1, 2:
		return model.BrowserExtStoreAMO
	case 0:
		return model.BrowserExtStoreNone
	default:
		return model.BrowserExtStoreUnknown
	}
}
