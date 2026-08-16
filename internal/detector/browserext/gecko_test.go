package browserext

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// geckoAddonJSON writes one profile's add-on database.
func geckoAddonJSON(t *testing.T, dir, addons string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "extensions.json"), `{"schemaVersion": 37, "addons": [`+addons+`]}`)
}

// firefoxFinding runs one Firefox profile and returns its single finding plus the
// browser's coverage entry.
func firefoxFinding(t *testing.T, addon string) (model.BrowserExtensionFinding, model.BrowserCoverage) {
	t.Helper()
	home := tempHome(t)
	root := firefoxRoot(home)
	writeFile(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=abcd1234.default-release\n")
	geckoAddonJSON(t, filepath.Join(root, "abcd1234.default-release"), addon)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserFirefox)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want exactly one", len(got))
	}
	return got[0], coverageFor(t, info, browserFirefox)
}

// TestGecko_ProfileEnumeration covers both ways a profile is found. The listing is
// a union with the declared list rather than a replacement: a profile
// unregistered from the declaration still holds real extensions, and missing it
// would be a membership gap under a status that claims completeness.
func TestGecko_ProfileEnumeration(t *testing.T) {
	home := tempHome(t)
	root := firefoxRoot(home)
	orphan := filepath.Join(root, "zzzz9999.orphan")
	declared := filepath.Join(root, "abcd1234.default-release")
	absolute := filepath.Join(home, "mozilla-profiles", "work")

	writeFile(t, filepath.Join(root, "profiles.ini"), strings.Join([]string{
		"[Profile0]", "IsRelative=1", "Path=abcd1234.default-release",
		"[Profile1]", "IsRelative=0", "Path=" + filepath.ToSlash(absolute),
		// An installation section repeats what the profile sections say and is
		// not read as a profile of its own.
		"[Install4F96D1932A9F858E]", "Default=abcd1234.default-release", "Locked=1",
		"",
	}, "\n"))
	geckoAddonJSON(t, declared, `{"id": "declared@example-org", "type": "extension", "active": true}`)
	geckoAddonJSON(t, absolute, `{"id": "relocated@example-org", "type": "extension", "active": true}`)
	geckoAddonJSON(t, orphan, `{"id": "orphan@example-org", "type": "extension", "active": true}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)

	got := map[string]bool{}
	for _, f := range findingsFor(info, browserFirefox) {
		got[f.ExtensionID] = true
	}
	for _, want := range []string{"declared@example-org", "relocated@example-org", "orphan@example-org"} {
		if !got[want] {
			t.Errorf("no finding for %s", want)
		}
	}
	if c := coverageFor(t, info, browserFirefox); c.ProfileCount != 3 {
		t.Errorf("profile_count = %d, want 3", c.ProfileCount)
	}
}

// TestGecko_TypeVocabularyInBothPolarities is the rule that trades a visible gap
// for a silent one. A recognised non-member is skipped and costs nothing; a class
// this build does not know may be a real extension, so it fails the browser rather
// than being dropped from a list that reads as complete or reported as something
// it is not.
func TestGecko_TypeVocabularyInBothPolarities(t *testing.T) {
	tests := []struct {
		name   string
		addon  string
		status string
		reason string
	}{
		{
			name:   "an extension is a member",
			addon:  `{"id": "ext@example-org", "type": "extension", "active": true}`,
			status: model.BrowserCoverageScanned,
		},
		{
			name:   "a theme is a recognised non-member",
			addon:  `{"id": "theme@example-org", "type": "theme", "active": true}`,
			status: model.BrowserCoverageScanned,
		},
		{
			name:   "a language pack is a recognised non-member",
			addon:  `{"id": "langpack-de@example-org", "type": "locale", "active": true}`,
			status: model.BrowserCoverageScanned,
		},
		{
			name:   "a dictionary is a recognised non-member",
			addon:  `{"id": "dict-de@example-org", "type": "dictionary", "active": true}`,
			status: model.BrowserCoverageScanned,
		},
		{
			name:   "a site permission is a recognised non-member",
			addon:  `{"id": "sitepermission@example-org", "type": "sitepermission", "active": true}`,
			status: model.BrowserCoverageScanned,
		},
		{
			name:   "a class this build does not know fails the browser",
			addon:  `{"id": "future@example-org", "type": "recipe", "active": true}`,
			status: model.BrowserCoverageFailed,
			reason: model.BrowserExtReasonParseError,
		},
		{
			name:   "a record with no class fails the browser",
			addon:  `{"id": "classless@example-org", "active": true}`,
			status: model.BrowserCoverageFailed,
			reason: model.BrowserExtReasonParseError,
		},
		{
			// No map key to fall back on here: the identity lives inside the
			// record, so a record that will not decode is an extension whose
			// identity cannot be recovered.
			name:   "a record that will not decode fails the browser",
			addon:  `"not a record"`,
			status: model.BrowserCoverageFailed,
			reason: model.BrowserExtReasonParseError,
		},
		{
			name:   "a record with no identity fails the browser",
			addon:  `{"type": "extension", "active": true}`,
			status: model.BrowserCoverageFailed,
			reason: model.BrowserExtReasonParseError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			root := firefoxRoot(home)
			writeFile(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=p1\n")
			geckoAddonJSON(t, filepath.Join(root, "p1"), tc.addon)

			info := scanHome(t, home)
			assertPayloadInvariants(t, info)
			got := coverageFor(t, info, browserFirefox)
			if got.Status != tc.status || got.ReasonCode != tc.reason {
				t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode, tc.status, tc.reason)
			}
			if tc.status == model.BrowserCoverageFailed && len(findingsFor(info, browserFirefox)) != 0 {
				t.Error("a failed browser shipped findings")
			}
		})
	}
}

// TestGecko_InstallSourceAndExclusions maps the recorded scopes. The sideload
// scopes are alive on the extended-support channel, which is exactly the
// enterprise population, so they are reported; the builtin scopes are the
// browser's own parts and are not.
func TestGecko_InstallSourceAndExclusions(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		want     string
		excluded bool
	}{
		{name: "an ordinary profile install", record: `"location": "app-profile"`, want: model.BrowserExtInstallUser},
		{
			name:   "an administrator install, which looks like any other",
			record: `"location": "app-profile", "installTelemetryInfo": {"source": "enterprise-policy"}`,
			want:   model.BrowserExtInstallPolicy,
		},
		{name: "a registry sideload", record: `"location": "winreg-app-user"`, want: model.BrowserExtInstallRegistry},
		{name: "a filesystem sideload", record: `"location": "app-system-share"`, want: model.BrowserExtInstallSideload},
		{name: "a temporary load", record: `"location": "app-temporary"`, want: model.BrowserExtInstallUnpacked},
		{name: "a scope this build does not know", record: `"location": "app-future"`, want: model.BrowserExtInstallUnknown},
		{name: "a browser component", record: `"location": "app-builtin"`, excluded: true},
		{name: "a system add-on", record: `"location": "app-system-addons"`, excluded: true},
		{name: "a hidden add-on", record: `"location": "app-profile", "hidden": true`, excluded: true},
		{name: "a shadowed duplicate", record: `"location": "app-profile", "visible": false`, excluded: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addon := `{"id": "ext@example-org", "type": "extension", "active": true, ` + tc.record + `}`
			if tc.excluded {
				home := tempHome(t)
				root := firefoxRoot(home)
				writeFile(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=p1\n")
				geckoAddonJSON(t, filepath.Join(root, "p1"), addon)

				info := scanHome(t, home)
				assertPayloadInvariants(t, info)
				if got := findingsFor(info, browserFirefox); len(got) != 0 {
					t.Errorf("findings = %d, want none", len(got))
				}
				if c := coverageFor(t, info, browserFirefox); c.Status != model.BrowserCoverageScanned {
					t.Errorf("status = %q/%q, want the browser scanned: an exclusion is not damage", c.Status, c.ReasonCode)
				}
				return
			}
			got, _ := firefoxFinding(t, addon)
			if got.InstallSource != tc.want {
				t.Errorf("install_source = %q, want %q", got.InstallSource, tc.want)
			}
		})
	}
}

// TestGecko_SigningStateAndStore covers the engine-specific field pair. An
// unsigned add-on that is enabled is the headline signal here, and the signature is
// also all there is to attribute a store by: the download address would be the
// honest signal and is dropped unread because it can embed a private one.
func TestGecko_SigningStateAndStore(t *testing.T) {
	tests := []struct {
		name   string
		record string
		signed string
		store  string
	}{
		{name: "unsigned", record: `"signedState": 0`, signed: model.BrowserExtSignedMissing, store: model.BrowserExtStoreNone},
		{name: "signed", record: `"signedState": 2`, signed: model.BrowserExtSignedSigned, store: model.BrowserExtStoreAMO},
		{name: "preliminarily signed", record: `"signedState": 1`, signed: model.BrowserExtSignedPreliminary, store: model.BrowserExtStoreAMO},
		{name: "a broken signature", record: `"signedState": -2`, signed: model.BrowserExtSignedBroken, store: model.BrowserExtStoreUnknown},
		{name: "an unverifiable chain", record: `"signedState": -1`, signed: model.BrowserExtSignedUnknownChain, store: model.BrowserExtStoreUnknown},
		{name: "a browser-privileged add-on", record: `"signedState": 4`, signed: model.BrowserExtSignedPrivileged, store: model.BrowserExtStoreUnknown},
		{name: "no signature record at all", record: `"version": "1.0"`, signed: "", store: model.BrowserExtStoreUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := firefoxFinding(t,
				`{"id": "ext@example-org", "type": "extension", "active": true, "location": "app-profile", `+tc.record+`}`)
			if got.SignedState != tc.signed {
				t.Errorf("signed_state = %q, want %q", got.SignedState, tc.signed)
			}
			if got.Store != tc.store {
				t.Errorf("store = %q, want %q", got.Store, tc.store)
			}
			// The store fields have no counterpart on this engine, and a reader
			// rejects a payload that carries them here.
			if got.StoreListing != "" || got.StoreViolation != "" {
				t.Errorf("store fields = %q/%q, want neither on this engine", got.StoreListing, got.StoreViolation)
			}
		})
	}
}

// TestGecko_EnabledState covers who turned the add-on off. A record that does not
// say whether it is active reports unknown rather than an invented cause.
func TestGecko_EnabledState(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		state      string
		disabledBy string
	}{
		{name: "active", record: `"active": true`, state: model.BrowserExtEnabled},
		{
			name:       "the user's own choice",
			record:     `"active": false, "userDisabled": true`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUser,
		},
		{
			name:       "the browser's decision",
			record:     `"active": false, "appDisabled": true`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByBrowser,
		},
		{
			name:       "off with no reason recorded",
			record:     `"active": false`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUnknown,
		},
		{name: "no state recorded", record: `"version": "1.0"`, state: model.BrowserExtStateUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := firefoxFinding(t,
				`{"id": "ext@example-org", "type": "extension", "location": "app-profile", `+tc.record+`}`)
			if got.EnabledState != tc.state || got.DisabledBy != tc.disabledBy {
				t.Errorf("state/cause = %q/%q, want %q/%q", got.EnabledState, got.DisabledBy, tc.state, tc.disabledBy)
			}
		})
	}
}

// TestGecko_NameAndPermissions covers the metadata this engine records in one
// place, so no second file is opened for it.
func TestGecko_NameAndPermissions(t *testing.T) {
	got, _ := firefoxFinding(t, `{
		"id": "ext@example-org", "type": "extension", "active": true, "location": "app-profile",
		"version": "3.2.1",
		"defaultLocale": {"name": "Example Content Filter", "description": "unread"},
		"userPermissions": {"permissions": ["webRequest", "storage"], "origins": ["<all_urls>"]}
	}`)

	if got.Name != "Example Content Filter" || got.Version != "3.2.1" {
		t.Errorf("name/version = %q/%q, want the recorded values", got.Name, got.Version)
	}
	if strings.Join(got.Permissions, ",") != "storage,webRequest" {
		t.Errorf("permissions = %v, want them sorted", got.Permissions)
	}
	if strings.Join(got.HostPermissions, ",") != "<all_urls>" {
		t.Errorf("host_permissions = %v", got.HostPermissions)
	}
}

// TestGecko_OverlongIdentityFailsTheBrowser pins the one string that is never
// shortened. A truncated identity is a different extension, and dropping it under
// a status that claims a complete list would retire the real one's stored row.
func TestGecko_OverlongIdentityFailsTheBrowser(t *testing.T) {
	home := tempHome(t)
	root := firefoxRoot(home)
	writeFile(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=p1\n")
	long := strings.Repeat("x", maxExtensionIDBytes+1) + "@example-org"
	geckoAddonJSON(t, filepath.Join(root, "p1"), `{"id": "`+long+`", "type": "extension", "active": true}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := coverageFor(t, info, browserFirefox)
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonParseError {
		t.Errorf("status = %q/%q, want failed rather than partial", got.Status, got.ReasonCode)
	}
	if len(findingsFor(info, browserFirefox)) != 0 {
		t.Error("a failed browser shipped findings")
	}
}

// TestGecko_TwoDataDirectoriesDeduplicate covers the layout where a native install
// and a packaged one both exist. Their union is the answer, and one extension in
// both is one finding.
func TestGecko_TwoDataDirectoriesDeduplicate(t *testing.T) {
	home := tempHome(t)
	native := firefoxRoot(home)
	snap := filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox")

	for _, root := range []string{native, snap} {
		writeFile(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=p1\n")
	}
	geckoAddonJSON(t, filepath.Join(native, "p1"),
		`{"id": "shared@example-org", "type": "extension", "active": false, "userDisabled": true, "location": "app-profile", "version": "1.0"}`)
	geckoAddonJSON(t, filepath.Join(snap, "p1"),
		`{"id": "shared@example-org", "type": "extension", "active": true, "location": "app-profile", "version": "2.0"}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserFirefox)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want one per extension however many directories hold it", len(got))
	}
	if got[0].EnabledState != model.BrowserExtEnabled {
		t.Errorf("enabled_state = %q, want enabled: it runs in one of the two", got[0].EnabledState)
	}
	if c := coverageFor(t, info, browserFirefox); c.ProfileCount != 2 {
		t.Errorf("profile_count = %d, want both directories' profiles counted together", c.ProfileCount)
	}
}

// TestGecko_MissingProfileListIsNotAnInstallation keeps a leftover directory from
// reading as a broken browser, which would paint a permanent red row for something
// nobody installed. An installation is a registered profile list or a profile
// holding a database; the residue of an uninstall is neither.
func TestGecko_MissingProfileListIsNotAnInstallation(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home string)
	}{
		{
			name:  "an empty directory",
			setup: func(t *testing.T, home string) { mkdir(t, firefoxRoot(home)) },
		},
		{
			name: "a directory holding leftovers but no profile",
			setup: func(t *testing.T, home string) {
				mkdir(t, filepath.Join(firefoxRoot(home), "Crash Reports"))
				writeFile(t, filepath.Join(firefoxRoot(home), "installs.ini"), "\n")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			tc.setup(t, home)

			info := scanHome(t, home)
			assertPayloadInvariants(t, info)
			got := coverageFor(t, info, browserFirefox)
			if got.Status != model.BrowserCoverageNotPresent || got.ReasonCode != "" {
				t.Errorf("status = %q/%q, want not present with no reason", got.Status, got.ReasonCode)
			}
		})
	}
}

// TestGecko_UnreadableMembershipDocumentFailsTheBrowser covers the floor under
// tolerant parsing. Individual fields may be missing, but the two documents that
// define the membership list — which profiles exist, and which add-ons each holds
// — have to be understood whole. Each case below would otherwise produce a
// complete-looking empty list, which is the one answer that retires stored rows.
func TestGecko_UnreadableMembershipDocumentFailsTheBrowser(t *testing.T) {
	tests := []struct {
		name  string
		ini   string
		addon string
	}{
		{
			name:  "a database that will not decode",
			ini:   "[Profile0]\nIsRelative=1\nPath=p1\n",
			addon: `{"addons": [`,
		},
		{
			name: "a database carrying no add-on list at all",
			ini:  "[Profile0]\nIsRelative=1\nPath=p1\n",
			// Not the same as an empty list: a profile with no add-ons still
			// writes the key, so its absence is a document this cannot read.
			addon: `{"schemaVersion": 37}`,
		},
		{
			name:  "a declared profile with no path",
			ini:   "[Profile0]\nIsRelative=1\n",
			addon: `{"addons": []}`,
		},
		{
			name:  "a declared profile whose path is neither relative nor absolute",
			ini:   "[Profile0]\nIsRelative=maybe\nPath=p1\n",
			addon: `{"addons": []}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			root := firefoxRoot(home)
			writeFile(t, filepath.Join(root, "profiles.ini"), tc.ini)
			writeFile(t, filepath.Join(root, "p1", "extensions.json"), tc.addon)

			info := scanHome(t, home)
			assertPayloadInvariants(t, info)
			got := coverageFor(t, info, browserFirefox)
			if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonParseError {
				t.Errorf("status = %q/%q, want failed and a parse error", got.Status, got.ReasonCode)
			}
		})
	}
}

// TestGecko_ProfileOutsideTheHomeIsRefusedUnread covers the one path class this
// detector does not build itself. A declared profile is a string from a config
// file, so a location outside the account's own tree is refused before it is
// touched — a stat into a network volume is itself the call that blocks. Refused
// and absent are not interchangeable here: the browser fails rather than
// publishing a list that would read as complete.
func TestGecko_ProfileOutsideTheHomeIsRefusedUnread(t *testing.T) {
	home := tempHome(t)
	root := firefoxRoot(home)
	// Nothing exists at this path. A resolver that walked to it before deciding
	// would report it missing and carry on.
	outside := filepath.Join(t.TempDir(), "elsewhere", "work")
	writeFile(t, filepath.Join(root, "profiles.ini"), strings.Join([]string{
		"[Profile0]", "IsRelative=0", "Path=" + filepath.ToSlash(outside), "",
	}, "\n"))

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := coverageFor(t, info, browserFirefox)
	if got.Status != model.BrowserCoverageFailed {
		t.Errorf("status = %q/%q, want the browser failed rather than reported empty", got.Status, got.ReasonCode)
	}
	if len(findingsFor(info, browserFirefox)) != 0 {
		t.Error("a failed browser shipped findings")
	}
}
