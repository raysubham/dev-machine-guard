package browserext

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Extension ids of the shape this family generates: thirty-two characters from a
// through p.
const (
	idA = "abcdefghijklmnopabcdefghijklmnop"
	idB = "bcdefghijklmnopabcdefghijklmnopa"
	idC = "cdefghijklmnopabcdefghijklmnopab"
)

// manySettings builds n extension records, for the tests that push a bound. The
// counter is spelled in the sixteen letters this family's ids are made of, so
// every one of them passes the shape gate.
func manySettings(n int) string {
	const letters = "abcdefghijklmnop"
	entries := make([]string, 0, n)
	for i := range n {
		var spelled strings.Builder
		for _, digit := range fmt.Sprintf("%04d", i) {
			spelled.WriteByte(letters[digit-'0'])
		}
		id := strings.Repeat("a", 28) + spelled.String()
		entries = append(entries, `"`+id+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)
	}
	return strings.Join(entries, ",")
}

// chromeFinding runs one Chrome profile and returns its single finding plus the
// browser's coverage entry, which is what most of the parsing rules are stated in
// terms of.
func chromeFinding(t *testing.T, settings string) (model.BrowserExtensionFinding, model.BrowserCoverage) {
	t.Helper()
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default", settings)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want exactly one", len(got))
	}
	return got[0], coverageFor(t, info, browserChrome)
}

// TestChromium_PrefsResidenceAndMerge pins where the extension map is read from.
// It lives in the integrity-tracked file on every platform — the belief that Linux
// keeps it in the plain one is wrong, and reading the plain file first would report
// a stale record over the live one.
func TestChromium_PrefsResidenceAndMerge(t *testing.T) {
	home := tempHome(t)
	root := chromeRoot(home)
	localState(t, root, "Default")
	securePrefs(t, root, "Default", `"`+idA+`": {
		"location": 1, "active_permissions": {}, "manifest": {"name": "From Secure", "version": "1.0"}
	}`)
	writeFile(t, filepath.Join(root, "Default", "Preferences"), `{"extensions": {"settings": {
		"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "From Plain", "version": "9.9"}},
		"`+idB+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Only In Plain", "version": "2.0"}}
	}}}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserChrome)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want the union of both files", len(got))
	}
	byID := map[string]model.BrowserExtensionFinding{}
	for _, f := range got {
		byID[f.ExtensionID] = f
	}
	if name := byID[idA].Name; name != "From Secure" {
		t.Errorf("name = %q, want the integrity-tracked file to win", name)
	}
	if name := byID[idB].Name; name != "Only In Plain" {
		t.Errorf("name = %q, want the plain file to fill an id the other lacks", name)
	}
	// Both records are complete, so nothing here is an attribute this scan failed
	// to recover and the browser has no reason to report degraded.
	if got := coverageFor(t, info, browserChrome); got.Status != model.BrowserCoverageScanned {
		t.Errorf("status = %q/%q, want scanned", got.Status, got.ReasonCode)
	}
}

// TestChromium_EnabledState covers every shape the disable record takes in the
// wild, and what each one says about who turned the extension off. Enabled is the
// empty set — not a flag, and not the record's absence.
func TestChromium_EnabledState(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		state      string
		disabledBy string
	}{
		{
			name:   "no disable record is enabled",
			record: `"location": 1`,
			state:  model.BrowserExtEnabled,
		},
		{
			name:   "empty list is enabled",
			record: `"location": 1, "disable_reasons": []`,
			state:  model.BrowserExtEnabled,
		},
		{
			name:       "the user's own action",
			record:     `"location": 1, "disable_reasons": [1]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUser,
		},
		{
			// The browser's own decision, which is where a store takedown lands.
			name:       "a reason of the browser's own",
			record:     `"location": 1, "disable_reasons": [512]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByBrowser,
		},
		{
			// The bit an administrator reaches for to ban an extension outright,
			// as measured against a live blocklist.
			name:       "an administrator's policy blocking it outright",
			record:     `"location": 1, "disable_reasons": [65536]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByPolicy,
		},
		{
			name:       "an administrator's policy holding an update back",
			record:     `"location": 1, "disable_reasons": [16384]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByPolicy,
		},
		{
			// An externally installed extension awaiting the user's approval. No
			// administrator is involved, so naming one would be wrong.
			name:       "an external installation awaiting approval",
			record:     `"location": 1, "disable_reasons": [8192]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByBrowser,
		},
		{
			// Family supervision, likewise not an administrator.
			name:       "a custodian's approval outstanding",
			record:     `"location": 1, "disable_reasons": [32768]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByBrowser,
		},
		{
			// Out of range of the enumeration entirely, which is what one browser
			// in the family writes. Naming an actor for it would be invention.
			name:       "a value the enumeration does not carry",
			record:     `"location": 1, "disable_reasons": [134217728]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUnknown,
		},
		{
			// A reason kept only for profiles old enough to still hold it. Still
			// recognised, so it must not turn the whole set unknown.
			name:       "a retired reason alongside the user's action",
			record:     `"location": 1, "disable_reasons": [2097152, 1]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUser,
		},
		{
			// The user's action wins the cause when a set carries several.
			name:       "the user's action alongside another reason",
			record:     `"location": 1, "disable_reasons": [1, 512]`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUser,
		},
		{
			name:       "the older combined bitmask",
			record:     `"location": 1, "disable_reasons": 513`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUser,
		},
		{
			name:   "the bitmask reading zero is enabled",
			record: `"location": 1, "disable_reasons": 0`,
			state:  model.BrowserExtEnabled,
		},
		{
			name:   "the pre-list flag, read only when nothing else says",
			record: `"location": 1, "state": 1`,
			state:  model.BrowserExtEnabled,
		},
		{
			name:       "the pre-list flag saying disabled",
			record:     `"location": 1, "state": 0`,
			state:      model.BrowserExtDisabled,
			disabledBy: model.BrowserExtDisabledByUnknown,
		},
		{
			// Present and unreadable: enabled and disabled are indistinguishable,
			// and saying either would be a guess displayed as a fact.
			name:   "an unreadable disable record",
			record: `"location": 1, "disable_reasons": "wat"`,
			state:  model.BrowserExtStateUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := chromeFinding(t, `"`+idA+`": {`+tc.record+
				`, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)
			if got.EnabledState != tc.state {
				t.Errorf("enabled_state = %q, want %q", got.EnabledState, tc.state)
			}
			if got.DisabledBy != tc.disabledBy {
				t.Errorf("disabled_by = %q, want %q", got.DisabledBy, tc.disabledBy)
			}
		})
	}
}

// TestChromium_InstallSource maps every recorded location. The values the browser
// uses for its own components are the only ones that produce no row at all.
func TestChromium_InstallSource(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{name: "an ordinary install", location: "1", want: model.BrowserExtInstallUser},
		{name: "a sideload through external preferences", location: "2", want: model.BrowserExtInstallSideload},
		{name: "a downloaded sideload", location: "6", want: model.BrowserExtInstallSideload},
		{name: "a registry sideload", location: "3", want: model.BrowserExtInstallRegistry},
		{name: "developer mode", location: "4", want: model.BrowserExtInstallUnpacked},
		{name: "a command-line load", location: "8", want: model.BrowserExtInstallUnpacked},
		{name: "an administrator install", location: "7", want: model.BrowserExtInstallPolicy},
		{name: "an administrator install, other form", location: "9", want: model.BrowserExtInstallPolicy},
		{name: "a value this build does not know", location: "42", want: model.BrowserExtInstallUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := chromeFinding(t, `"`+idA+`": {"location": `+tc.location+
				`, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)
			if got.InstallSource != tc.want {
				t.Errorf("install_source = %q, want %q", got.InstallSource, tc.want)
			}
		})
	}
}

// TestChromium_ExcludedAndNonMemberEntries covers everything that is in the
// preference map and not an installed extension. None of them may degrade the
// browser: they are classification, not damage — and a bookkeeping stub that
// degraded it would do so on every scan for ever.
func TestChromium_ExcludedAndNonMemberEntries(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		record  string
		reasons string
	}{
		{
			name:   "the browser's own component",
			id:     idA,
			record: `"location": 5, "manifest": {"name": "Component", "version": "1.0"}`,
		},
		{
			name:   "the browser's own external component",
			id:     idA,
			record: `"location": 10, "manifest": {"name": "Component", "version": "1.0"}`,
		},
		{
			name:   "a theme",
			id:     idA,
			record: `"location": 1, "manifest": {"name": "Dark", "version": "1.0", "theme": {"colors": {}}}`,
		},
		{
			name:   "a legacy packaged app",
			id:     idA,
			record: `"location": 1, "manifest": {"name": "Notes", "version": "1.0", "app": {"launch": {}}}`,
		},
		{
			// Bookkeeping residue the browser's own loader cannot load. Reporting
			// it would invent an extension and, having no manifest, would pin the
			// browser to a degraded status permanently.
			name:   "an update-ping stub",
			id:     idA,
			record: `"active_bit": true, "allowlist": {"state": 1}, "lastpingday": "13300000000000000"`,
		},
		{
			name:   "a key that cannot be an extension id",
			id:     "not-an-extension-id",
			record: `"location": 1, "manifest": {"name": "Example", "version": "1.0"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			localState(t, chromeRoot(home), "Default")
			securePrefs(t, chromeRoot(home), "Default", `"`+tc.id+`": {`+tc.record+`}`)

			info := scanHome(t, home)
			assertPayloadInvariants(t, info)
			if got := findingsFor(info, browserChrome); len(got) != 0 {
				t.Errorf("findings = %d (%q), want none", len(got), got[0].Name)
			}
			got := coverageFor(t, info, browserChrome)
			if got.Status != model.BrowserCoverageScanned || got.ReasonCode != "" {
				t.Errorf("status = %q/%q, want the browser scanned and undegraded", got.Status, got.ReasonCode)
			}
		})
	}
}

// TestChromium_CorruptRecordKeepsItsIdentity is the difference between the two
// families: here the map key is the identity, so a record whose value cannot be
// read still reports the extension. Dropping it under a status that claims a
// complete list would retire that extension's stored row.
func TestChromium_CorruptRecordKeepsItsIdentity(t *testing.T) {
	got, coverage := chromeFinding(t, `"`+idA+`": "this is not a record"`)

	if got.ExtensionID != idA {
		t.Errorf("extension_id = %q, want the map key", got.ExtensionID)
	}
	if got.Name != "" || got.Version != "" {
		t.Errorf("name/version = %q/%q, want both empty on a record that could not be read", got.Name, got.Version)
	}
	if got.EnabledState != model.BrowserExtStateUnknown {
		t.Errorf("enabled_state = %q, want unknown", got.EnabledState)
	}
	// A reader requires both store fields on this family, and "cannot tell" is a
	// value rather than an omission.
	if got.StoreListing != model.BrowserExtStoreListingUnknown || got.StoreViolation != model.BrowserExtStoreViolationUnknown {
		t.Errorf("store fields = %q/%q, want both unknown", got.StoreListing, got.StoreViolation)
	}
	if coverage.Status != model.BrowserCoveragePartial || coverage.ReasonCode != model.BrowserExtReasonManifestUnavailable {
		t.Errorf("status = %q/%q, want partial and the missing metadata named",
			coverage.Status, coverage.ReasonCode)
	}
}

// TestChromium_StoreDisposition covers the pair this feature exists for: an
// extension the store has pulled while the machine still runs it. Absent, the
// answer is unknown and never listed — inferring that the store still carries it
// would turn a missing answer into a reassuring one.
func TestChromium_StoreDisposition(t *testing.T) {
	tests := []struct {
		name      string
		record    string
		listing   string
		violation string
		state     string
	}{
		{
			name:      "listed and clean",
			record:    `"cws-info": {"is-live": true, "violation-type": 0}`,
			listing:   model.BrowserExtStoreListingListed,
			violation: model.BrowserExtStoreViolationNone,
			state:     model.BrowserExtEnabled,
		},
		{
			name:      "pulled for a policy violation",
			record:    `"disable_reasons": [512], "cws-info": {"is-live": false, "violation-type": 2}`,
			listing:   model.BrowserExtStoreListingDelisted,
			violation: model.BrowserExtStoreViolationFlagged,
			state:     model.BrowserExtDisabled,
		},
		{
			// The worst case, and the only field that finds it: no longer in the
			// store, still running, still holding its permissions.
			name:      "delisted and still enabled",
			record:    `"cws-info": {"is-live": false, "violation-type": 0}`,
			listing:   model.BrowserExtStoreListingDelisted,
			violation: model.BrowserExtStoreViolationNone,
			state:     model.BrowserExtEnabled,
		},
		{
			name:      "no store record at all",
			record:    `"location": 1`,
			listing:   model.BrowserExtStoreListingUnknown,
			violation: model.BrowserExtStoreViolationUnknown,
			state:     model.BrowserExtEnabled,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := chromeFinding(t, `"`+idA+`": {"location": 1, "active_permissions": {}, `+tc.record+
				`, "manifest": {"name": "Example", "version": "1.0"}}`)
			if got.StoreListing != tc.listing || got.StoreViolation != tc.violation {
				t.Errorf("store fields = %q/%q, want %q/%q",
					got.StoreListing, got.StoreViolation, tc.listing, tc.violation)
			}
			if got.EnabledState != tc.state {
				t.Errorf("enabled_state = %q, want %q: the listing is independent of it", got.EnabledState, tc.state)
			}
		})
	}
}

// TestChromium_StoreAttribution reduces the update server to a label. The URL
// itself never ships: a self-hosted one names internal infrastructure.
func TestChromium_StoreAttribution(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{
			name:   "the public store's update server",
			record: `"manifest": {"name": "Example", "update_url": "` + chromeWebStoreUpdateURL + `"}`,
			want:   model.BrowserExtStoreChromeWebStore,
		},
		{
			name:   "the other vendor's store",
			record: `"manifest": {"name": "Example", "update_url": "` + edgeAddonsUpdateURL + `?prod=edgechromium"}`,
			want:   model.BrowserExtStoreEdgeAddons,
		},
		{
			name:   "somebody's own server",
			record: `"manifest": {"name": "Example", "update_url": "https://updates.example.internal/crx"}`,
			want:   model.BrowserExtStoreSelfHosted,
		},
		{
			name:   "no update server, but the store flag",
			record: `"from_webstore": true, "manifest": {"name": "Example"}`,
			want:   model.BrowserExtStoreChromeWebStore,
		},
		{
			name:   "nothing to attribute it by",
			record: `"manifest": {"name": "Example"}`,
			want:   model.BrowserExtStoreUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := chromeFinding(t, `"`+idA+`": {"location": 1, "active_permissions": {}, `+tc.record+`}`)
			if got.Store != tc.want {
				t.Errorf("store = %q, want %q", got.Store, tc.want)
			}
			if strings.Contains(got.Store, "://") {
				t.Errorf("store = %q, want a label rather than a URL", got.Store)
			}
		})
	}
}

// TestChromium_Permissions covers the one record the wire is built from. The
// browser keeps three, and only the active set says what the extension holds
// now: the granted set is everything it has ever held and never had globally
// revoked, and the runtime store is bookkeeping behind the site-access control.
func TestChromium_Permissions(t *testing.T) {
	t.Run("the active set is the answer and the other two are not", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {
				"api": ["storage", "tabs"],
				"explicit_host": ["https://example.internal/*"]
			},
			"granted_permissions": {
				"api": ["storage", "tabs", "webview"],
				"explicit_host": ["https://example.internal/*", "https://dropped.internal/*"]
			},
			"runtime_granted_permissions": {
				"api": ["cookies"],
				"scriptable_host": ["https://other.internal/*"]
			}
		}`)

		wantPerms := []string{"storage", "tabs"}
		if strings.Join(got.Permissions, ",") != strings.Join(wantPerms, ",") {
			t.Errorf("permissions = %v, want %v: a permission the browser stopped honouring is not one the machine holds",
				got.Permissions, wantPerms)
		}
		wantHosts := []string{"https://example.internal/*"}
		if strings.Join(got.HostPermissions, ",") != strings.Join(wantHosts, ",") {
			t.Errorf("host_permissions = %v, want %v", got.HostPermissions, wantHosts)
		}
		// Nothing failed to read. The other two records were present and
		// deliberately not used, which is not a degraded attribute.
		if coverage.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q/%q, want scanned", coverage.Status, coverage.ReasonCode)
		}
	})

	// The same divergence arriving the other way: an optional permission the
	// extension asked for at runtime and later handed back through the
	// permissions API. The browser removes it from the active set and leaves it
	// in the granted one for good.
	t.Run("an optional permission handed back is not reported", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {"api": ["storage"]},
			"granted_permissions": {"api": ["storage", "bookmarks"]},
			"runtime_granted_permissions": {"api": ["bookmarks"]}
		}`)

		if slices.Contains(got.Permissions, "bookmarks") {
			t.Errorf("permissions = %v, want no bookmarks: it is a record of a grant, not a grant",
				got.Permissions)
		}
	})

	// No fallback. A record whose active set could not be read reports nothing
	// rather than reporting history, because an empty list is the positive claim
	// that the extension holds nothing and this is not that claim.
	t.Run("no active set means no permissions and a partial browser", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"granted_permissions": {
				"api": ["storage", "tabs"],
				"explicit_host": ["<all_urls>"],
				"scriptable_host": ["<all_urls>"]
			},
			"runtime_granted_permissions": {"api": ["cookies"]}
		}`)

		if len(got.Permissions) != 0 || len(got.HostPermissions) != 0 {
			t.Errorf("permissions/host_permissions = %v/%v, want neither: history is not present access",
				got.Permissions, got.HostPermissions)
		}
		if got.ScriptableHostPermissions != nil {
			t.Errorf("scriptable_host_permissions = %v, want absent: an empty list would say it injects nowhere",
				*got.ScriptableHostPermissions)
		}
		// The extension is still reported, so membership stays complete and only
		// the attribute is missing.
		if coverage.Status != model.BrowserCoveragePartial ||
			coverage.ReasonCode != model.BrowserExtReasonManifestUnavailable {
			t.Errorf("status = %q/%q, want partial and manifest_unavailable",
				coverage.Status, coverage.ReasonCode)
		}
	})
}

// TestChromium_WithheldHostsAreNotReported covers the site-access control. The
// browser does not rewrite the active set when the user restricts a site: it sets
// a flag, keeps the request as it was, and records the granted origins in the
// runtime store, so the hosts it honours have to be read from both records.
func TestChromium_WithheldHostsAreNotReported(t *testing.T) {
	const broadRequest = `"api": ["storage", "tabs"], "explicit_host": ["*://*/*", "<all_urls>", "https://kept.internal/*"]`

	for _, tt := range []struct {
		name    string
		active  string
		entry   string
		want    []string
		wantAPI []string
	}{
		{
			// Site access restricted to nothing: the extension holds no host at
			// all, however much the active record still requests.
			name:    "withheld with nothing granted back reaches no host",
			entry:   `"withholding_permissions": true, "runtime_granted_permissions": {"api": ["cookies"]}`,
			want:    nil,
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// Site access restricted to one site. The granted origin lives in the
			// runtime store and is never copied into the active set, so this is
			// the one place it can be read from.
			name: "withheld with one site granted back reaches that site",
			entry: `"withholding_permissions": true, "runtime_granted_permissions": {
				"api": ["cookies"], "explicit_host": ["https://kept.internal/*"]
			}`,
			want:    []string{"https://kept.internal/*"},
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// The user may grant a pattern wider than any one site, and the browser
			// records it as given. It is still bounded by the request, which here is
			// every site, so what the extension holds is the grant.
			name: "a grant under a whole-web request is reported as granted",
			entry: `"withholding_permissions": true, "runtime_granted_permissions": {
				"explicit_host": ["https://*.internal/*"]
			}`,
			want:    []string{"https://*.internal/*"},
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// The pair is the same whole-web authority as either single wildcard,
			// and an extension that asks for it that way is left the same site.
			name:    "the http and https pair is whole-web authority too",
			active:  `"api": ["storage", "tabs"], "explicit_host": ["http://*/*", "https://*/*"]`,
			entry:   `"withholding_permissions": true, "runtime_granted_permissions": {"explicit_host": ["https://kept.internal/*"]}`,
			want:    []string{"https://kept.internal/*"},
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// A whole-web request carries no reach over local files, so a granted
			// file pattern under one is not a host this extension holds.
			name:    "a whole-web request does not admit a granted file pattern",
			active:  `"api": ["storage", "tabs"], "explicit_host": ["*://*/*"]`,
			entry:   `"withholding_permissions": true, "runtime_granted_permissions": {"explicit_host": ["file://*/*", "https://kept.internal/*"]}`,
			want:    []string{"https://kept.internal/*"},
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// <all_urls> is the one whole-web form that does reach local files, and
			// the browser's own separate file-access setting is the gate on that,
			// not this. Nothing else here tells the two forms apart.
			name:    "an every-scheme request admits a granted file pattern",
			active:  `"api": ["storage", "tabs"], "explicit_host": ["<all_urls>"]`,
			entry:   `"withholding_permissions": true, "runtime_granted_permissions": {"explicit_host": ["file://*/*"]}`,
			want:    []string{"file://*/*"},
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// Neither pattern is the other and the request is not whole-web, so
			// whether one covers the other is the browser's matching logic and not
			// ours to guess. Reported as no host: a false negative, and the
			// direction to err in.
			name:    "a partial request with a grant we cannot match reports no host",
			active:  `"api": ["storage", "tabs"], "explicit_host": ["https://maps.example.internal/*"]`,
			entry:   `"withholding_permissions": true, "runtime_granted_permissions": {"explicit_host": ["https://*.example.internal/*"]}`,
			want:    nil,
			wantAPI: []string{"storage", "tabs"},
		},
		{
			// Every browser that does not write the flag, and every extension
			// whose access was never restricted: the active set stands as it is,
			// and the runtime store is not read at all.
			name:    "no flag leaves the active set alone",
			entry:   `"runtime_granted_permissions": {"api": ["cookies"], "scriptable_host": ["https://elsewhere.internal/*"]}`,
			want:    []string{"*://*/*", "<all_urls>", "https://kept.internal/*"},
			wantAPI: []string{"storage", "tabs"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			active := tt.active
			if active == "" {
				active = broadRequest
			}
			got, _ := chromeFinding(t, `"`+idA+`": {
				"location": 1,
				"manifest": {"name": "Example", "version": "1.0"},
				"active_permissions": {`+active+`},
				`+tt.entry+`
			}`)

			if strings.Join(got.HostPermissions, ",") != strings.Join(tt.want, ",") {
				t.Errorf("host_permissions = %v, want %v", got.HostPermissions, tt.want)
			}
			// Withholding is about hosts. An API permission moving here means the
			// branch caught the wrong list.
			if strings.Join(got.Permissions, ",") != strings.Join(tt.wantAPI, ",") {
				t.Errorf("permissions = %v, want %v", got.Permissions, tt.wantAPI)
			}
		})
	}

	// The record a real browser writes for the ordinary "on specific sites"
	// choice, copied from a profile that was put in that state: the request stays
	// whole-web, the granted origin appears in both runtime buckets even though
	// the extension has no content script, and the active scriptable list stays
	// empty. Reporting the granted origin as injectable would be the browser's
	// bookkeeping read as provenance.
	t.Run("the shape a browser really writes for one granted site", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {
			"location": 4,
			"path": "/home/user/probe",
			"withholding_permissions": true,
			"active_permissions": {"api": [], "explicit_host": ["<all_urls>"], "scriptable_host": []},
			"runtime_granted_permissions": {
				"api": [],
				"explicit_host": ["https://example.test/*"],
				"scriptable_host": ["https://example.test/*"]
			}
		}`)

		if strings.Join(got.HostPermissions, ",") != "https://example.test/*" {
			t.Errorf("host_permissions = %v, want the one granted site", got.HostPermissions)
		}
		if got.ScriptableHostPermissions == nil || len(*got.ScriptableHostPermissions) != 0 {
			t.Errorf("scriptable_host_permissions = %v, want empty: the extension declares no content script",
				got.ScriptableHostPermissions)
		}
		// Both permission records were read, and an unpacked extension having no
		// manifest is not a failure, so nothing here degrades the browser.
		if coverage.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q, want scanned", coverage.Status)
		}
	})
}

// TestChromium_UnreadablePermissionRecords covers a permission block written in a
// shape this parser does not know. Each of the three records is decoded on its
// own, so one of them being unreadable costs what it holds and nothing else.
func TestChromium_UnreadablePermissionRecords(t *testing.T) {
	const manifest = `"location": 1, "manifest": {"name": "Example", "version": "1.0"}`

	t.Run("an unreadable active set keeps the rest of the record", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {`+manifest+`,
			"active_permissions": {"api": "storage"}
		}`)

		// The point of the case: identity and install facts survive.
		if got.Name != "Example" || got.Version != "1.0" ||
			got.InstallSource != model.BrowserExtInstallUser ||
			got.EnabledState != model.BrowserExtEnabled {
			t.Errorf("finding = %+v, want the metadata intact", got)
		}
		if len(got.Permissions) != 0 || len(got.HostPermissions) != 0 {
			t.Errorf("permissions/host_permissions = %v/%v, want neither",
				got.Permissions, got.HostPermissions)
		}
		if got.ScriptableHostPermissions != nil {
			t.Errorf("scriptable_host_permissions = %v, want absent", *got.ScriptableHostPermissions)
		}
		if coverage.Status != model.BrowserCoveragePartial ||
			coverage.ReasonCode != model.BrowserExtReasonManifestUnavailable {
			t.Errorf("status = %q/%q, want partial and manifest_unavailable",
				coverage.Status, coverage.ReasonCode)
		}
	})

	// Historical state is not read, so its shape cannot matter. This is the whole
	// reason the field was dropped from the struct rather than parsed and ignored.
	t.Run("an unreadable granted set changes nothing", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {`+manifest+`,
			"active_permissions": {"api": ["storage"]},
			"granted_permissions": ["not", "an", "object"]
		}`)

		if strings.Join(got.Permissions, ",") != "storage" {
			t.Errorf("permissions = %v, want storage", got.Permissions)
		}
		if coverage.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q, want scanned", coverage.Status)
		}
	})

	t.Run("an unreadable runtime store is not read without withholding", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {`+manifest+`,
			"active_permissions": {"api": ["storage"], "explicit_host": ["https://example.internal/*"]},
			"runtime_granted_permissions": 7
		}`)

		if strings.Join(got.HostPermissions, ",") != "https://example.internal/*" {
			t.Errorf("host_permissions = %v, want the active host", got.HostPermissions)
		}
		if coverage.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q, want scanned: the store was never needed", coverage.Status)
		}
	})

	// Under withholding the hosts cannot be worked out without that store, but the
	// API permissions never went through it.
	t.Run("an unreadable runtime store under withholding costs the hosts alone", func(t *testing.T) {
		got, coverage := chromeFinding(t, `"`+idA+`": {`+manifest+`,
			"withholding_permissions": true,
			"active_permissions": {"api": ["storage", "tabs"], "explicit_host": ["<all_urls>"]},
			"runtime_granted_permissions": 7
		}`)

		if strings.Join(got.Permissions, ",") != "storage,tabs" {
			t.Errorf("permissions = %v, want storage,tabs", got.Permissions)
		}
		if got.Name != "Example" {
			t.Errorf("name = %q, want the metadata intact", got.Name)
		}
		if len(got.HostPermissions) != 0 {
			t.Errorf("host_permissions = %v, want none: which of them survived is unknown", got.HostPermissions)
		}
		if got.ScriptableHostPermissions != nil {
			t.Errorf("scriptable_host_permissions = %v, want absent", *got.ScriptableHostPermissions)
		}
		if coverage.Status != model.BrowserCoveragePartial ||
			coverage.ReasonCode != model.BrowserExtReasonManifestUnavailable {
			t.Errorf("status = %q/%q, want partial and manifest_unavailable",
				coverage.Status, coverage.ReasonCode)
		}
	})
}

// TestChromium_ScriptableHostsAreASubset covers the stronger of the two host
// capabilities. Injecting code into a page is not the same as sending it a
// request, and the browser records the difference, so the payload keeps it.
func TestChromium_ScriptableHostsAreASubset(t *testing.T) {
	t.Run("the injectable hosts are named inside the reachable ones", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {
				"explicit_host": ["<all_urls>"],
				"scriptable_host": ["https://example.internal/*"]
			}
		}`)

		wantHosts := []string{"<all_urls>", "https://example.internal/*"}
		if strings.Join(got.HostPermissions, ",") != strings.Join(wantHosts, ",") {
			t.Errorf("host_permissions = %v, want %v", got.HostPermissions, wantHosts)
		}
		if got.ScriptableHostPermissions == nil {
			t.Fatal("scriptable_host_permissions is absent, want the answer this family always has")
		}
		want := []string{"https://example.internal/*"}
		if strings.Join(*got.ScriptableHostPermissions, ",") != strings.Join(want, ",") {
			t.Errorf("scriptable_host_permissions = %v, want %v", *got.ScriptableHostPermissions, want)
		}
	})

	t.Run("an extension that injects nowhere says so", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {"explicit_host": ["https://example.internal/*"]}
		}`)

		if got.ScriptableHostPermissions == nil || len(*got.ScriptableHostPermissions) != 0 {
			t.Errorf("scriptable_host_permissions = %v, want an empty list: this family knows the answer",
				got.ScriptableHostPermissions)
		}
	})

	t.Run("withholding empties both lists together", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"withholding_permissions": true,
			"active_permissions": {"scriptable_host": ["https://taken-back.internal/*"]},
			"runtime_granted_permissions": {"api": ["cookies"]}
		}`)

		if len(got.HostPermissions) != 0 {
			t.Errorf("host_permissions = %v, want none", got.HostPermissions)
		}
		// A host the extension cannot reach is not one it can inject into, so the
		// stronger list cannot outlive the weaker one.
		if got.ScriptableHostPermissions == nil || len(*got.ScriptableHostPermissions) != 0 {
			t.Errorf("scriptable_host_permissions = %v, want none", got.ScriptableHostPermissions)
		}
	})

	// The two buckets mean different things to the browser: one is what requests
	// and cookie reads may reach, the other is where content scripts run. Under
	// withholding each is intersected against its own side of the runtime store,
	// so a runtime host grant cannot invent content-script provenance.
	t.Run("withholding keeps the two host buckets apart", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"withholding_permissions": true,
			"active_permissions": {
				"explicit_host": ["https://example.internal/*"],
				"scriptable_host": ["https://example.internal/*"]
			},
			"runtime_granted_permissions": {"explicit_host": ["https://example.internal/*"]}
		}`)

		want := []string{"https://example.internal/*"}
		if strings.Join(got.HostPermissions, ",") != strings.Join(want, ",") {
			t.Errorf("host_permissions = %v, want %v: the user left it that site", got.HostPermissions, want)
		}
		if got.ScriptableHostPermissions == nil {
			t.Fatal("scriptable_host_permissions is absent")
		}
		if len(*got.ScriptableHostPermissions) != 0 {
			t.Errorf("scriptable_host_permissions = %v, want none: the runtime store granted the site to requests, not to content scripts",
				*got.ScriptableHostPermissions)
		}
	})

	t.Run("a host the cap drops is absent from both lists", func(t *testing.T) {
		// Sorts after every filler entry, so the count cap is what removes it.
		const last = `"https://zz-injectable.internal/*"`
		filler := make([]string, maxPermissionsPerFinding)
		for i := range filler {
			filler[i] = fmt.Sprintf(`"https://a%02d.internal/*"`, i)
		}
		got, coverage := chromeFinding(t, `"`+idA+`": {
			"location": 1,
			"manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {
				"explicit_host": [`+strings.Join(filler, ",")+`],
				"scriptable_host": [`+last+`]
			}
		}`)

		if slices.Contains(got.HostPermissions, strings.Trim(last, `"`)) {
			t.Fatalf("host_permissions still carries the capped entry: %v", got.HostPermissions)
		}
		if got.ScriptableHostPermissions == nil {
			t.Fatal("scriptable_host_permissions is absent")
		}
		if len(*got.ScriptableHostPermissions) != 0 {
			t.Errorf("scriptable_host_permissions = %v, want none: the stronger list must not outlive the cap",
				*got.ScriptableHostPermissions)
		}
		if coverage.Status != model.BrowserCoveragePartial || coverage.ReasonCode != model.BrowserExtReasonCapped {
			t.Errorf("status = %q/%q, want partial and capped", coverage.Status, coverage.ReasonCode)
		}
	})
}

// TestChromium_ManifestVersion separates two extensions that otherwise look
// identical. Version 2 can hold blocking request interception, which version 3
// removed, so the same content blocker on two engines is not the same capability.
func TestChromium_ManifestVersion(t *testing.T) {
	for _, tt := range []struct {
		name     string
		manifest string
		want     int
	}{
		{"the revision that can still block requests", `"manifest_version": 2`, 2},
		{"the revision that cannot", `"manifest_version": 3`, 3},
		{"a record that does not say", `"version": "1.0"`, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := chromeFinding(t, `"`+idA+`": {
				"location": 1,
				"active_permissions": {},
				"manifest": {"name": "Example", `+tt.manifest+`}
			}`)
			if got.ManifestVersion != tt.want {
				t.Errorf("manifest_version = %d, want %d", got.ManifestVersion, tt.want)
			}
		})
	}
}

// TestChromium_OverlongFieldsByClass pins the difference between a string a person
// reads and a string something matches. A name is shortened; a permission is
// dropped, because a shortened grant is a different grant and showing an auditor a
// permission the extension never held is worse than showing one fewer.
func TestChromium_OverlongFieldsByClass(t *testing.T) {
	t.Run("a name is shortened and the browser stays clean", func(t *testing.T) {
		long := strings.Repeat("N", maxNameBytes+50)
		got, coverage := chromeFinding(t, `"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "`+long+`", "version": "1.0"}}`)
		if len(got.Name) > maxNameBytes {
			t.Errorf("name is %d bytes, want at most %d", len(got.Name), maxNameBytes)
		}
		if coverage.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q, want no status change for a display field", coverage.Status)
		}
	})

	t.Run("an overlong host pattern is absent, not shortened", func(t *testing.T) {
		long := "https://" + strings.Repeat("h", maxPermissionBytes) + ".internal/*"
		got, coverage := chromeFinding(t, `"`+idA+`": {
			"location": 1, "manifest": {"name": "Example", "version": "1.0"},
			"active_permissions": {"explicit_host": ["`+long+`", "https://kept.internal/*"]}
		}`)
		want := []string{"https://kept.internal/*"}
		if strings.Join(got.HostPermissions, ",") != strings.Join(want, ",") {
			t.Errorf("host_permissions = %v, want exactly %v — a shortened pattern must never ship",
				got.HostPermissions, want)
		}
		if coverage.Status != model.BrowserCoveragePartial || coverage.ReasonCode != model.BrowserExtReasonCapped {
			t.Errorf("status = %q/%q, want partial and capped", coverage.Status, coverage.ReasonCode)
		}
	})
}

// TestChromium_ManifestFallbackAndLocalizedName covers the two reads beyond the
// preferences: the manifest on disk when the preference copy is missing, and the
// message table a localized name resolves through.
func TestChromium_ManifestFallbackAndLocalizedName(t *testing.T) {
	t.Run("the manifest on disk fills in for a store install", func(t *testing.T) {
		home := tempHome(t)
		root := chromeRoot(home)
		localState(t, root, "Default")
		securePrefs(t, root, "Default", `"`+idA+`": {"location": 1, "active_permissions": {}, "path": "`+idA+`/1.2.3_0"}`)
		writeFile(t, filepath.Join(root, "Default", "Extensions", idA, "1.2.3_0", "manifest.json"),
			`{"name": "Example From Disk", "version": "1.2.3"}`)

		info := scanHome(t, home)
		assertPayloadInvariants(t, info)
		got := findingsFor(info, browserChrome)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want one", len(got))
		}
		if got[0].Name != "Example From Disk" || got[0].Version != "1.2.3" {
			t.Errorf("name/version = %q/%q, want the values from the manifest on disk", got[0].Name, got[0].Version)
		}
		if c := coverageFor(t, info, browserChrome); c.Status != model.BrowserCoverageScanned {
			t.Errorf("status = %q/%q, want scanned: nothing was missing", c.Status, c.ReasonCode)
		}
	})

	t.Run("a localized name resolves through the declared locale", func(t *testing.T) {
		home := tempHome(t)
		root := chromeRoot(home)
		localState(t, root, "Default")
		securePrefs(t, root, "Default", `"`+idA+`": {
			"location": 1, "path": "`+idA+`/1.0_0", "active_permissions": {},
			"manifest": {"name": "__MSG_extName__", "version": "1.0", "default_locale": "en-GB"}
		}`)
		// Directory names use underscores rather than a language tag's hyphen,
		// and the browser compares message names without case.
		writeFile(t, filepath.Join(root, "Default", "Extensions", idA, "1.0_0", "_locales", "en_GB", "messages.json"),
			`{"EXTNAME": {"message": "Example Localized"}}`)

		got := findingsFor(scanHome(t, home), browserChrome)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want one", len(got))
		}
		if got[0].Name != "Example Localized" {
			t.Errorf("name = %q, want the resolved message", got[0].Name)
		}
	})

	t.Run("an unresolvable name keeps its placeholder", func(t *testing.T) {
		got, _ := chromeFinding(t, `"`+idA+`": {"location": 1, "active_permissions": {}, "path": "`+idA+`/1.0_0",
			"manifest": {"name": "__MSG_extName__", "version": "1.0", "default_locale": "en"}}`)
		if got.Name != "__MSG_extName__" {
			t.Errorf("name = %q, want the placeholder kept rather than an empty name", got.Name)
		}
	})

	// Both reads describe an extension the preference map has already listed.
	// Neither can add or remove one, so a refusal costs the attribute and leaves
	// membership — and every other extension in the browser — standing.
	t.Run("a refused attribute read degrades rather than failing the browser", func(t *testing.T) {
		tests := []struct {
			name  string
			entry string
			// Planted where the read expects a state file: something of that name
			// which is not one. The read refuses it rather than describing
			// whatever it is.
			plant []string
		}{
			{
				name:  "the manifest on disk",
				entry: `"` + idA + `": {"location": 1, "active_permissions": {}, "path": "` + idA + `/1.0_0"}`,
				plant: []string{"manifest.json", "anything"},
			},
			{
				name: "the message table behind a localized name",
				entry: `"` + idA + `": {"location": 1, "active_permissions": {}, "path": "` + idA + `/1.0_0",
					"manifest": {"name": "__MSG_extName__", "version": "1.0", "default_locale": "en"}}`,
				plant: []string{"_locales", "en", "messages.json", "anything"},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				home := tempHome(t)
				root := chromeRoot(home)
				localState(t, root, "Default")
				securePrefs(t, root, "Default", tc.entry)
				mkdir(t, filepath.Join(append([]string{root, "Default", "Extensions", idA, "1.0_0"}, tc.plant...)...))

				info := scanHome(t, home)
				assertPayloadInvariants(t, info)
				got := findingsFor(info, browserChrome)
				if len(got) != 1 || got[0].ExtensionID != idA {
					t.Fatalf("findings = %d, want the listed extension still reported", len(got))
				}
				if c := coverageFor(t, info, browserChrome); c.Status != model.BrowserCoveragePartial {
					t.Errorf("status = %q/%q, want partial: membership is still complete", c.Status, c.ReasonCode)
				}
			})
		}
	})
}

// TestChromium_UnpackedContentIsNeverOpened is the rule with no exception: an
// unpacked extension's directory is an arbitrary user location, so its absolute
// path is never resolved and never read. The manifest planted there would supply
// a name if anything opened it.
//
// The path itself does ship. It is the one thing that makes the row actionable
// once the name is gone, and it is reported exactly as the preferences recorded
// it. Nothing was read and failed to read here, so the browser stays clean: a
// developer with a build loaded would otherwise see a degraded browser on every
// scan for ever.
func TestChromium_UnpackedContentIsNeverOpened(t *testing.T) {
	home := tempHome(t)
	unpacked := filepath.Join(home, "projects", "client-work", "ext")
	writeFile(t, filepath.Join(unpacked, "manifest.json"), `{"name": "Example Never Read", "version": "9.9"}`)

	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default",
		`"`+idA+`": {"location": 4, "active_permissions": {}, "path": "`+filepath.ToSlash(unpacked)+`"}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want the extension reported with what the preferences held", len(got))
	}
	if got[0].Name != "" {
		t.Errorf("name = %q, want none: the extension's own directory must never be opened", got[0].Name)
	}
	if got[0].InstallSource != model.BrowserExtInstallUnpacked {
		t.Errorf("install_source = %q, want unpacked — the whole signal this row carries", got[0].InstallSource)
	}
	if got[0].InstallPath != filepath.ToSlash(unpacked) {
		t.Errorf("install_path = %q, want %q: where it was loaded from is what this row is for",
			got[0].InstallPath, unpacked)
	}
	c := coverageFor(t, info, browserChrome)
	if c.Status != model.BrowserCoverageScanned {
		t.Errorf("status = %q/%q, want scanned: no manifest was read, so none failed to read",
			c.Status, c.ReasonCode)
	}
}

// TestChromium_UnpackedPathIsOmittedRatherThanShortened keeps the load path in
// the class of strings that are matched rather than read. Half a path names a
// directory nobody has, and a browser is not degraded over it: the row still
// carries the identity and the install source that make it worth looking at.
func TestChromium_UnpackedPathIsOmittedRatherThanShortened(t *testing.T) {
	home := tempHome(t)
	long := "/" + strings.Repeat("d", maxInstallPathBytes)

	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default", `"`+idA+`": {"location": 4, "active_permissions": {}, "path": "`+long+`"}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := findingsFor(info, browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want the extension reported without its path", len(got))
	}
	if got[0].InstallPath != "" {
		t.Errorf("install_path = %q, want none: a shortened path is a different directory", got[0].InstallPath)
	}
	if got[0].InstallSource != model.BrowserExtInstallUnpacked {
		t.Errorf("install_source = %q, want unpacked", got[0].InstallSource)
	}
}

// TestChromium_UnreadableManifestStillDegrades is the other polarity of the same
// branch. An unpacked extension is not degraded because nothing was read; a store
// install whose manifest genuinely refuses to read still is, because something
// was.
func TestChromium_UnreadableManifestStillDegrades(t *testing.T) {
	home := tempHome(t)
	root := chromeRoot(home)
	localState(t, root, "Default")
	securePrefs(t, root, "Default", `"`+idA+`": {"location": 1, "active_permissions": {}, "path": "`+idA+`/1.2.3_0"}`)
	writeFile(t, filepath.Join(root, "Default", "Extensions", idA, "1.2.3_0", "manifest.json"),
		strings.Repeat("{", maxManifestBytes+1))

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	c := coverageFor(t, info, browserChrome)
	if c.Status != model.BrowserCoveragePartial {
		t.Errorf("status = %q, want partial: a document was reached and could not be read", c.Status)
	}
}

// TestChromium_ByteOrderMarkedPrefsStillParse covers the class of failure a
// Windows-authored file introduces: a mark in front of the document makes every
// parser reject the whole thing, and a profile full of extensions would report as
// empty.
func TestChromium_ByteOrderMarkedPrefsStillParse(t *testing.T) {
	home := tempHome(t)
	root := chromeRoot(home)
	localState(t, root, "Default")
	const bom = "\uFEFF"
	writeFile(t, filepath.Join(root, "Default", "Secure Preferences"),
		bom+`{"extensions": {"settings": {"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}}}}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	if got := findingsFor(info, browserChrome); len(got) != 1 {
		t.Fatalf("findings = %d, want the byte order mark stripped and the file parsed", len(got))
	}
}

// TestChromium_TwoByteEncodingIsReportedRatherThanParsed covers the other
// encoding. A byte-oriented parser reads almost nothing from it rather than
// failing, so the file would read as holding no extensions.
func TestChromium_TwoByteEncodingIsReportedRatherThanParsed(t *testing.T) {
	home := tempHome(t)
	root := chromeRoot(home)
	localState(t, root, "Default")
	if err := os.MkdirAll(filepath.Join(root, "Default"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Default", "Secure Preferences"),
		[]byte{0xFF, 0xFE, 0x7B, 0x00}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := coverageFor(t, info, browserChrome)
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonUnsupportedEncoding {
		t.Errorf("status = %q/%q, want failed and the encoding named", got.Status, got.ReasonCode)
	}
}

// TestChromium_PreinstalledIsReportedAndNotHidden keeps a default-installed
// extension in the inventory. It is a real extension with real permissions; the
// flag is there so a console can de-emphasize it rather than so this can drop it.
func TestChromium_PreinstalledIsReportedAndNotHidden(t *testing.T) {
	got, _ := chromeFinding(t, `"`+idA+`": {
		"location": 6, "was_installed_by_default": true, "active_permissions": {},
		"manifest": {"name": "Example Bundled", "version": "1.0"}
	}`)
	if !got.Preinstalled {
		t.Error("preinstalled = false, want the default-install flag reported")
	}
	if got.InstallSource != model.BrowserExtInstallSideload {
		t.Errorf("install_source = %q, want the location's own answer rather than the flag's", got.InstallSource)
	}
}
