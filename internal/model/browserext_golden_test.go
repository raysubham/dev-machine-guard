package model

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// browserExtGoldenPath holds one browser extension snapshot exercising every
// enum value a single valid payload can carry, plus the coverage combinations
// that are easy to get wrong: a failed browser with no findings, an
// authoritative browser with none, a reduced finding with no name. The same
// bytes are the contract the reader in the other repository is tested against.
const browserExtGoldenPath = "testdata/browser_extension_scan_golden.json"

// browserExtGoldenGeckoIDs names the fixture's gecko browsers. The engine of a
// browser_id is catalog knowledge and this package is dependency-free, so the
// two engine-specific field rules are checked against the one gecko id the
// fixture uses.
var browserExtGoldenGeckoIDs = map[string]bool{"firefox": true}

// TestBrowserExtensionScanGolden_RoundTripsWithNoDroppedField is the contract
// check between this struct and the reader on the other end of the wire. Both
// sides are hand-maintained Go types in separate repositories, and the reader
// drops a field it does not know rather than rejecting it — so a field renamed
// here does not fail anything, it silently stops arriving.
func TestBrowserExtensionScanGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, err := os.ReadFile(browserExtGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// A field in the fixture this struct has no home for is a field this agent
	// would never send, which is how the two shapes drift apart unnoticed.
	var info BrowserExtensionScanInfo
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info); err != nil {
		t.Fatalf("golden payload does not fit BrowserExtensionScanInfo: %v", err)
	}

	// A field decoded but not emitted back is the same drift the other way, so
	// the comparison is on the re-encoded document rather than on the struct.
	encoded, err := json.Marshal(&info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := decodeGeneric(t, raw)
	got := decodeGeneric(t, encoded)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

// TestBrowserExtensionScanGolden_CoversTheWholeVocabulary keeps the fixture
// honest. Its value is entirely in what it exercises, so one that has quietly
// stopped covering a state is worse than none: it passes while the field it
// protects goes unchecked.
func TestBrowserExtensionScanGolden_CoversTheWholeVocabulary(t *testing.T) {
	info := loadBrowserExtGolden(t)

	statuses := map[string]bool{}
	for _, b := range info.Browsers {
		statuses[b.Status] = true
	}
	states, disabledBy, listings, violations := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	sources, stores, signed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range info.Findings {
		states[f.EnabledState] = true
		stores[f.Store] = true
		sources[f.InstallSource] = true
		if f.DisabledBy != "" {
			disabledBy[f.DisabledBy] = true
		}
		if f.StoreListing != "" {
			listings[f.StoreListing] = true
		}
		if f.StoreViolation != "" {
			violations[f.StoreViolation] = true
		}
		if f.SignedState != "" {
			signed[f.SignedState] = true
		}
	}

	for _, tt := range []struct {
		what string
		got  map[string]bool
		want []string
	}{
		// BrowserCoverageNotPresent is absent on purpose. The catalog is three
		// browsers and the other three statuses are each load-bearing here, so a
		// fourth cannot be shown in one payload. It is covered directly instead,
		// by the detector's no-installation and no-browsers-at-all cases.
		{"status", statuses, []string{
			BrowserCoverageScanned, BrowserCoveragePartial, BrowserCoverageFailed,
		}},
		{"enabled_state", states, []string{
			BrowserExtEnabled, BrowserExtDisabled, BrowserExtStateUnknown,
		}},
		{"disabled_by", disabledBy, []string{
			BrowserExtDisabledByUser, BrowserExtDisabledByBrowser,
			BrowserExtDisabledByPolicy, BrowserExtDisabledByUnknown,
		}},
		{"store_listing", listings, []string{
			BrowserExtStoreListingListed, BrowserExtStoreListingDelisted,
			BrowserExtStoreListingUnknown,
		}},
		{"store_violation", violations, []string{
			BrowserExtStoreViolationNone, BrowserExtStoreViolationFlagged,
			BrowserExtStoreViolationUnknown,
		}},
		{"install_source", sources, []string{
			BrowserExtInstallUser, BrowserExtInstallSideload, BrowserExtInstallRegistry,
			BrowserExtInstallUnpacked, BrowserExtInstallPolicy, BrowserExtInstallUnknown,
		}},
		{"store", stores, []string{
			BrowserExtStoreChromeWebStore, BrowserExtStoreEdgeAddons, BrowserExtStoreAMO,
			BrowserExtStoreSelfHosted, BrowserExtStoreNone, BrowserExtStoreUnknown,
		}},
		{"signed_state", signed, []string{
			BrowserExtSignedBroken, BrowserExtSignedUnknownChain, BrowserExtSignedMissing,
			BrowserExtSignedPreliminary, BrowserExtSignedSigned, BrowserExtSignedSystem,
			BrowserExtSignedPrivileged,
		}},
	} {
		for _, want := range tt.want {
			if !tt.got[want] {
				t.Errorf("golden payload has no %s %q", tt.what, want)
			}
		}
	}

	// The two closed sets a single valid payload cannot demonstrate. A browser
	// carries one reason code and a payload one truncated reason, so the fixture
	// can only ever show a couple of each — while a reader matches every one of
	// them against a list it maintains separately. Spelled out here so a renamed
	// or dropped code fails at home rather than as a rejected payload.
	for _, tt := range []struct{ got, want string }{
		{BrowserExtReasonRefusedTCC, "refused_tcc"},
		{BrowserExtReasonPermissionDenied, "permission_denied"},
		{BrowserExtReasonParseError, "parse_error"},
		{BrowserExtReasonUnsupportedEncoding, "unsupported_encoding"},
		{BrowserExtReasonSymlinkRejected, "symlink_rejected"},
		{BrowserExtReasonManifestUnavailable, "manifest_unavailable"},
		{BrowserExtReasonCapped, "capped"},
		{BrowserExtReasonTimedOut, "timed_out"},
		{BrowserExtTruncatedFindingCap, "finding_cap"},
		{BrowserExtTruncatedDeadline, "deadline"},
	} {
		if tt.got != tt.want {
			t.Errorf("code is spelled %q, and a reader matches %q", tt.got, tt.want)
		}
	}

	// The four fields whose whole value is a distinction, so a fixture that
	// stops showing both sides of one leaves the reader's handling of it
	// unchecked. Scriptable hosts have three states, not two: a real subset, an
	// empty list meaning the extension injects nowhere, and an absent one
	// meaning nothing recorded the split.
	scriptableSubset, scriptableEmpty, scriptableAbsent := false, false, false
	manifestVersions := map[int]bool{}
	dataCollection, installPath := false, false
	for _, f := range info.Findings {
		switch {
		case f.ScriptableHostPermissions == nil:
			scriptableAbsent = true
		case len(*f.ScriptableHostPermissions) == 0:
			scriptableEmpty = true
		default:
			scriptableSubset = true
		}
		manifestVersions[f.ManifestVersion] = true
		if len(f.DataCollection) > 0 {
			dataCollection = true
		}
		if f.InstallPath != "" {
			installPath = true
		}
	}
	for _, tt := range []struct {
		got  bool
		want string
	}{
		{scriptableSubset, "a finding whose scriptable_host_permissions names hosts"},
		{scriptableEmpty, "a finding that injects nowhere, whose scriptable_host_permissions is empty"},
		{scriptableAbsent, "a finding with no scriptable_host_permissions, where the split was not recorded"},
		{manifestVersions[2], "a manifest version 2 finding, which can hold blocking request interception"},
		{manifestVersions[3], "a manifest version 3 finding"},
		{manifestVersions[0], "a finding whose manifest version the browser never recorded"},
		{dataCollection, "a finding declaring data_collection"},
		{installPath, "an unpacked finding carrying its install_path"},
	} {
		if !tt.got {
			t.Errorf("golden payload must carry %s", tt.want)
		}
	}

	// A reduced finding: metadata that could not be recovered, identity that
	// could. A reader that requires a name drops a real extension on this row.
	reduced := false
	for _, f := range info.Findings {
		if f.Name == "" && f.ExtensionID != "" {
			reduced = true
		}
	}
	if !reduced {
		t.Error("golden payload must carry a finding whose name is empty and whose identity is not")
	}

	// Both incompleteness flags together, and the reason for the second: a
	// reader validates the pair in both directions.
	if info.ScanComplete || !info.Truncated || info.TruncatedReason == "" {
		t.Error("golden payload must exercise an incomplete, truncated snapshot with its reason")
	}
	if info.CatalogVersion == "" {
		t.Error("golden payload must declare a catalog_version")
	}
	if info.PayloadSchemaVersion != CurrentBrowserExtensionSchemaVersion {
		t.Errorf("golden payload declares schema %d, want %d",
			info.PayloadSchemaVersion, CurrentBrowserExtensionSchemaVersion)
	}
}

// TestBrowserExtensionScanGolden_HonoursTheCoverageInvariants checks the rules a
// reader rejects the whole block over. A fixture that violates one would be
// accepted here and refused there, which is the worst possible fixture: it
// proves the contract while breaking it.
func TestBrowserExtensionScanGolden_HonoursTheCoverageInvariants(t *testing.T) {
	info := loadBrowserExtGolden(t)

	perBrowser := map[string]int{}
	for _, f := range info.Findings {
		perBrowser[f.BrowserID]++
	}

	seen := map[string]bool{}
	for _, b := range info.Browsers {
		if seen[b.BrowserID] {
			t.Errorf("%s: second coverage entry for one browser", b.BrowserID)
		}
		seen[b.BrowserID] = true

		switch b.Status {
		case BrowserCoveragePartial, BrowserCoverageFailed:
			if b.ReasonCode == "" {
				t.Errorf("%s: status %q needs a reason_code", b.BrowserID, b.Status)
			}
		default:
			if b.ReasonCode != "" {
				t.Errorf("%s: status %q must carry no reason_code, got %q", b.BrowserID, b.Status, b.ReasonCode)
			}
		}
		// failed ships nothing: a partial list under an authoritative status
		// would delete the extensions it left out.
		if b.Status == BrowserCoverageFailed || b.Status == BrowserCoverageNotPresent {
			if b.ExtensionCount != 0 || perBrowser[b.BrowserID] != 0 {
				t.Errorf("%s: status %q must carry zero findings, got count=%d findings=%d",
					b.BrowserID, b.Status, b.ExtensionCount, perBrowser[b.BrowserID])
			}
			continue
		}
		if b.ExtensionCount != perBrowser[b.BrowserID] {
			t.Errorf("%s: extension_count = %d, findings = %d", b.BrowserID, b.ExtensionCount, perBrowser[b.BrowserID])
		}
	}

	for _, f := range info.Findings {
		if !seen[f.BrowserID] {
			t.Errorf("%s: finding for a browser with no coverage entry", f.BrowserID)
		}
		if f.ExtensionID == "" {
			t.Error("finding with no identity")
		}
		// The cause is present exactly when there is something to explain.
		if (f.EnabledState == BrowserExtDisabled) != (f.DisabledBy != "") {
			t.Errorf("%s: enabled_state %q with disabled_by %q", f.ExtensionID, f.EnabledState, f.DisabledBy)
		}
		gecko := browserExtGoldenGeckoIDs[f.BrowserID]
		if gecko != (f.SignedState != "") {
			t.Errorf("%s: signed_state %q on browser %q", f.ExtensionID, f.SignedState, f.BrowserID)
		}
		if gecko == (f.StoreListing != "") || gecko == (f.StoreViolation != "") {
			t.Errorf("%s: store fields %q/%q on browser %q",
				f.ExtensionID, f.StoreListing, f.StoreViolation, f.BrowserID)
		}
		if f.ScriptableHostPermissions != nil {
			// Gecko keeps one origins list, so a list here would be an answer
			// the engine never gave.
			if gecko {
				t.Errorf("%s: scriptable_host_permissions on gecko browser %q", f.ExtensionID, f.BrowserID)
			}
			// A host that can be injected into is one the extension reaches, so
			// a scriptable entry missing from host_permissions understates the
			// row it appears on.
			for _, h := range *f.ScriptableHostPermissions {
				if !slices.Contains(f.HostPermissions, h) {
					t.Errorf("%s: scriptable host %q is absent from host_permissions", f.ExtensionID, h)
				}
			}
		}
		// The path is the load location of an unpacked extension and means
		// nothing on any other install source.
		if f.InstallPath != "" && f.InstallSource != BrowserExtInstallUnpacked {
			t.Errorf("%s: install_path on install_source %q", f.ExtensionID, f.InstallSource)
		}
		if f.ManifestVersion < 0 {
			t.Errorf("%s: manifest_version %d", f.ExtensionID, f.ManifestVersion)
		}
	}
}

func loadBrowserExtGolden(t *testing.T) BrowserExtensionScanInfo {
	t.Helper()
	raw, err := os.ReadFile(browserExtGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var info BrowserExtensionScanInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return info
}
