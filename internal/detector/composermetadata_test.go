package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestComposerMetadataEvidence(t *testing.T) {
	m, err := parseComposerManifest([]byte(`{"name":"example/app","require":{"example/lib":"dev-main as 1.0.x-dev","php":"^8.2","ext-json":"*","composer-runtime-api":"^2"},"require-dev":{"example/tool":"^2@dev"},"suggest":{"example/optional":"no"},"provide":{"virtual/pkg":"*"},"scripts":{"post-install-cmd":"NEVER_RUN"}}`))
	if err != nil || m.partial || len(m.packages) != 2 {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	if p := m.packages[0]; p.PackageName != "example/lib" || p.VersionStatus != "unknown" || p.Version != "" || p.RequestedVersion != "dev-main as 1.0.x-dev" || p.DependencyRelation != "direct" {
		t.Fatalf("declaration: %+v", p)
	}
	for _, tc := range []struct {
		name, body string
		installed  bool
		count      int
		kind       string
	}{
		{"lock", `{"packages":[{"name":"example/lib","version":"dev-main"},{"name":"example/transitive","version":"1.2.3"}],"packages-dev":[{"name":"example/tool","version":"2.1.0"}],"aliases":[{"package":"example/lib","alias":"1.0.x-dev"}]}`, false, 3, "require"},
		{"legacy", `[{"name":"example/lib","version":"v1.0.0"}]`, true, 1, "unknown"},
		{"current", `{"packages":[{"name":"example/lib","version":"1.2.3","require-dev":{"vendor/dev":"*"}}],"dev":false,"dev-package-names":[]}`, true, 1, "require"},
		{"dev", `{"packages":[{"name":"example/tool","version":"2.1.0"}],"dev-package-names":["example/tool"]}`, true, 1, "require_dev"},
		{"empty legacy", `[]`, true, 0, ""}, {"empty current", `{"packages":[]}`, true, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, partial, err := parseComposerPackages([]byte(tc.body), tc.installed)
			if err != nil || partial || len(entries) != tc.count {
				t.Fatalf("entries=%+v partial=%v err=%v", entries, partial, err)
			}
			if tc.count > 0 && entries[0].pkg.DependencyKind != tc.kind {
				t.Fatalf("kind=%s", entries[0].pkg.DependencyKind)
			}
		})
	}
}
func TestComposerMetadataMalformedNeighborsAndBounds(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"packages":null}`, `{"packages":{}}`, `{"packages":[`, `false`} {
		if _, _, err := parseComposerPackages([]byte(body), true); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	entries, partial, err := parseComposerPackages([]byte(`{"packages":[null,{"name":"../evil","version":"1"},{"name":"example/good","version":"dev-main","version_normalized":"dev-main"},{"name":"example/missing"}]}`), true)
	if err != nil || !partial || len(entries) != 1 || entries[0].pkg.PackageName != "example/good" {
		t.Fatalf("neighbors %+v %v %v", entries, partial, err)
	}
	old := maxComposerMetadataBytes
	t.Cleanup(func() { maxComposerMetadataBytes = old })
	maxComposerMetadataBytes = 8
	if _, _, err := parseComposerPackages([]byte(`{"packages":[]}`), true); err == nil {
		t.Fatal("accepted oversized metadata")
	}
}
func TestComposerMetadataChecksumAndURLs(t *testing.T) {
	for _, tc := range []struct {
		hash, status string
		count        int
	}{{"", "absent", 0}, {strings.Repeat("AB", 20), "recorded", 1}, {"SECRET_CANARY", "partial", 0}, {strings.Repeat("f", 39), "partial", 0}} {
		body := `{"packages":[{"name":"example/lib","version":"1.0.0","source":{"type":"git","url":"https://alice:SECRET_CANARY@code.example.invalid/lib?secret=SECRET_CANARY#SECRET_CANARY","reference":"branch/release"},"dist":{"type":"zip","url":"https://dist.example.invalid/lib.zip?token=SECRET_CANARY","shasum":"` + tc.hash + `"}}]}`
		entries, partial, err := parseComposerPackages([]byte(body), false)
		if err != nil || partial || len(entries) != 1 {
			t.Fatalf("parse %+v %v %v", entries, partial, err)
		}
		p := entries[0].pkg
		if p.ChecksumStatus != tc.status || len(p.RecordedChecksums) != tc.count {
			t.Fatalf("checksum %+v", p)
		}
		encoded, _ := json.Marshal(p)
		if strings.Contains(string(encoded), "SECRET_CANARY") {
			t.Fatal("secret survived")
		}
		if p.Source.URL != "https://code.example.invalid/lib" || p.Source.Reference != "branch/release" {
			t.Fatalf("descriptor %+v", p.Source)
		}
		if tc.count > 0 && (p.RecordedChecksums[0].Value != strings.Repeat("ab", 20) || p.RecordedChecksums[0].Verification != "not_verified") {
			t.Fatal("checksum normalization")
		}
	}
}

// Sanitized receipts from the research archive dated 2026-10-04, including
// Composer 1.10.28 and 2.2.30. Only parser-allowlisted package fields remain.
// These format tests do not substitute for the product VM acceptance run.
func TestComposerNativeMetadataFixtures(t *testing.T) {
	for _, name := range []string{"composer1", "composer22", "baseline", "no-dev", "custom-installer", "public-app"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "composer", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			entries, partial, err := parseComposerPackages(data, true)
			if err != nil || partial || len(entries) == 0 {
				t.Fatalf("native metadata %d %v %v", len(entries), partial, err)
			}
			if name == "baseline" && len(entries) != 4 {
				t.Fatalf("baseline count %d", len(entries))
			}
			if name == "no-dev" && len(entries) != 3 {
				t.Fatalf("no-dev count %d", len(entries))
			}
			if name == "custom-installer" && !slices.ContainsFunc(entries, func(e composerEntry) bool { return strings.Contains(e.installPath, "wp-content/plugins") }) {
				t.Fatal("missing custom path")
			}
			if name == "composer1" && slices.ContainsFunc(entries, func(e composerEntry) bool { return e.pathProvided || e.pkg.DependencyKind != "unknown" }) {
				t.Fatal("legacy attribution")
			}
		})
	}
}
func TestComposerAlternateLockNames(t *testing.T) {
	for input, want := range map[string]string{"composer.json": "composer.lock", "backend.json": "backend.lock", "deps.manifest": "deps.manifest.lock"} {
		if got := composerLockPath(input); got != want {
			t.Errorf("%s -> %s", input, got)
		}
	}
}

func TestComposerMetadataMalformedMetapackagePath(t *testing.T) {
	entries, partial, err := parseComposerPackages([]byte(`{"packages":[{"name":"example/meta","version":"1","type":"metapackage","install-path":"../bad"}]}`), true)
	if err != nil || !partial || len(entries) != 1 || entries[0].installPath != "" {
		t.Fatal("malformed metapackage path could invalidate the whole inventory")
	}
}

func TestComposerManifestPlatformNamesAndVendorNamespaces(t *testing.T) {
	m, err := parseComposerManifest([]byte(`{"require":{"php":"^8","php-64bit":"^8","php-ipv6":"^8","php-zts":"^8","php-debug":"^8","composer":"^2","composer-plugin-api":"^2","composer-runtime-api":"^2","ext-json":"*","lib-curl":"*","ext-example/lib":"^1","lib-example/lib":"^1","php-example/lib":"^1","composer-example/lib":"^1"}}`))
	if err != nil || m.partial || len(m.packages) != 4 {
		t.Fatalf("platform requirements affected package enumeration: %+v, %v", m, err)
	}
	for _, p := range m.packages {
		if !strings.Contains(p.PackageName, "/") {
			t.Fatal("platform emitted as package")
		}
	}
}
