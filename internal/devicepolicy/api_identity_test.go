package devicepolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
)

// newPolicyFetchServer is a fetch server that asserts the request carries the
// EXPECTED category/target query and returns a fixed body. Unlike newFetchServer
// (pinned to ide_extension/vscode) it lets a test drive any requested pair —
// needed by the identity checks below, which turn on the (category, target) the
// RESPONSE claims versus the one the agent asked for.
func newPolicyFetchServer(t *testing.T, wantCategory, wantTarget, body string) *HTTPFetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("category"); got != wantCategory {
			t.Errorf("request category = %q, want %q", got, wantCategory)
		}
		if got := r.URL.Query().Get("target"); got != wantTarget {
			t.Errorf("request target = %q, want %q", got, wantTarget)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	f, ok := NewHTTPFetcher(ingest.Config{APIEndpoint: srv.URL, APIKey: "test-key"}, srv.Client())
	if !ok {
		t.Fatal("NewHTTPFetcher returned ok=false on valid config")
	}
	return f
}

func TestFetchRejectsMismatchedResponseCategory(t *testing.T) {
	// The agent asked for ide_extension/vscode; the response claims a DIFFERENT
	// category (backend bug, proxy/cache mixup). Enforcing it would apply the
	// wrong pair — Fetch must reject it before the reconciler ever sees it.
	body := `{"policy":{"category":"package_config","target":"vscode","clear":false,` +
		`"policy":{"x":true},"hash":"sha256:h","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil || !strings.Contains(err.Error(), "category") {
		t.Fatalf("mismatched response category must error, got %v", err)
	}
}

func TestFetchRejectsMismatchedResponseTarget(t *testing.T) {
	// Category matches but the response targets a different IDE family — still the
	// wrong pair to act on.
	body := `{"policy":{"category":"ide_extension","target":"jetbrains","clear":false,` +
		`"policy":{"x":true},"hash":"sha256:h","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("mismatched response target must error, got %v", err)
	}
}

func TestFetchRejectsMismatchedClearDirective(t *testing.T) {
	// The most dangerous mixup: a clear:true scoped to the WRONG pair. If it
	// slipped through, the reconciler would remove an unrelated category's value.
	// The identity check fires before clear is ever surfaced as a directive.
	body := `{"policy":{"category":"package_config","target":"npm","clear":true,"generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
	_, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode)
	if err == nil {
		t.Fatal("a clear scoped to a different category/target must be rejected, not surfaced as a clear")
	}
}

func TestFetchPackageConfigTargetRoundTrips(t *testing.T) {
	// The generic fetcher carries the package_config/npm pair end to end: the
	// request query is scoped to it and a matching response parses back cleanly.
	body := `{"policy":{"category":"package_config","target":"npm","clear":false,` +
		`"policy":{"registry":"https://npm.pkg.example/"},"hash":"sha256:npm","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryPackageConfig, TargetNPM, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryPackageConfig, TargetNPM)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Category != CategoryPackageConfig || ep.Target != TargetNPM {
		t.Fatalf("round-trip identity = %q/%q, want %q/%q",
			ep.Category, ep.Target, CategoryPackageConfig, TargetNPM)
	}
	if ep.Hash != "sha256:npm" || !ep.present() {
		t.Fatalf("ep = %+v, want present with hash sha256:npm", ep)
	}
}

func TestPackageConfigPyPIIdentityRoundTrip(t *testing.T) {
	body := `{"policy":{"category":"package_config","target":"pypi","clear":false,` +
		`"policy":{"ecosystem":"pypi"},"hash":"sha256:pypi","generated_at":"x"}}`
	f := newPolicyFetchServer(t, CategoryPackageConfig, TargetPyPI, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryPackageConfig, TargetPyPI)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if ep.Category != CategoryPackageConfig || ep.Target != TargetPyPI {
		t.Fatalf("round-trip identity = %q/%q, want %q/%q",
			ep.Category, ep.Target, CategoryPackageConfig, TargetPyPI)
	}
}

func TestComplianceReportOmitsEmptyEvaluatedHash(t *testing.T) {
	raw, err := json.Marshal(ComplianceReport{Category: CategoryPackageConfig, Target: TargetNPM})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["evaluated_hash"]; ok {
		t.Fatalf("empty evaluated_hash must be omitted: %s", raw)
	}
}

func TestComplianceReportIncludesEvaluatedHashWhenSet(t *testing.T) {
	raw, err := json.Marshal(ComplianceReport{
		Category:      CategoryPackageConfig,
		Target:        TargetPyPI,
		EvaluatedHash: "sha256:pypi",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if got := string(fields["evaluated_hash"]); got != `"sha256:pypi"` {
		t.Fatalf("evaluated_hash = %s, want %q", got, "sha256:pypi")
	}
}

// ---------------------------------------------------------------------------
// Category-gated policy validation
// ---------------------------------------------------------------------------

func TestFetchAcceptsNPMPolicyWithoutIDEKeys(t *testing.T) {
	// `policy` travels raw because its shape is per-category. The ide_extension
	// structural check (extensions.allowed present and an object) must therefore be
	// GATED on the category: a legitimate package_config object has no such key and
	// must not be rejected by it. The npm structure is validated downstream by
	// RenderNPMRCBlock.
	body := `{"policy":{"category":"package_config","target":"npm","clear":false,` +
		`"policy":{"ecosystem":"npm","registry_url":"https://t.registry.stepsecurity.io/javascript",` +
		`"auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"}},` +
		`"hash":"sha256:n","enforcement":"mdm","generated_at":"2026-07-24T00:00:00Z"}}`
	f := newPolicyFetchServer(t, CategoryPackageConfig, TargetNPM, body)
	ep, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryPackageConfig, TargetNPM)
	if err != nil {
		t.Fatalf("a valid npm policy must be accepted, got %v", err)
	}
	if !ep.present() || ep.Clear {
		t.Fatalf("npm policy must be present and non-clear, got %+v", ep)
	}
	if ep.Enforcement != "mdm" {
		t.Fatalf("enforcement = %q, want mdm", ep.Enforcement)
	}
	// The raw bytes reach the renderer untouched — never re-serialized.
	if !strings.Contains(string(ep.Policy), `"ecosystem":"npm"`) {
		t.Fatalf("policy bytes = %s, want the npm object verbatim", ep.Policy)
	}
}

func TestFetchRejectsNonObjectPolicyForEveryCategory(t *testing.T) {
	// The top-level object-shape check is category-AGNOSTIC: a string/array/scalar
	// `policy` is malformed in every lane, and a non-object written verbatim could
	// even read back "compliant".
	for _, tc := range []struct{ category, target string }{
		{CategoryIDEExtension, TargetVSCode},
		{CategoryPackageConfig, TargetNPM},
	} {
		for _, raw := range []string{`"bad"`, `[]`, `42`, `true`} {
			body := `{"policy":{"category":"` + tc.category + `","target":"` + tc.target + `","clear":false,` +
				`"policy":` + raw + `,"hash":"sha256:x","generated_at":"x"}}`
			f := newPolicyFetchServer(t, tc.category, tc.target, body)
			if _, err := f.Fetch(context.Background(), "cust", "dev-1", tc.category, tc.target); err == nil {
				t.Fatalf("%s/%s: policy %s must be an error", tc.category, tc.target, raw)
			}
		}
	}
}

func TestFetchIDEStructuralCheckStillApplies(t *testing.T) {
	// The mirror of the npm case: gating the check on the category must not weaken
	// it for ide_extension. An allowlist-missing or non-object allowlist bag still
	// errors, even though the same raw shape would be fine for npm.
	for _, settings := range []string{
		`{"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`,
		`{"extensions.allowed":"nope"}`,
		`{"extensions.allowed":[]}`,
	} {
		body := `{"policy":{"category":"ide_extension","target":"vscode","clear":false,` +
			`"policy":` + settings + `,"hash":"sha256:x","generated_at":"x"}}`
		f := newPolicyFetchServer(t, CategoryIDEExtension, TargetVSCode, body)
		if _, err := f.Fetch(context.Background(), "cust", "dev-1", CategoryIDEExtension, TargetVSCode); err == nil {
			t.Fatalf("ide settings %s must be an error", settings)
		}
	}
}
