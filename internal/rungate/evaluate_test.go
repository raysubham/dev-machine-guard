package rungate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// pointGateAt routes Evaluate's check-in to srv and clears the environment
// escapes, so each test states the escapes it wants.
func pointGateAt(t *testing.T, srv *httptest.Server) {
	t.Helper()
	prevEndpoint, prevKey, prevCustomer := config.APIEndpoint, config.APIKey, config.CustomerID
	config.APIEndpoint, config.APIKey, config.CustomerID = srv.URL, "test-key", "acme"
	t.Cleanup(func() { config.APIEndpoint, config.APIKey, config.CustomerID = prevEndpoint, prevKey, prevCustomer })
	t.Setenv("STEPSEC_FORCE_SCAN", "")
	t.Setenv("STEPSEC_DISABLE_RUN_GATE", "")
}

// seedCache leaves a prior run's cache with a known device id (so Evaluate
// never probes the serial) and the given credential setting.
func seedCache(t *testing.T, credentialScanning *bool) {
	t.Helper()
	if err := recordCheckin("SER-CACHED", Directive{Mode: ModeFull, GatingEnabled: true, EffectiveIntervalMinutes: 240},
		credentialScanning, time.Unix(1_753_160_800, 0)); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
}

func staticServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
}

func evaluate(t *testing.T, forceScan bool) Result {
	t.Helper()
	return Evaluate(context.Background(), executor.NewMock(), progress.NewNoop(), forceScan, "")
}

func storedSetting(t *testing.T) *bool {
	t.Helper()
	st, ok := readState()
	if !ok {
		t.Fatal("state unreadable")
	}
	return st.CredentialScanning()
}

func TestEvaluateResolvesCredentialSetting(t *testing.T) {
	const full = `{"scan_directive":{"mode":"full","reason":"due","gating_enabled":true,"effective_interval_minutes":240}`
	for _, tt := range []struct {
		name         string
		cached       *bool
		body         string
		status       int
		wantDisabled bool
		wantStored   *bool
	}{
		{name: "fresh false, no cache", body: full + `,"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "fresh true over cached false", cached: boolPtr(false), body: full + `,"scanners":{"credentials":{"enabled":true}}}`, wantStored: boolPtr(true)},
		{name: "missing key keeps cached false", cached: boolPtr(false), body: full + `}`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "null keeps cached false", cached: boolPtr(false), body: full + `,"scanners":{"credentials":{"enabled":null}}}`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "missing key keeps cached true", cached: boolPtr(true), body: full + `}`, wantStored: boolPtr(true)},
		{name: "missing key, no cache, scans", body: full + `}`},
		{name: "wrong type keeps cached false", cached: boolPtr(false), body: full + `,"scanners":{"credentials":{"enabled":"false"}}}`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "malformed body keeps cached false", cached: boolPtr(false), body: `{"scan_directive":`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "server error keeps cached false", cached: boolPtr(false), status: http.StatusInternalServerError, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "server error, no cache, scans", status: http.StatusInternalServerError},
		{name: "false without any directive", cached: boolPtr(true), body: `{"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true, wantStored: boolPtr(false)},
		{name: "skip directive still records false", body: `{"scan_directive":{"mode":"skip","reason":"not_due"},"scanners":{"credentials":{"enabled":false}}}`, wantDisabled: true, wantStored: boolPtr(false)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withTempState(t)
			seedCache(t, tt.cached)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			pointGateAt(t, srv)

			res := evaluate(t, false)
			if res.CredentialScanningDisabled != tt.wantDisabled {
				t.Fatalf("CredentialScanningDisabled = %v, want %v (reason %s)", res.CredentialScanningDisabled, tt.wantDisabled, res.Reason)
			}
			if got := storedSetting(t); (got == nil) != (tt.wantStored == nil) || (got != nil && *got != *tt.wantStored) {
				t.Fatalf("stored setting = %v, want %v", deref(got), deref(tt.wantStored))
			}
		})
	}
}

// TestEvaluateCadenceBypassesStillResolveCredentials: --force-scan,
// STEPSEC_FORCE_SCAN and STEPSEC_DISABLE_RUN_GATE win the cadence decision but
// still check in, so a fresh false is applied and a cached false is kept.
func TestEvaluateCadenceBypassesStillResolveCredentials(t *testing.T) {
	for _, tt := range []struct {
		name       string
		forceFlag  bool
		env        string
		wantReason string
	}{
		{name: "--force-scan", forceFlag: true, wantReason: "forced"},
		{name: "STEPSEC_FORCE_SCAN", env: "STEPSEC_FORCE_SCAN", wantReason: "forced"},
		{name: "STEPSEC_DISABLE_RUN_GATE", env: "STEPSEC_DISABLE_RUN_GATE", wantReason: "kill_switch"},
	} {
		t.Run(tt.name+" fresh false", func(t *testing.T) {
			withTempState(t)
			seedCache(t, nil)
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(`{"scan_directive":{"mode":"skip","reason":"not_due"},"scanners":{"credentials":{"enabled":false}}}`))
			}))
			defer srv.Close()
			pointGateAt(t, srv)
			if tt.env != "" {
				t.Setenv(tt.env, "1")
			}

			res := evaluate(t, tt.forceFlag)
			if res.Skip || res.Reason != tt.wantReason {
				t.Fatalf("result = %+v, want proceed with reason %s", res, tt.wantReason)
			}
			if hits.Load() != 1 {
				t.Fatalf("check-in calls = %d, want 1: a bypass must still resolve the setting", hits.Load())
			}
			if !res.CredentialScanningDisabled {
				t.Fatal("fresh false must apply on a bypassed run")
			}
		})
		t.Run(tt.name+" offline cached false", func(t *testing.T) {
			withTempState(t)
			seedCache(t, boolPtr(false))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
			defer srv.Close()
			pointGateAt(t, srv)
			if tt.env != "" {
				t.Setenv(tt.env, "1")
			}

			res := evaluate(t, tt.forceFlag)
			if res.Skip || res.Reason != tt.wantReason || !res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want proceed with reason %s and credentials disabled", res, tt.wantReason)
			}
		})
	}
}

// TestEvaluateNoDeviceIDKeepsCachedSetting: a cache that holds a false but no
// device id cannot check in; the early fail-open return still honours the
// cached setting.
func TestEvaluateNoDeviceIDKeepsCachedSetting(t *testing.T) {
	path := withTempState(t)
	if err := heartbeat.UpdateRunGate(path, func(rg *heartbeat.RunGate) {
		rg.Scanners = &heartbeat.RunGateScanners{}
		rg.Scanners.Credentials.Enabled = boolPtr(false)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := staticServer(`{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":true}}}`)
	defer srv.Close()
	pointGateAt(t, srv)

	// The mock executor answers no serial probe, so the device id is unusable.
	res := evaluate(t, false)
	if res.Skip || res.Reason != "no_device_id" || !res.CredentialScanningDisabled {
		t.Fatalf("result = %+v, want no_device_id fail-open with credentials disabled", res)
	}
	if got := storedSetting(t); got == nil || *got {
		t.Fatalf("stored setting = %v, want the false untouched", deref(got))
	}
}

// TestEvaluateFreshFalseAppliesWhenPersistenceFails: the answer governs this
// invocation even when the cache cannot be written; only offline memory is lost.
func TestEvaluateFreshFalseAppliesWhenPersistenceFails(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("blocker: %v", err)
	}
	restore := SetStatePathForTest(filepath.Join(blocker, "last-run.json"))
	t.Cleanup(restore)
	srv := staticServer(`{"scan_directive":{"mode":"full"},"scanners":{"credentials":{"enabled":false}}}`)
	defer srv.Close()
	pointGateAt(t, srv)

	// No cache means no device id; give the mock a serial to probe.
	exec := executor.NewMock()
	exec.SetGOOS("darwin")
	exec.SetCommand(`    "IOPlatformSerialNumber" = "SER-PROBED"`, "", 0, "ioreg", "-l")

	res := Evaluate(context.Background(), exec, progress.NewNoop(), false, "")
	if res.Skip || !res.CredentialScanningDisabled {
		t.Fatalf("result = %+v, want proceed with credentials disabled", res)
	}
	if _, ok := readState(); ok {
		t.Fatal("state must not have been written past the blocker")
	}
}

func TestEvaluateUnusableCacheScans(t *testing.T) {
	for name, body := range map[string]string{
		"corrupt": "not json{{",
		"future":  `{"schema_version": 99, "run_gate": {"device_id": "SER", "credential_scanning_enabled": false}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := withTempState(t)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
			defer srv.Close()
			pointGateAt(t, srv)

			if res := evaluate(t, false); res.CredentialScanningDisabled {
				t.Fatalf("result = %+v, want credentials enabled with no usable cache", res)
			}
		})
	}
}
