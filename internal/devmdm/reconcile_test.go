package devmdm

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// --- fakes -----------------------------------------------------------------

type fakeFetcher struct {
	ep  EffectivePolicy
	err error
}

func (f *fakeFetcher) Fetch(_ context.Context, _, _, _ string) (EffectivePolicy, error) {
	return f.ep, f.err
}

type fakeReporter struct {
	reports []ComplianceReport
	err     error
}

func (r *fakeReporter) Report(_ context.Context, _, _ string, rep ComplianceReport) error {
	r.reports = append(r.reports, rep)
	return r.err
}

type fakeWriter struct {
	value            string
	present          bool
	readErr          error
	writeErr         error
	readbackOverride string // when set, Write returns this instead of echoing input
	writes           []string
	clears           int
	reads            int
}

func (w *fakeWriter) Read() (string, bool, error) {
	w.reads++
	return w.value, w.present, w.readErr
}

func (w *fakeWriter) Write(v string) (string, error) {
	w.writes = append(w.writes, v)
	if w.writeErr != nil {
		return "", w.writeErr
	}
	w.value, w.present = v, true
	if w.readbackOverride != "" {
		return w.readbackOverride, nil
	}
	return v, nil
}

func (w *fakeWriter) Clear() error {
	w.clears++
	w.value, w.present = "", false
	return nil
}

func (w *fakeWriter) Location() string { return "fake://policy" }

// --- helpers ---------------------------------------------------------------

func withTempCache(t *testing.T) {
	t.Helper()
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	t.Cleanup(restore)
}

func newRec(t *testing.T, ep EffectivePolicy, fetchErr error, w *fakeWriter, version string) (*Reconciler, *fakeReporter) {
	t.Helper()
	withTempCache(t)
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:       &fakeFetcher{ep: ep, err: fetchErr},
		Reporter:      rep,
		Writer:        w,
		CustomerID:    "cust",
		DeviceID:      "dev-1",
		Platform:      "linux",
		VSCodeVersion: func() string { return version },
		Now:           func() time.Time { return time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC) },
	}
	return r, rep
}

func policyEP(hash string) EffectivePolicy {
	return EffectivePolicy{
		Category:         CategoryIDEExtension,
		Clear:            false,
		Policy:           json.RawMessage(samplePolicy),
		Hash:             hash,
		MinVSCodeVersion: "1.96.0",
	}
}

func lastReport(t *testing.T, rep *fakeReporter) ComplianceReport {
	t.Helper()
	if len(rep.reports) != 1 {
		t.Fatalf("expected exactly 1 report, got %d: %+v", len(rep.reports), rep.reports)
	}
	return rep.reports[0]
}

// --- tests -----------------------------------------------------------------

func TestEnforceWritesExactPolicyAndReportsCompliant(t *testing.T) {
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("expected exact policy written once, got %v", w.writes)
	}
	got := lastReport(t, rep)
	if got.State != StateCompliant {
		t.Fatalf("state = %q, want compliant", got.State)
	}
	// applied_hash echoed verbatim (never recomputed).
	if got.AppliedHash != "sha256:H" {
		t.Fatalf("applied_hash = %q, want sha256:H", got.AppliedHash)
	}
	// Ownership recorded.
	st, ok := ReadAppliedState()
	if !ok || st.WrittenValue != samplePolicy || st.AppliedHash != "sha256:H" {
		t.Fatalf("cache = %+v ok=%v", st, ok)
	}
}

func TestEnforceIdempotentSecondRunWritesNothing(t *testing.T) {
	withTempCache(t)
	// Seed prior ownership + on-disk value matching the desired policy.
	if err := WriteAppliedState(AppliedState{Category: CategoryIDEExtension, AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: samplePolicy, present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:H")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		VSCodeVersion: func() string { return "1.96.2" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("idempotent run must not write, got %v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateCompliant {
		t.Fatalf("state = %q, want compliant", got.State)
	}
}

func TestClearRemovesAgentOwnedPolicy(t *testing.T) {
	withTempCache(t)
	if err := WriteAppliedState(AppliedState{Category: CategoryIDEExtension, AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: samplePolicy, present: true} // on-disk == what we wrote → owned
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: EffectivePolicy{Category: CategoryIDEExtension, Clear: true}},
		Reporter: rep, Writer: w, CustomerID: "c", DeviceID: "d", Platform: "linux",
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if w.clears != 1 {
		t.Fatalf("owned policy should be cleared once, clears=%d", w.clears)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("clear must not report a compliance state, got %+v", rep.reports)
	}
	if st, _ := ReadAppliedState(); st.WrittenValue != "" {
		t.Fatalf("ownership record should be dropped, got %+v", st)
	}
}

func TestClearLeavesForeignPolicy(t *testing.T) {
	withTempCache(t)
	// We recorded writing "mine", but on disk is "theirs" — an MDM/human changed it.
	if err := WriteAppliedState(AppliedState{Category: CategoryIDEExtension, WrittenValue: "mine"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "theirs", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: EffectivePolicy{Category: CategoryIDEExtension, Clear: true}},
		Reporter: rep, Writer: w, CustomerID: "c", DeviceID: "d", Platform: "linux",
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if w.clears != 0 {
		t.Fatalf("foreign policy must NOT be cleared, clears=%d", w.clears)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("clear path reports nothing, got %+v", rep.reports)
	}
}

func TestEnforceForeignValueReportsMDMManaged(t *testing.T) {
	// Cache empty (we own nothing) but a value is on disk → foreign (MDM).
	w := &fakeWriter{value: "mdm-pushed-value", present: true}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("must not overwrite a foreign value, writes=%v", w.writes)
	}
	got := lastReport(t, rep)
	if got.State != StateMDMManaged {
		t.Fatalf("state = %q, want mdm_managed", got.State)
	}
	if got.AppliedHash != "" {
		t.Fatalf("applied_hash should be empty when nothing applied, got %q", got.AppliedHash)
	}
}

func TestEnforceBelowFloorReportsVSCodeUnsupported(t *testing.T) {
	w := &fakeWriter{}
	ep := policyEP("sha256:H")
	ep.MinVSCodeVersion = "1.106.0" // Linux floor
	r, rep := newRec(t, ep, nil, w, "1.96.2")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("below-floor must not write, writes=%v", w.writes)
	}
	if w.reads != 0 {
		t.Fatalf("below-floor short-circuits before ownership read, reads=%d", w.reads)
	}
	if got := lastReport(t, rep); got.State != StateVSCodeUnsupported {
		t.Fatalf("state = %q, want vscode_unsupported", got.State)
	}
}

func TestEnforceWriteFailureReportsWriteFailed(t *testing.T) {
	w := &fakeWriter{writeErr: errors.New("access denied")}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("write failure should surface an error")
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceReadbackMismatchReportsPolicyNotApplied(t *testing.T) {
	w := &fakeWriter{readbackOverride: `{"*":true}`} // VS Code silently kept a different value
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := lastReport(t, rep); got.State != StatePolicyNotApplied {
		t.Fatalf("state = %q, want policy_not_applied", got.State)
	}
	// Ownership IS recorded even on a readback mismatch — it tracks what the
	// agent wrote, not what it verified; next-cycle recovery depends on it
	// (value-based ownership only takes effect if the value actually landed).
	if st, ok := ReadAppliedState(); !ok || st.WrittenValue != samplePolicy {
		t.Fatalf("cache must record the written value even on readback mismatch, got %+v ok=%v", st, ok)
	}
}

func TestEnforceReadbackMismatchRecoversNextCycle(t *testing.T) {
	// Cycle 1: the write lands but readback transiently mismatches →
	// policy_not_applied. Cycle 2: the on-disk value IS what we wrote; with
	// ownership recorded the agent reclaims it and reports compliant — it must
	// not classify its own write as foreign (stuck mdm_managed).
	w := &fakeWriter{readbackOverride: `{"*":true}`}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if rep.reports[0].State != StatePolicyNotApplied {
		t.Fatalf("cycle 1 state = %q, want policy_not_applied", rep.reports[0].State)
	}

	w.readbackOverride = "" // transient condition gone; disk holds our value
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(rep.reports) != 2 || rep.reports[1].State != StateCompliant {
		t.Fatalf("cycle 2 reports = %+v, want second report compliant", rep.reports)
	}
	if len(w.writes) != 1 {
		t.Fatalf("cycle 2 must be idempotent (no rewrite), writes=%v", w.writes)
	}
}

func TestEnforceReadErrorReportsVerificationFailed(t *testing.T) {
	w := &fakeWriter{readErr: errors.New("registry locked")}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("read error should surface")
	}
	if got := lastReport(t, rep); got.State != StateVerificationFailed {
		t.Fatalf("state = %q, want verification_failed", got.State)
	}
}

func TestMalformedFetchIsNoOp(t *testing.T) {
	w := &fakeWriter{value: "existing", present: true}
	r, rep := newRec(t, EffectivePolicy{}, errors.New("malformed"), w, "1.96.2")
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("fetch error should surface")
	}
	if len(w.writes) != 0 || w.clears != 0 || w.reads != 0 {
		t.Fatalf("malformed fetch must touch nothing: writes=%v clears=%d reads=%d", w.writes, w.clears, w.reads)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("malformed fetch must not report, got %+v", rep.reports)
	}
}

func TestNilWriterPlatformIsNoOp(t *testing.T) {
	withTempCache(t)
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: policyEP("sha256:H")}, // backend would actually send clear for macOS
		Reporter: rep, Writer: nil, CustomerID: "c", DeviceID: "d", Platform: "darwin",
		VSCodeVersion: func() string { return "1.99.0" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("nil-writer platform should no-op without error, got %v", err)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("unsupported platform reports nothing, got %+v", rep.reports)
	}
}

func TestEnforcePresentValueWithoutOwnershipRecordIsForeign(t *testing.T) {
	// No ownership record + ANY present value → foreign, even when it is empty
	// (a wrong-typed registry value can read back as "") or byte-equal to the
	// desired policy (an MDM pushed the same thing). Never overwrite, never adopt.
	cases := []struct {
		name  string
		value string
	}{
		{"empty value (wrong-typed registry data)", ""},
		{"value equal to desired policy", samplePolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{value: tc.value, present: true}
			r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(w.writes) != 0 || w.clears != 0 {
				t.Fatalf("foreign value must not be touched: writes=%v clears=%d", w.writes, w.clears)
			}
			if got := lastReport(t, rep); got.State != StateMDMManaged {
				t.Fatalf("state = %q, want mdm_managed", got.State)
			}
		})
	}
}

func TestEnforceStateUnwritablePreflightWritesNothing(t *testing.T) {
	// If the ownership store can't be persisted, the policy must never be
	// written: an enforced value with no record would be orphaned (a later
	// clear refuses it; the agent would misreport its own write as mdm_managed).
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	r.writeState = func(AppliedState) error { return errors.New("disk full") }
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("unwritable ownership store should surface an error")
	}
	if len(w.writes) != 0 {
		t.Fatalf("policy must NOT be written when ownership can't be recorded, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceStatePersistFailureRollsBackWrite(t *testing.T) {
	// Preflight succeeds but the post-write persist fails: the agent undoes the
	// just-written value (no prior owned value → clear) so it never leaves an
	// enforced policy it has no ownership record for.
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w, "1.96.2")
	calls := 0
	r.writeState = func(AppliedState) error {
		calls++
		if calls == 1 {
			return nil // preflight probe
		}
		return errors.New("disk full")
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("persist failure should surface an error")
	}
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("writes = %v, want exactly one write of the policy", w.writes)
	}
	if w.clears != 1 || w.present {
		t.Fatalf("rolled-back write should clear the location, clears=%d present=%v", w.clears, w.present)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceStatePersistFailureRestoresPreviousOwnedValue(t *testing.T) {
	// Same as above but a previous owned value existed: rollback restores it,
	// keeping the (intact, atomic) old state file and the disk consistent.
	withTempCache(t)
	if err := WriteAppliedState(AppliedState{Category: CategoryIDEExtension, AppliedHash: "sha256:OLD", WrittenValue: "old-value"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "old-value", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:NEW")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		VSCodeVersion: func() string { return "1.96.2" },
		Now:           func() time.Time { return time.Unix(0, 0).UTC() },
	}
	r.writeState = func(s AppliedState) error {
		if s.WrittenValue == samplePolicy {
			return errors.New("disk full") // fail only the post-write persist
		}
		return nil // preflight probe succeeds
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("persist failure should surface an error")
	}
	if len(w.writes) != 2 || w.writes[0] != samplePolicy || w.writes[1] != "old-value" {
		t.Fatalf("writes = %v, want [new policy, restored old-value]", w.writes)
	}
	if w.value != "old-value" || !w.present {
		t.Fatalf("on-disk should be restored to old-value, got %q present=%v", w.value, w.present)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforcePolicyChangeRewrites(t *testing.T) {
	withTempCache(t)
	// We own "old"; the backend now sends a new policy with a new hash.
	if err := WriteAppliedState(AppliedState{Category: CategoryIDEExtension, AppliedHash: "sha256:OLD", WrittenValue: "old-value"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "old-value", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:NEW")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		VSCodeVersion: func() string { return "1.96.2" },
		Now:           func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("owned policy change should rewrite to new value, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateCompliant || got.AppliedHash != "sha256:NEW" {
		t.Fatalf("report = %+v, want compliant + sha256:NEW", got)
	}
}
