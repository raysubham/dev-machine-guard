package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

type coordinatorFetcher struct {
	policy EffectivePolicy
	calls  int
}

type coordinatorUserExecutor struct {
	*executor.Mock
	user *user.User
}

func (e *coordinatorUserExecutor) CurrentUser() (*user.User, error)  { return e.user, nil }
func (e *coordinatorUserExecutor) LoggedInUser() (*user.User, error) { return e.user, nil }
func (e *coordinatorUserExecutor) RunAsUser(ctx context.Context, username, command string) (string, error) {
	if strings.Contains(command, "XDG_CONFIG_HOME") && strings.Contains(command, "PIP_CONFIG_FILE") {
		return "", nil
	}
	return e.Mock.RunAsUser(ctx, username, command)
}

func (f *coordinatorFetcher) Fetch(_ context.Context, _, _, category, target string) (EffectivePolicy, error) {
	f.calls++
	if category != CategoryPackageConfig || target != TargetPyPI {
		return EffectivePolicy{}, errors.New("wrong policy identity")
	}
	return f.policy, nil
}

type coordinatorReporter struct {
	reports []ComplianceReport
}

func (r *coordinatorReporter) Report(_ context.Context, _, _ string, report ComplianceReport) error {
	r.reports = append(r.reports, report)
	return nil
}

type coordinatorWriter struct {
	name            string
	events          *[]string
	value           string
	present         bool
	static          bool
	mdm             bool
	mdmUnowned      bool
	writeErr        error
	clearErr        error
	observeErr      error
	restores        int
	override        string
	snapshotValue   string
	snapshotPresent bool
	snapshotStatic  bool
}

func (w *coordinatorWriter) Read() (string, bool, error) { return w.value, w.present, nil }

func (w *coordinatorWriter) Write(value string) (string, error) {
	*w.events = append(*w.events, w.name+":write")
	if w.writeErr != nil {
		return "", w.writeErr
	}
	w.snapshotValue, w.snapshotPresent, w.snapshotStatic = w.value, w.present, w.static
	w.value, w.present, w.static = value, true, true
	return value, nil
}

func (w *coordinatorWriter) Clear() (bool, error) {
	*w.events = append(*w.events, w.name+":clear")
	if w.clearErr != nil {
		return false, w.clearErr
	}
	changed := w.present
	w.value, w.present, w.static = "", false, false
	return changed, nil
}

func (w *coordinatorWriter) Location() string { return w.name }

func (w *coordinatorWriter) converged(expected string) (bool, error) {
	return w.present && w.value == expected, nil
}

func (w *coordinatorWriter) staticConverged(string) (bool, error) {
	return w.static, nil
}

func (w *coordinatorWriter) restore() error {
	w.restores++
	*w.events = append(*w.events, w.name+":restore")
	w.value, w.present, w.static = w.snapshotValue, w.snapshotPresent, w.snapshotStatic
	return nil
}

func (w *coordinatorWriter) observation(client PyPIClient, registryURL, expected string) (componentObservation, error) {
	if w.observeErr != nil {
		return componentObservation{}, w.observeErr
	}
	if client == "" {
		status := authTokenAbsent
		if w.present {
			status = authTokenMismatch
		}
		if w.static && w.value == expected {
			status = authTokenMatch
		}
		return componentObservation{credential: status}, nil
	}
	status := "absent"
	if w.static {
		status = "match"
	}
	effective, source := "not_installed", "none"
	if w.override != "" {
		effective, source = "mismatch", w.override
	}
	return componentObservation{client: &PyPIClientObservation{
		RegistryURL:     registryURL,
		ConfigStatus:    status,
		EffectiveStatus: effective,
		OverrideSource:  source,
	}}, nil
}

type coordinatorFixture struct {
	events     []string
	credential *coordinatorWriter
	pip        *coordinatorWriter
	uv         *coordinatorWriter
}

func newCoordinatorFixture() *coordinatorFixture {
	f := &coordinatorFixture{}
	f.credential = &coordinatorWriter{name: "credential", events: &f.events}
	f.pip = &coordinatorWriter{name: "pip", events: &f.events}
	f.uv = &coordinatorWriter{name: "uv", events: &f.events}
	return f
}

func (f *coordinatorFixture) components(policy PyPIPolicy) *pypiComponents {
	return &pypiComponents{
		credential: fakeCoordinatorComponent("credential", PyPICredentialOwnershipTarget, PyPICredentialOwnershipValue, policy.DeviceToken(), f.credential, "", policy.RegistryURL),
		pip:        fakeCoordinatorComponent("pip", PyPIPipOwnershipTarget, "", "pip-settings:"+policy.RegistryURL, f.pip, PyPIClientPip, policy.RegistryURL),
		uv:         fakeCoordinatorComponent("uv", PyPIUVOwnershipTarget, "", "uv-settings:"+policy.RegistryURL, f.uv, PyPIClientUV, policy.RegistryURL),
	}
}

func fakeCoordinatorComponent(name, ownershipTarget, ownershipValue, expected string, writer *coordinatorWriter, client PyPIClient, registryURL string) *pypiComponent {
	return &pypiComponent{
		name:                name,
		ownershipTarget:     ownershipTarget,
		ownershipKey:        name,
		ownershipStateValue: ownershipValue,
		writer:              writer,
		expected:            expected,
		converged:           writer.converged,
		restoreSnapshot:     writer.restore,
		hasMDMMarker:        func() (bool, error) { return writer.mdm, nil },
		mdmOwned:            func() (bool, error) { return writer.mdm && !writer.mdmUnowned, nil },
		staticConverged:     writer.staticConverged,
		observe: func(context.Context) (componentObservation, error) {
			return writer.observation(client, registryURL, expected)
		},
	}
}

func coordinatorPolicy(clients string, hash string, enforcement string) EffectivePolicy {
	return EffectivePolicy{
		Category:    CategoryPackageConfig,
		Target:      TargetPyPI,
		Policy:      json.RawMessage(`{"ecosystem":"pypi","clients":` + clients + `,"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"tenant-secret"}}`),
		Hash:        hash,
		Enforcement: enforcement,
	}
}

func newTestCoordinator(t *testing.T, policy EffectivePolicy, fixture *coordinatorFixture) (*PyPICoordinator, *coordinatorFetcher, *coordinatorReporter) {
	t.Helper()
	withTempCache(t)
	fetcher := &coordinatorFetcher{policy: policy}
	reporter := &coordinatorReporter{}
	coordinator := &PyPICoordinator{
		Fetcher:    fetcher,
		Reporter:   reporter,
		Exec:       executor.NewMock(),
		CustomerID: "cust",
		DeviceID:   "DEVICE-123",
		Platform:   "linux",
		buildComponents: func(_ context.Context, _ executor.Executor, parsed PyPIPolicy) (*pypiComponents, error) {
			return fixture.components(parsed), nil
		},
	}
	return coordinator, fetcher, reporter
}

func TestPyPICoordinator_FetchesOnceAndMissingPolicyIsNoOp(t *testing.T) {
	fixture := newCoordinatorFixture()
	coordinator, fetcher, reporter := newTestCoordinator(t, EffectivePolicy{}, fixture)
	coordinator.buildComponents = func(context.Context, executor.Executor, PyPIPolicy) (*pypiComponents, error) {
		t.Fatal("components constructed for absent policy")
		return nil, nil
	}

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if fetcher.calls != 1 || len(reporter.reports) != 0 || len(fixture.events) != 0 {
		t.Fatalf("calls=%d reports=%d events=%v, want one fetch and no side effects", fetcher.calls, len(reporter.reports), fixture.events)
	}
}

func TestPyPICoordinator_ComponentOrdering(t *testing.T) {
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
	tests := []struct {
		name        string
		policy      EffectivePolicy
		configure   func(*coordinatorFixture)
		wantEvents  string
		wantErr     bool
		wantReports int
		wantState   string
		wantApplied string
	}{
		{
			name:       "credential then pip then uv",
			policy:     coordinatorPolicy(`["pip","uv"]`, "sha256:H", enforcementDMG),
			wantEvents: "credential:write,pip:write,uv:write", wantReports: 1,
			wantState: StateCompliant, wantApplied: "sha256:H",
		},
		{
			name:       "credential failure skips clients",
			policy:     coordinatorPolicy(`["pip","uv"]`, "sha256:H", enforcementDMG),
			configure:  func(f *coordinatorFixture) { f.credential.writeErr = errors.New("credential write failed") },
			wantEvents: "credential:write", wantErr: true, wantReports: 1, wantState: StateWriteFailed,
		},
		{
			name:       "unselected uv clears before selected pip",
			policy:     coordinatorPolicy(`["pip"]`, "sha256:H", enforcementDMG),
			configure:  func(f *coordinatorFixture) { f.uv.present, f.uv.static = true, true },
			wantEvents: "credential:write,uv:clear,pip:write", wantReports: 1,
			wantState: StateCompliant, wantApplied: "sha256:H",
		},
		{
			name:       "explicit clear continues after error",
			policy:     clear,
			configure:  func(f *coordinatorFixture) { f.pip.clearErr = errors.New("pip clear failed") },
			wantEvents: "pip:clear,uv:clear,credential:clear", wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCoordinatorFixture()
			if tc.configure != nil {
				tc.configure(fixture)
			}
			coordinator, fetcher, reporter := newTestCoordinator(t, tc.policy, fixture)
			err := coordinator.Reconcile(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile error = %v, wantErr %v", err, tc.wantErr)
			}
			if got := strings.Join(fixture.events, ","); got != tc.wantEvents {
				t.Fatalf("events = %q, want %q", got, tc.wantEvents)
			}
			if fetcher.calls != 1 || len(reporter.reports) != tc.wantReports {
				t.Fatalf("fetches=%d reports=%d, want 1 and %d", fetcher.calls, len(reporter.reports), tc.wantReports)
			}
			if tc.wantReports == 1 {
				report := reporter.reports[0]
				if report.Target != TargetPyPI || report.State != tc.wantState || report.AppliedHash != tc.wantApplied || report.EvaluatedHash != "sha256:H" {
					t.Fatalf("report = %+v", report)
				}
			}
		})
	}
}

func TestPyPICoordinator_ExplicitClearWithoutTargetUserFailsWithoutReport(t *testing.T) {
	fixture := newCoordinatorFixture()
	policy := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
	coordinator, _, reporter := newTestCoordinator(t, policy, fixture)
	coordinator.buildComponents = func(context.Context, executor.Executor, PyPIPolicy) (*pypiComponents, error) {
		return nil, ErrNoTargetUser
	}

	if err := coordinator.Reconcile(context.Background()); !errors.Is(err, ErrNoTargetUser) {
		t.Fatalf("Reconcile error = %v, want ErrNoTargetUser", err)
	}
	if len(reporter.reports) != 0 || len(fixture.events) != 0 {
		t.Fatalf("reports=%d events=%v, want failed clear without side effects", len(reporter.reports), fixture.events)
	}
}

func TestPyPICoordinator_MDMRequiresEverySelectedMarker(t *testing.T) {
	tests := []struct {
		name          string
		credentialMDM bool
		pipMDM        bool
		unowned       bool
		wantState     string
		wantAuth      string
		wantPip       string
	}{
		{"all MDM-owned", true, true, false, StateMDMManaged, authTokenMatch, "match"},
		{"unrelated credential marker", true, true, true, StatePolicyNotApplied, authTokenMismatch, "match"},
		{"credential only", true, false, false, StatePolicyNotApplied, authTokenMatch, "mismatch"},
		{"pip only", false, true, false, StatePolicyNotApplied, authTokenMismatch, "match"},
		{"equivalent unowned configuration", false, false, false, StatePolicyNotApplied, authTokenMismatch, "mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			effective := coordinatorPolicy(`["pip"]`, "sha256:MDM", enforcementMDM)
			policy, err := ParsePyPIPolicy(effective.Policy, "DEVICE-123")
			if err != nil {
				t.Fatal(err)
			}
			fixture := newCoordinatorFixture()
			fixture.credential.present, fixture.credential.static = true, true
			fixture.credential.value, fixture.credential.mdm = policy.DeviceToken(), tc.credentialMDM
			fixture.credential.mdmUnowned = tc.unowned
			fixture.pip.static, fixture.pip.mdm = true, tc.pipMDM
			coordinator, _, reporter := newTestCoordinator(t, effective, fixture)
			if err := coordinator.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(reporter.reports) != 1 || reporter.reports[0].State != tc.wantState {
				t.Fatalf("reports = %+v, want state %s", reporter.reports, tc.wantState)
			}
			var observed PyPIObserved
			if err := json.Unmarshal(reporter.reports[0].Observed, &observed); err != nil {
				t.Fatal(err)
			}
			if observed.AuthTokenStatus != tc.wantAuth || observed.Clients[string(PyPIClientPip)].ConfigStatus != tc.wantPip {
				t.Fatalf("observed = %+v, want auth=%s pip=%s", observed, tc.wantAuth, tc.wantPip)
			}
		})
	}
}

func TestPyPICoordinator_MDMRouting(t *testing.T) {
	tests := []struct {
		name        string
		clients     string
		hash        string
		enforcement string
		marker      string
		static      bool
		initFailure bool
		wantErr     bool
		wantState   string
	}{
		{name: "credential marker", clients: `["pip","uv"]`, hash: "sha256:H", enforcement: enforcementDMG, marker: "credential", wantState: StatePolicyNotApplied},
		{name: "pip marker", clients: `["pip","uv"]`, hash: "sha256:H", enforcement: enforcementDMG, marker: "pip", wantState: StatePolicyNotApplied},
		{name: "uv marker", clients: `["pip","uv"]`, hash: "sha256:H", enforcement: enforcementDMG, marker: "uv", wantState: StatePolicyNotApplied},
		{name: "verify only", clients: `["pip","uv"]`, hash: "sha256:MDM", enforcement: enforcementMDM, marker: "all", static: true, wantState: StateMDMManaged},
		{name: "case insensitive", clients: `["pip"]`, hash: "sha256:MDM", enforcement: " MDM ", marker: "all", static: true, wantState: StateMDMManaged},
		{name: "component init failure", clients: `["pip"]`, hash: "sha256:MDM", enforcement: enforcementMDM, initFailure: true, wantErr: true, wantState: StateVerificationFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCoordinatorFixture()
			if tc.static {
				fixture.credential.static, fixture.pip.static, fixture.uv.static = true, true, true
			}
			switch tc.marker {
			case "credential":
				fixture.credential.mdm = true
			case "pip":
				fixture.pip.mdm = true
			case "uv":
				fixture.uv.mdm = true
			case "all":
				fixture.credential.mdm, fixture.pip.mdm, fixture.uv.mdm = true, true, true
			}
			coordinator, _, reporter := newTestCoordinator(t, coordinatorPolicy(tc.clients, tc.hash, tc.enforcement), fixture)
			if tc.initFailure {
				coordinator.buildComponents = func(_ context.Context, _ executor.Executor, policy PyPIPolicy) (*pypiComponents, error) {
					components := fixture.components(policy)
					components.credential = &pypiComponent{name: "credential", ownershipTarget: PyPICredentialOwnershipTarget, ownershipKey: pypiCredentialOwnershipKey, initErr: ErrNoTargetUser, expected: policy.DeviceToken()}
					return components, nil
				}
			}

			err := coordinator.Reconcile(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile error = %v, wantErr %v", err, tc.wantErr)
			}
			if len(fixture.events) != 0 {
				t.Fatalf("MDM wrote: %v", fixture.events)
			}
			if len(reporter.reports) != 1 {
				t.Fatalf("reports = %+v", reporter.reports)
			}
			report := reporter.reports[0]
			if report.State != tc.wantState || report.AppliedHash != "" || report.EvaluatedHash != tc.hash || report.EvaluatedEnforcement != canonicalEnforcement(tc.enforcement) {
				t.Fatalf("report = %+v", report)
			}
		})
	}
}

func TestAggregatePyPIState_Precedence(t *testing.T) {
	tests := []struct {
		name   string
		states []string
		want   string
	}{
		{"all compliant", []string{StateCompliant, StateCompliant}, StateCompliant},
		{"drift", []string{StateCompliant, StateDriftDetected}, StateDriftDetected},
		{"policy not applied over drift", []string{StateDriftDetected, StatePolicyNotApplied}, StatePolicyNotApplied},
		{"write over policy", []string{StatePolicyNotApplied, StateWriteFailed}, StateWriteFailed},
		{"verification over write", []string{StateWriteFailed, StateVerificationFailed}, StateVerificationFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := make([]componentResult, len(tc.states))
			for i, state := range tc.states {
				results[i].state = state
			}
			if got := aggregatePyPIState(results); got != tc.want {
				t.Fatalf("aggregatePyPIState(%v) = %q, want %q", tc.states, got, tc.want)
			}
		})
	}
}

func TestPyPICoordinator_UnsupportedUVReportsPolicyNotApplied(t *testing.T) {
	fixture := newCoordinatorFixture()
	fixture.uv.writeErr = errUVUnsupportedVersion
	coordinator, _, reporter := newTestCoordinator(t, coordinatorPolicy(`["uv"]`, "sha256:H", enforcementDMG), fixture)

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile error = %v, want nil for expected unsupported uv", err)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StatePolicyNotApplied || reporter.reports[0].AppliedHash != "" {
		t.Fatalf("reports = %+v", reporter.reports)
	}
}

func TestPyPICoordinator_ComponentInspectionFailureDoesNotBlockSibling(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*pypiComponents)
	}{
		{
			name: "initialization failure",
			configure: func(components *pypiComponents) {
				components.uv.initErr = errors.New("uv initialization failed")
			},
		},
		{
			name: "marker inspection failure",
			configure: func(components *pypiComponents) {
				components.uv.hasMDMMarker = func() (bool, error) {
					return false, errors.New("uv marker inspection failed")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCoordinatorFixture()
			coordinator, _, reporter := newTestCoordinator(t, coordinatorPolicy(`["pip","uv"]`, "sha256:H", enforcementDMG), fixture)
			coordinator.buildComponents = func(_ context.Context, _ executor.Executor, policy PyPIPolicy) (*pypiComponents, error) {
				components := fixture.components(policy)
				tc.configure(components)
				return components, nil
			}

			if err := coordinator.Reconcile(context.Background()); err == nil {
				t.Fatal("Reconcile error = nil, want component failure")
			}
			if got := strings.Join(fixture.events, ","); got != "credential:write,pip:write" {
				t.Fatalf("events = %q, want successful sibling enforcement", got)
			}
			if !fixture.pip.static || !fixture.pip.present {
				t.Fatal("successful pip enforcement was suppressed")
			}
			if len(reporter.reports) != 1 || reporter.reports[0].State != StateVerificationFailed || reporter.reports[0].AppliedHash != "" {
				t.Fatalf("reports = %+v", reporter.reports)
			}
		})
	}
}

func TestPyPICoordinator_PartialSuccessRetainsSiblingAndOmitsAppliedHash(t *testing.T) {
	fixture := newCoordinatorFixture()
	fixture.uv.writeErr = errors.New("uv failed")
	coordinator, _, reporter := newTestCoordinator(t, coordinatorPolicy(`["pip","uv"]`, "sha256:H", enforcementDMG), fixture)

	if err := coordinator.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile error = nil, want uv error")
	}
	if !fixture.pip.static || !fixture.pip.present {
		t.Fatal("successful pip enforcement was rolled back")
	}
	if fixture.credential.restores != 0 {
		t.Fatal("credential rolled back despite a statically converged client")
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StateWriteFailed || reporter.reports[0].AppliedHash != "" {
		t.Fatalf("reports = %+v", reporter.reports)
	}
}

func TestPyPICoordinator_CredentialRollbackRules(t *testing.T) {
	t.Run("new credential rolls back when no client converges", func(t *testing.T) {
		fixture := newCoordinatorFixture()
		fixture.pip.writeErr = errors.New("pip failed")
		fixture.uv.writeErr = errors.New("uv failed")
		coordinator, _, _ := newTestCoordinator(t, coordinatorPolicy(`["pip","uv"]`, "sha256:H", enforcementDMG), fixture)
		if err := coordinator.Reconcile(context.Background()); err == nil {
			t.Fatal("Reconcile error = nil")
		}
		if fixture.credential.restores != 1 || fixture.credential.present {
			t.Fatalf("credential restores=%d present=%v, want one restore and absent", fixture.credential.restores, fixture.credential.present)
		}
		if _, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget); ok {
			t.Fatal("rolled-back credential ownership remains")
		}
	})

	t.Run("rotation rollback restores prior credential ownership", func(t *testing.T) {
		fixture := newCoordinatorFixture()
		fixture.credential.value = "old-secret::dev:DEVICE-123"
		fixture.credential.present, fixture.credential.static = true, true
		fixture.pip.writeErr = errors.New("pip failed")
		coordinator, _, _ := newTestCoordinator(t, coordinatorPolicy(`["pip"]`, "sha256:NEW", enforcementDMG), fixture)
		prior := AppliedTargetState{
			AppliedHash:     "sha256:OLD",
			WrittenSettings: map[string]string{pypiCredentialOwnershipKey: PyPICredentialOwnershipValue},
		}
		if err := WriteAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget, prior); err != nil {
			t.Fatal(err)
		}

		if err := coordinator.Reconcile(context.Background()); err == nil {
			t.Fatal("Reconcile error = nil")
		}
		if fixture.credential.value != "old-secret::dev:DEVICE-123" || fixture.credential.restores != 1 {
			t.Fatalf("credential value=%q restores=%d, want old credential restored", fixture.credential.value, fixture.credential.restores)
		}
		state, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget)
		if !ok || state.AppliedHash != prior.AppliedHash || state.WrittenSettings[pypiCredentialOwnershipKey] != PyPICredentialOwnershipValue {
			t.Fatalf("credential ownership = %+v ok=%v, want prior state", state, ok)
		}
	})

	t.Run("static client with environment override retains credential", func(t *testing.T) {
		fixture := newCoordinatorFixture()
		fixture.pip.override = "environment"
		coordinator, _, reporter := newTestCoordinator(t, coordinatorPolicy(`["pip"]`, "sha256:H", enforcementDMG), fixture)
		if err := coordinator.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if fixture.credential.restores != 0 || !fixture.credential.present {
			t.Fatal("credential not retained for matching static configuration")
		}
		if reporter.reports[0].State != StatePolicyNotApplied || reporter.reports[0].AppliedHash != "" {
			t.Fatalf("report = %+v", reporter.reports[0])
		}
	})

	t.Run("already serving credential survives later client failure", func(t *testing.T) {
		fixture := newCoordinatorFixture()
		fixture.credential.value = "tenant-secret::dev:DEVICE-123"
		fixture.credential.present, fixture.credential.static = true, true
		fixture.pip.writeErr = errors.New("pip failed")
		coordinator, _, _ := newTestCoordinator(t, coordinatorPolicy(`["pip"]`, "sha256:H", enforcementDMG), fixture)
		if err := coordinator.Reconcile(context.Background()); err == nil {
			t.Fatal("Reconcile error = nil")
		}
		if fixture.credential.restores != 0 || !fixture.credential.present {
			t.Fatal("already-serving credential was rolled back")
		}
	})
}

func TestPyPICoordinator_StateAndReportRemainSecretFreeAcrossLifecycle(t *testing.T) {
	fixture := newCoordinatorFixture()
	policy := coordinatorPolicy(`["pip","uv"]`, "sha256:OLD", enforcementDMG)
	coordinator, fetcher, reporter := newTestCoordinator(t, policy, fixture)

	assertSecretFree := func(forbidden ...string) {
		t.Helper()
		state, err := os.ReadFile(CachePath())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		reports, err := json.Marshal(reporter.reports)
		if err != nil {
			t.Fatal(err)
		}
		combined := append(append([]byte(nil), state...), reports...)
		for _, secret := range forbidden {
			if bytes.Contains(combined, []byte(secret)) {
				t.Fatalf("state/report leaked %q: %s", secret, combined)
			}
		}
		if bytes.Contains(reports, []byte(PyPICredentialOwnershipTarget)) || bytes.Contains(reports, []byte(PyPIPipOwnershipTarget)) || bytes.Contains(reports, []byte(PyPIUVOwnershipTarget)) {
			t.Fatalf("component ownership target entered report: %s", reports)
		}
	}

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSecretFree("tenant-secret", "::dev:")

	fixture.credential.value = "tampered"
	fixture.credential.static = false
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSecretFree("tenant-secret", "::dev:")

	fetcher.policy = coordinatorPolicy(`["pip","uv"]`, "sha256:NEW", enforcementDMG)
	fetcher.policy.Policy = bytes.Replace(fetcher.policy.Policy, []byte("tenant-secret"), []byte("rotated-secret"), 1)
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSecretFree("tenant-secret", "rotated-secret", "::dev:")

	fetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSecretFree("tenant-secret", "rotated-secret", "::dev:")
}

func TestBuildPyPIComponents_SharesResolvedUserExecutor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("resolved-user shell wrapping is Unix-only")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(true)
	mock.SetHomeDir(homeDir)
	mock.SetUsername(current.Username)
	mock.SetAppleCLTInstalled(true)
	mock.SetCommand("/opt/homebrew/bin/pip\n", "", 0, "bash", "-c", "which 'pip'")
	mock.SetCommand("pip 25.2 from /opt/homebrew/lib/python/site-packages/pip\n", "", 0, "bash", "-c", "'pip' '--version'")
	mock.SetCommand("user:\n", "", 0, "bash", "-c", "'pip' 'config' 'debug'")
	mock.SetCommand("/opt/homebrew/bin/uv\n", "", 0, "bash", "-c", "which 'uv'")
	mock.SetCommand("uv 0.10.0\n", "", 0, "bash", "-c", "'uv' '--version'")
	exec := &coordinatorUserExecutor{Mock: mock, user: &user.User{Username: current.Username, Uid: current.Uid, Gid: current.Gid, HomeDir: homeDir}}

	components, err := buildPyPIComponents(context.Background(), exec, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = components.close() }()
	pip := components.pip.writer.(*PipWriter)
	uv := components.uv.writer.(*UVWriter)
	if components.credential.mdmOwned == nil || components.pip.mdmOwned == nil || components.uv.mdmOwned == nil {
		t.Fatal("components are missing strict MDM ownership probes")
	}
	if pip.exec != uv.exec {
		t.Fatalf("pip executor %p and uv executor %p differ", pip.exec, uv.exec)
	}
	if _, ok := pip.exec.(*executor.UserAwareExecutor); !ok {
		t.Fatalf("shared executor = %T, want *executor.UserAwareExecutor", pip.exec)
	}
	if len(pip.invocations) == 0 || !uv.installed {
		t.Fatalf("resolved-user discovery missed clients: pip=%d uv=%v", len(pip.invocations), uv.installed)
	}
}
