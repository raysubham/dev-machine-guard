package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

type goCoordinatorFetcher struct {
	policy EffectivePolicy
	calls  int
}

func (f *goCoordinatorFetcher) Fetch(_ context.Context, _, _, category, target string) (EffectivePolicy, error) {
	f.calls++
	if category != CategoryPackageConfig || target != TargetGo {
		return EffectivePolicy{}, errors.New("wrong Go policy identity")
	}
	return f.policy, nil
}

type goCoordinatorFixture struct {
	events      []string
	credential  *coordinatorWriter
	env         *coordinatorWriter
	pypiSibling bool
}

func newGoCoordinatorFixture() *goCoordinatorFixture {
	f := &goCoordinatorFixture{}
	f.credential = &coordinatorWriter{name: "credential", events: &f.events}
	f.env = &coordinatorWriter{name: "go-env", events: &f.events}
	return f
}

func (f *goCoordinatorFixture) components(policy GoPolicy) *goComponents {
	credentialExpected := renderNetrcEntry(policy.RegistryHost(), policy.DeviceToken())
	credential := &goComponent{
		name: "credential", ownershipTarget: GoCredentialOwnershipTarget, ownershipKey: goCredentialOwnershipKey,
		ownershipStateValue: GoCredentialOwnershipValue, writer: f.credential, expected: credentialExpected,
		converged: f.credential.converged, restoreSnapshot: f.credential.restore,
		hasMDMMarker: func() (bool, error) { return f.credential.mdm, nil },
		mdmOwned:     func() (bool, error) { return f.credential.mdm && !f.credential.mdmUnowned, nil },
		observe: func() (goComponentObservation, error) {
			if f.credential.observeErr != nil {
				return goComponentObservation{}, f.credential.observeErr
			}
			status := authTokenAbsent
			if f.credential.present {
				status = authTokenMismatch
			}
			if f.credential.static && f.credential.value == credentialExpected {
				status = authTokenMatch
			}
			return goComponentObservation{auth: status}, nil
		},
	}
	credential.completeState = func(_ AppliedTargetState, _ bool, state *AppliedTargetState) error {
		state.RegistryHost = policy.RegistryHost()
		return nil
	}
	envExpected := "GOPROXY=" + policy.RegistryURL
	env := &goComponent{
		name: "go-env", ownershipTarget: GoEnvOwnershipTarget, ownershipKey: goEnvOwnershipKey,
		ownershipStateValue: GoEnvOwnershipValue, writer: f.env, expected: envExpected,
		converged: f.env.converged, staticConverged: f.env.staticConverged, restoreSnapshot: f.env.restore,
		hasMDMMarker: func() (bool, error) { return f.env.mdm, nil },
		mdmOwned:     func() (bool, error) { return f.env.mdm && !f.env.mdmUnowned, nil },
		observe: func() (goComponentObservation, error) {
			if f.env.observeErr != nil {
				return goComponentObservation{}, f.env.observeErr
			}
			status := "absent"
			if f.env.present {
				status = "mismatch"
			}
			if f.env.static && f.env.value == envExpected {
				status = "match"
			}
			effective, source := "mismatch", "none"
			if status == "match" {
				effective = "match"
			}
			if f.env.override != "" {
				effective, source = "mismatch", f.env.override
			}
			return goComponentObservation{env: &GoEnvObservation{RegistryURL: policy.RegistryURL, ConfigStatus: status, EffectiveStatus: effective, OverrideSource: source}}, nil
		},
	}
	return &goComponents{
		credential:           credential,
		env:                  env,
		hasPyPISibling:       func() (bool, error) { return f.pypiSibling, nil },
		hasManagedCredential: func() (bool, error) { return f.credential.present, nil },
	}
}

func goCoordinatorPolicy(hash, enforcement string) EffectivePolicy {
	return EffectivePolicy{
		Category: CategoryPackageConfig, Target: TargetGo, Hash: hash, Enforcement: enforcement,
		Policy: json.RawMessage(`{"ecosystem":"go","registry_url":"https://registry.stepsecurity.io/go","auth":{"scheme":"stepsecurity_device_token","api_key":"tenant-secret"}}`),
	}
}

func newTestGoCoordinator(t *testing.T, policy EffectivePolicy, fixture *goCoordinatorFixture) (*GoCoordinator, *goCoordinatorFetcher, *coordinatorReporter) {
	t.Helper()
	withTempCache(t)
	fetcher := &goCoordinatorFetcher{policy: policy}
	reporter := &coordinatorReporter{}
	coordinator := &GoCoordinator{
		Fetcher: fetcher, Reporter: reporter, Exec: executor.NewMock(), CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux",
		buildComponents: func(_ executor.Executor, parsed GoPolicy) (*goComponents, error) {
			return fixture.components(parsed), nil
		},
	}
	if policy.Clear {
		if err := WriteAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget, AppliedTargetState{RegistryHost: "registry.stepsecurity.io"}); err != nil {
			t.Fatal(err)
		}
	}
	return coordinator, fetcher, reporter
}

func TestGoCoordinator_FetchesOnceAndMissingPolicyIsNoOp(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	coordinator, fetcher, reporter := newTestGoCoordinator(t, EffectivePolicy{}, fixture)
	coordinator.buildComponents = func(executor.Executor, GoPolicy) (*goComponents, error) {
		t.Fatal("components constructed for absent policy")
		return nil, nil
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 1 || len(reporter.reports) != 0 || len(fixture.events) != 0 {
		t.Fatalf("fetches=%d reports=%d events=%v", fetcher.calls, len(reporter.reports), fixture.events)
	}
}

func TestGoCoordinator_ComponentOrderingAndRollback(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*goCoordinatorFixture)
		wantEvents string
		wantState  string
		wantErr    bool
	}{
		{"credential then env", nil, "credential:write,go-env:write", StateCompliant, false},
		{"credential failure skips env", func(f *goCoordinatorFixture) { f.credential.writeErr = errors.New("credential failed") }, "credential:write", StateWriteFailed, true},
		{"env failure rolls back changed credential", func(f *goCoordinatorFixture) { f.env.writeErr = errors.New("env failed") }, "credential:write,go-env:write,credential:restore", StateWriteFailed, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newGoCoordinatorFixture()
			if tc.configure != nil {
				tc.configure(fixture)
			}
			coordinator, fetcher, reporter := newTestGoCoordinator(t, goCoordinatorPolicy("sha256:H", enforcementDMG), fixture)
			err := coordinator.Reconcile(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile error = %v", err)
			}
			if got := strings.Join(fixture.events, ","); got != tc.wantEvents {
				t.Fatalf("events = %q, want %q", got, tc.wantEvents)
			}
			if fetcher.calls != 1 || len(reporter.reports) != 1 || reporter.reports[0].State != tc.wantState || reporter.reports[0].Target != TargetGo {
				t.Fatalf("fetches=%d reports=%+v", fetcher.calls, reporter.reports)
			}
			if tc.wantState == StateCompliant && reporter.reports[0].AppliedHash != "sha256:H" {
				t.Fatalf("applied hash = %q", reporter.reports[0].AppliedHash)
			}
		})
	}
}

func TestGoCoordinator_PreflightsBothComponentsBeforeCredentialMutation(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	coordinator, _, reporter := newTestGoCoordinator(t, goCoordinatorPolicy("sha256:H", enforcementDMG), fixture)
	coordinator.buildComponents = func(_ executor.Executor, policy GoPolicy) (*goComponents, error) {
		components := fixture.components(policy)
		components.env.preflight = func() error { return errors.New("unsafe Go env path") }
		return components, nil
	}
	if err := coordinator.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile error = nil")
	}
	if len(fixture.events) != 0 || len(reporter.reports) != 1 || reporter.reports[0].State != StateVerificationFailed {
		t.Fatalf("events=%v reports=%+v", fixture.events, reporter.reports)
	}
}

func TestGoCoordinator_OverrideIsPolicyNotAppliedWithoutAppliedHash(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	fixture.credential.value, fixture.credential.present, fixture.credential.static = "machine", true, true
	fixture.env.override = "environment"
	coordinator, _, reporter := newTestGoCoordinator(t, goCoordinatorPolicy("sha256:H", enforcementDMG), fixture)
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if report := reporter.reports[0]; report.State != StatePolicyNotApplied || report.AppliedHash != "" {
		t.Fatalf("report = %+v", report)
	}
}

func TestGoCoordinator_ClearRetainsSharedCredentialForPyPISibling(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	fixture.credential.present, fixture.env.present = true, true
	fixture.pypiSibling = true
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	coordinator, _, reporter := newTestGoCoordinator(t, clear, fixture)
	if err := ClearAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fixture.events, ","); got != "go-env:clear" {
		t.Fatalf("events = %q", got)
	}
	if !fixture.credential.present || len(reporter.reports) != 0 {
		t.Fatalf("credential retained=%v reports=%v", fixture.credential.present, reporter.reports)
	}
}

func TestGoCoordinator_StatelessAndRepeatedClearAreNoOps(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	coordinator, fetcher, reporter := newTestGoCoordinator(t, clear, fixture)
	if err := ClearAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := coordinator.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if fetcher.calls != 2 || len(reporter.reports) != 0 || len(fixture.events) != 2 {
		t.Fatalf("fetches=%d reports=%d events=%v", fetcher.calls, len(reporter.reports), fixture.events)
	}
	for _, event := range fixture.events {
		if event != "go-env:clear" {
			t.Fatalf("unexpected clear event %q", event)
		}
	}
}

func TestGoCoordinator_ClearFailureRetainsCredentialAndRetries(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	fixture.credential.present, fixture.env.present = true, true
	fixture.env.clearErr = errors.New("forced env clear failure")
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	coordinator, _, _ := newTestGoCoordinator(t, clear, fixture)
	if err := coordinator.Reconcile(context.Background()); err == nil {
		t.Fatal("first clear error = nil")
	}
	if !fixture.credential.present {
		t.Fatal("credential was cleared after config clear failed")
	}
	fixture.env.clearErr = nil
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.credential.present || fixture.env.present {
		t.Fatalf("retry left credential=%v env=%v", fixture.credential.present, fixture.env.present)
	}
}

func TestGoCoordinator_MDMVerificationIsWriteFree(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	fixture.credential.value = renderNetrcEntry("registry.stepsecurity.io", "tenant-secret::dev:DEVICE-123")
	fixture.credential.present, fixture.credential.static, fixture.credential.mdm = true, true, true
	fixture.env.value = goEnvExpected
	fixture.env.present, fixture.env.static, fixture.env.mdm = true, true, true
	coordinator, _, reporter := newTestGoCoordinator(t, goCoordinatorPolicy("sha256:H", enforcementMDM), fixture)
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fixture.events) != 0 || len(reporter.reports) != 1 || reporter.reports[0].State != StateMDMManaged || reporter.reports[0].AppliedHash != "" {
		t.Fatalf("events=%v reports=%+v", fixture.events, reporter.reports)
	}
}

func TestGoCoordinator_DMGYieldsToCompleteMDMOwnership(t *testing.T) {
	fixture := newGoCoordinatorFixture()
	fixture.credential.value = renderNetrcEntry("registry.stepsecurity.io", "tenant-secret::dev:DEVICE-123")
	fixture.credential.present, fixture.credential.static, fixture.credential.mdm = true, true, true
	fixture.env.value = goEnvExpected
	fixture.env.present, fixture.env.static, fixture.env.mdm = true, true, true
	coordinator, _, reporter := newTestGoCoordinator(t, goCoordinatorPolicy("sha256:H", enforcementDMG), fixture)
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fixture.events) != 0 || len(reporter.reports) != 1 || reporter.reports[0].State != StateMDMManaged || reporter.reports[0].EvaluatedEnforcement != enforcementDMG {
		t.Fatalf("events=%v reports=%+v", fixture.events, reporter.reports)
	}
}

func TestGoCoordinator_RealLifecycleIsIdempotentAndSecretFree(t *testing.T) {
	if testing.Short() {
		t.Skip("filesystem lifecycle")
	}
	withTempCache(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername(current.Username)
	mock.SetHomeDir(homeDir)
	exec := &coordinatorUserExecutor{Mock: mock, user: &user.User{Username: current.Username, Uid: current.Uid, Gid: current.Gid, HomeDir: homeDir}}
	fetcher := &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:H", enforcementDMG)}
	reporter := &coordinatorReporter{}
	coordinator := &GoCoordinator{Fetcher: fetcher, Reporter: reporter, Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux"}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var observed map[string]any
	if err := json.Unmarshal(reporter.reports[0].Observed, &observed); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 6 || observed["ecosystem"] != "go" || observed["registry_url"] != "https://registry.stepsecurity.io/go" ||
		observed["auth_token_status"] != "match" || observed["config_status"] != "match" ||
		observed["effective_status"] != "match" || observed["override_source"] != "none" {
		t.Fatalf("observed = %#v", observed)
	}
	envPath := filepath.Join(homeDir, ".config", "go", "env")
	netrcPath := filepath.Join(homeDir, ".netrc")
	before, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("idempotent cycle changed mtime: %v -> %v", before.ModTime(), after.ModTime())
	}
	if !os.SameFile(before, after) {
		t.Fatal("idempotent cycle replaced the Go env file")
	}
	state, err := os.ReadFile(CachePath())
	if err != nil {
		t.Fatal(err)
	}
	reports, _ := json.Marshal(reporter.reports)
	for _, forbidden := range [][]byte{[]byte("tenant-secret"), []byte("::dev:")} {
		if bytes.Contains(state, forbidden) || bytes.Contains(reports, forbidden) {
			t.Fatalf("state/report leaked %q", forbidden)
		}
	}
	for _, internalTarget := range [][]byte{[]byte(GoCredentialOwnershipTarget), []byte(GoEnvOwnershipTarget)} {
		if bytes.Contains(reports, internalTarget) {
			t.Fatalf("report leaked internal target %q", internalTarget)
		}
	}
	fetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{envPath, netrcPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("clear retained %s: %v", path, err)
		}
	}
	if err := filepath.WalkDir(homeDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if strings.Contains(name, ".dmg-") || strings.Contains(name, ".install") || strings.Contains(name, ".restore") {
			t.Fatalf("temporary residue remains at %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 2 {
		t.Fatalf("clear emitted a report: %d reports", len(reporter.reports))
	}
}

func TestPyPICoordinator_ClearRetainsCredentialForGoSibling(t *testing.T) {
	fixture := newCoordinatorFixture()
	fixture.credential.present, fixture.pip.present, fixture.uv.present = true, true, true
	clear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
	coordinator, _, _ := newTestCoordinator(t, clear, fixture)
	coordinator.buildComponents = func(_ context.Context, _ executor.Executor, policy PyPIPolicy) (*pypiComponents, error) {
		components := fixture.components(policy)
		components.hasGoSibling = func() (bool, error) { return true, nil }
		return components, nil
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fixture.events, ","); got != "pip:clear,uv:clear" {
		t.Fatalf("events = %q", got)
	}
	if !fixture.credential.present {
		t.Fatal("PyPI clear removed credential still used by Go")
	}
}

func TestGoCoordinator_StateFailureRestoresBothFiles(t *testing.T) {
	withTempCache(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	envPath := filepath.Join(homeDir, ".config", "go", "env")
	netrcPath := filepath.Join(homeDir, ".netrc")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initialEnv := []byte("GOPRIVATE=corp.example/*\nGOPROXY=https://proxy.golang.org\n")
	initialNetrc := []byte("machine other.example login user password pass\n")
	if err := os.WriteFile(envPath, initialEnv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netrcPath, initialNetrc, 0o600); err != nil {
		t.Fatal(err)
	}
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername(current.Username)
	exec := &coordinatorUserExecutor{Mock: mock, user: &user.User{Username: current.Username, Uid: current.Uid, Gid: current.Gid, HomeDir: homeDir}}
	reporter := &coordinatorReporter{}
	coordinator := &GoCoordinator{
		Fetcher: &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:H", enforcementDMG)}, Reporter: reporter,
		Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux",
		writeState: func(category, target string, state AppliedTargetState) error {
			if target == GoEnvOwnershipTarget {
				return errors.New("forced Go env state failure")
			}
			return WriteAppliedState(category, target, state)
		},
	}
	if err := coordinator.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile error = nil")
	}
	for path, want := range map[string][]byte{envPath: initialEnv, netrcPath: initialNetrc} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, want %q", path, got, want)
		}
	}
	for _, target := range []string{GoCredentialOwnershipTarget, GoEnvOwnershipTarget} {
		if _, ok := ReadAppliedState(CategoryPackageConfig, target); ok {
			t.Fatalf("rollback retained %s state", target)
		}
	}
	if len(reporter.reports) != 1 || reporter.reports[0].AppliedHash != "" {
		t.Fatalf("reports = %+v", reporter.reports)
	}
}

func TestGoAndPyPIShareOneNetrcBlockAcrossOrdersAndRotation(t *testing.T) {
	for _, order := range []string{"pypi-first", "go-first"} {
		t.Run(order, func(t *testing.T) {
			homeDir := t.TempDir()
			home := newSecureTestHome(t, homeDir)
			pypi := netrcTestPolicy(t)
			goPolicy, err := ParseGoPolicy(json.RawMessage(`{"ecosystem":"go","registry_url":"https://registry.stepsecurity.io/go","auth":{"scheme":"stepsecurity_device_token","api_key":"step_acme-1_uuid"}}`), "DEVICE-123")
			if err != nil {
				t.Fatal(err)
			}
			pypiWriter, err := NewNetrcWriter(home, pypi)
			if err != nil {
				t.Fatal(err)
			}
			goWriter, err := newNetrcWriter(home, goPolicy.RegistryHost(), goPolicy.DeviceToken())
			if err != nil {
				t.Fatal(err)
			}
			writers := []*NetrcWriter{pypiWriter, goWriter}
			if order == "go-first" {
				writers[0], writers[1] = writers[1], writers[0]
			}
			for _, writer := range writers {
				if _, err := writer.Write(writer.expected); err != nil {
					t.Fatal(err)
				}
			}
			content, err := os.ReadFile(writers[0].Location())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(content, []byte(dmgNetrcBegin)) != 1 || bytes.Count(content, []byte("machine registry.stepsecurity.io")) != 1 {
				t.Fatalf("shared credential duplicated:\n%s", content)
			}

			rotatedGo, err := ParseGoPolicy(json.RawMessage(`{"ecosystem":"go","registry_url":"https://registry.stepsecurity.io/go","auth":{"scheme":"stepsecurity_device_token","api_key":"rotated_key"}}`), "DEVICE-123")
			if err != nil {
				t.Fatal(err)
			}
			rotated, err := newNetrcWriter(home, rotatedGo.RegistryHost(), rotatedGo.DeviceToken())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rotated.Write(rotated.expected); err != nil {
				t.Fatal(err)
			}
			content, err = os.ReadFile(rotated.Location())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(content, []byte(dmgNetrcBegin)) != 1 || bytes.Count(content, []byte("machine registry.stepsecurity.io")) != 1 || bytes.Contains(content, []byte(pypi.DeviceToken())) {
				t.Fatalf("rotation did not converge one shared block:\n%s", content)
			}
		})
	}
}

func TestGoAndPyPISharedCredentialFinalClearAcrossRemovalOrders(t *testing.T) {
	if testing.Short() {
		t.Skip("filesystem lifecycle")
	}
	for _, first := range []string{"go", "pypi"} {
		t.Run(first+"-first", func(t *testing.T) {
			withTempCache(t)
			current, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			homeDir := t.TempDir()
			current.HomeDir = homeDir
			normalizeSecureTestUser(t, current)
			initialNetrc := []byte("machine registry.stepsecurity.io login original password original\nmachine other.example login user password pass\n")
			if err := os.WriteFile(filepath.Join(homeDir, ".netrc"), initialNetrc, 0o600); err != nil {
				t.Fatal(err)
			}
			mock := executor.NewMock()
			mock.SetGOOS("linux")
			mock.SetUsername(current.Username)
			mock.SetHomeDir(homeDir)
			exec := &coordinatorUserExecutor{Mock: mock, user: current}
			pypiFetcher := &coordinatorFetcher{policy: coordinatorPolicy(`["pip"]`, "sha256:P", enforcementDMG)}
			goFetcher := &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:G", enforcementDMG)}
			pypi := &PyPICoordinator{Fetcher: pypiFetcher, Reporter: &coordinatorReporter{}, Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux"}
			goCoordinator := &GoCoordinator{Fetcher: goFetcher, Reporter: &coordinatorReporter{}, Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux"}

			if err := pypi.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := goCoordinator.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			managed, err := os.ReadFile(filepath.Join(homeDir, ".netrc"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(managed, []byte(dmgNetrcBegin)) != 1 {
				t.Fatalf("shared credential blocks = %d, want 1", bytes.Count(managed, []byte(dmgNetrcBegin)))
			}

			pypiFetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true}
			goFetcher.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
			clearedTarget, retainedTarget := GoCredentialOwnershipTarget, PyPICredentialOwnershipTarget
			if first == "go" {
				if err := goCoordinator.Reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else {
				clearedTarget, retainedTarget = PyPICredentialOwnershipTarget, GoCredentialOwnershipTarget
				if err := pypi.Reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(filepath.Join(homeDir, ".netrc")); err != nil {
				t.Fatalf("%s-first clear removed shared credential: %v", first, err)
			}
			if _, ok := ReadAppliedState(CategoryPackageConfig, clearedTarget); ok {
				t.Fatalf("first clear retained %s state", clearedTarget)
			}
			if _, ok := ReadAppliedState(CategoryPackageConfig, retainedTarget); !ok {
				t.Fatalf("first clear removed %s state", retainedTarget)
			}
			if first == "go" {
				if err := pypi.Reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err := goCoordinator.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}

			restored, err := os.ReadFile(filepath.Join(homeDir, ".netrc"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored, initialNetrc) {
				t.Fatalf("final clear restored %q, want %q", restored, initialNetrc)
			}
			for _, target := range []string{GoCredentialOwnershipTarget, PyPICredentialOwnershipTarget} {
				if _, ok := ReadAppliedState(CategoryPackageConfig, target); ok {
					t.Fatalf("final clear retained %s state", target)
				}
			}
		})
	}
}

func TestGoCoordinatorFinalClearIgnoresMalformedPipWithoutMarker(t *testing.T) {
	if testing.Short() {
		t.Skip("filesystem lifecycle")
	}
	withTempCache(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	current.HomeDir = homeDir
	normalizeSecureTestUser(t, current)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername(current.Username)
	mock.SetHomeDir(homeDir)
	exec := &coordinatorUserExecutor{Mock: mock, user: current}
	getter := &goCoordinatorFetcher{policy: goCoordinatorPolicy("sha256:G", enforcementDMG)}
	coordinator := &GoCoordinator{Fetcher: getter, Reporter: &coordinatorReporter{}, Exec: exec, CustomerID: "cust", DeviceID: "DEVICE-123", Platform: "linux"}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("[malformed\nindex-url = https://other.example/simple\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	getter.policy = EffectivePolicy{Category: CategoryPackageConfig, Target: TargetGo, Clear: true}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(homeDir, ".netrc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final clear retained credential: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("final clear changed unrelated pip content: %q", got)
	}
}
