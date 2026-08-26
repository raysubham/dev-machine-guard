package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/devicepolicy"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type task9Executor struct {
	*executor.Mock
	user *user.User
}

func (e *task9Executor) CurrentUser() (*user.User, error)  { return e.user, nil }
func (e *task9Executor) LoggedInUser() (*user.User, error) { return e.user, nil }
func (e *task9Executor) RunAsUser(ctx context.Context, username, command string) (string, error) {
	if strings.Contains(command, "XDG_CONFIG_HOME") && strings.Contains(command, "PIP_CONFIG_FILE") {
		return "", nil
	}
	return e.Mock.RunAsUser(ctx, username, command)
}

type task9Fetcher struct {
	calls    []string
	contexts map[string]context.Context
	failures map[string]error
}

func (f *task9Fetcher) Fetch(ctx context.Context, _, _, _, target string) (devicepolicy.EffectivePolicy, error) {
	f.calls = append(f.calls, target)
	if f.contexts != nil {
		f.contexts[target] = ctx
	}
	return devicepolicy.EffectivePolicy{}, f.failures[target]
}

type task9Reporter struct{}

func (task9Reporter) Report(context.Context, string, string, devicepolicy.ComplianceReport) error {
	return nil
}

func TestPackageConfigLanes_FailureDoesNotSuppressSibling(t *testing.T) {
	t.Setenv("STEPSECURITY_HOME", t.TempDir())
	tests := []struct {
		name       string
		failTarget string
	}{
		{"npm failure still runs PyPI", devicepolicy.TargetNPM},
		{"PyPI failure keeps npm success", devicepolicy.TargetPyPI},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := &task9Fetcher{failures: map[string]error{tc.failTarget: errors.New("lane failed")}}
			mock := executor.NewMock()
			mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

			runPackageConfigLanes(mock, progress.NewNoop(), fetcher, task9Reporter{}, "customer", "serial", "linux")

			if got, want := strings.Join(fetcher.calls, ","), devicepolicy.TargetNPM+","+devicepolicy.TargetPyPI; got != want {
				t.Errorf("lane calls = %q, want %q", got, want)
			}
		})
	}
}

func TestPackageConfigLanes_UseSeparateTimeoutContexts(t *testing.T) {
	fetcher := &task9Fetcher{contexts: map[string]context.Context{}, failures: map[string]error{}}
	mock := executor.NewMock()
	mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

	runPackageConfigLanes(mock, progress.NewNoop(), fetcher, task9Reporter{}, "customer", "serial", "linux")

	npmCtx := fetcher.contexts[devicepolicy.TargetNPM]
	pypiCtx := fetcher.contexts[devicepolicy.TargetPyPI]
	if npmCtx == nil || pypiCtx == nil {
		t.Fatalf("lane contexts = %#v, want both", fetcher.contexts)
	}
	if npmCtx == pypiCtx {
		t.Error("npm and PyPI shared one context")
	}
	if _, ok := npmCtx.Deadline(); !ok {
		t.Error("npm context has no deadline")
	}
	if _, ok := pypiCtx.Deadline(); !ok {
		t.Error("PyPI context has no deadline")
	}
}

func TestOfflinePyPIDispatch_AbsentLeavesCommunityMode(t *testing.T) {
	handled, err := runOfflinePyPIIfConfigured(executor.NewMock(), progress.NewNoop(), "")
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Error("empty policy path was handled as offline mode")
	}
}

func TestOfflinePyPI_NoEnterpriseOrNetworkAndRedactedAggregateOutput(t *testing.T) {
	t.Setenv("DMG_CUSTOMER_ID", "")
	t.Setenv("DMG_API_ENDPOINT", "")
	t.Setenv("DMG_API_KEY", "")
	t.Setenv("STEPSECURITY_HOME", t.TempDir())
	restoreCache := devicepolicy.SetCachePathForTest(filepath.Join(t.TempDir(), devicepolicy.CacheFilename))
	t.Cleanup(restoreCache)

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername(current.Username)
	mock.SetHomeDir(home)
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("OFFLINE-DEVICE\n"))
	mock.SetFile("/etc/os-release", []byte("PRETTY_NAME=Test Linux\n"))
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("1.0\n"))
	exec := &task9Executor{Mock: mock, user: &user.User{Username: current.Username, Uid: current.Uid, Gid: current.Gid, HomeDir: home}}

	const secret = "offline-tenant-secret"
	policyFile := filepath.Join(t.TempDir(), "policy.json")
	policy := `{"category":"package_config","target":"pypi","hash":"sha256:offline","enforcement":"dmg","policy":{"ecosystem":"pypi","clients":["pip"],"registry_url":"https://registry.stepsecurity.io/python/simple","auth":{"scheme":"stepsecurity_device_token","api_key":"` + secret + `"}}}`
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := captureTask9Stdout(t, func() error {
		handled, err := runOfflinePyPIIfConfigured(exec, progress.NewNoop(), policyFile)
		if !handled {
			t.Error("policy path did not select offline mode")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), secret) || strings.Contains(string(body), "::dev:") {
		t.Fatalf("offline output leaked credential: %s", body)
	}
	var report devicepolicy.ComplianceReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode local aggregate: %v\n%s", err, body)
	}
	if report.Category != devicepolicy.CategoryPackageConfig || report.Target != devicepolicy.TargetPyPI || report.State == "" {
		t.Fatalf("local aggregate = %+v", report)
	}
}

func TestOfflinePyPIClear_NoTargetUserDoesNotReportCleared(t *testing.T) {
	t.Setenv("STEPSECURITY_HOME", t.TempDir())
	restoreCache := devicepolicy.SetCachePathForTest(filepath.Join(t.TempDir(), devicepolicy.CacheFilename))
	t.Cleanup(restoreCache)

	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("OFFLINE-DEVICE\n"))
	mock.SetFile("/etc/os-release", []byte("PRETTY_NAME=Test Linux\n"))
	mock.SetFile("/proc/sys/kernel/osrelease", []byte("1.0\n"))
	mock.SetLoggedInUserError(errors.New("no target user"))
	policyFile := filepath.Join(t.TempDir(), "clear.json")
	policy := `{"category":"package_config","target":"pypi","clear":true}`
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := captureTask9Stdout(t, func() error {
		return runOfflinePyPIEnforce(mock, progress.NewNoop(), policyFile)
	})
	if err == nil {
		t.Fatal("offline clear error = nil, want unresolved target-user failure")
	}
	if len(body) != 0 {
		t.Fatalf("offline clear emitted false success: %s", body)
	}
}

func captureTask9Stdout(t *testing.T, run func() error) ([]byte, error) {
	t.Helper()
	old := os.Stdout
	file, err := os.CreateTemp(t.TempDir(), "stdout-*.json")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = file
	t.Cleanup(func() { os.Stdout = old })
	runErr := run()
	os.Stdout = old
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return body, runErr
}
