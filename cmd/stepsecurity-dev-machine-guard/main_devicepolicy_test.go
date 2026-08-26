package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/devicepolicy"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type packageConfigFetcher struct {
	calls    []string
	contexts map[string]context.Context
	failures map[string]error
}

func (f *packageConfigFetcher) Fetch(ctx context.Context, _, _, _, target string) (devicepolicy.EffectivePolicy, error) {
	f.calls = append(f.calls, target)
	if f.contexts != nil {
		f.contexts[target] = ctx
	}
	return devicepolicy.EffectivePolicy{}, f.failures[target]
}

type packageConfigReporter struct{}

func (packageConfigReporter) Report(context.Context, string, string, devicepolicy.ComplianceReport) error {
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
			fetcher := &packageConfigFetcher{failures: map[string]error{tc.failTarget: errors.New("lane failed")}}
			mock := executor.NewMock()
			mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

			runPackageConfigLanes(mock, progress.NewNoop(), fetcher, packageConfigReporter{}, "customer", "serial", "linux")

			if got, want := strings.Join(fetcher.calls, ","), devicepolicy.TargetNPM+","+devicepolicy.TargetPyPI; got != want {
				t.Errorf("lane calls = %q, want %q", got, want)
			}
		})
	}
}

func TestPackageConfigLanes_UseSeparateTimeoutContexts(t *testing.T) {
	fetcher := &packageConfigFetcher{contexts: map[string]context.Context{}, failures: map[string]error{}}
	mock := executor.NewMock()
	mock.SetLoggedInUserError(errors.New("no user needed for absent policy"))

	runPackageConfigLanes(mock, progress.NewNoop(), fetcher, packageConfigReporter{}, "customer", "serial", "linux")

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
