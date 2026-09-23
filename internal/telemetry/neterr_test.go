package telemetry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNetErrorCode(t *testing.T) {
	// Real failures from http.Client, so the classification tracks what
	// net/http actually returns rather than hand-built error values. The
	// clients bypass proxy env vars: a proxy would answer for host.invalid and
	// turn the DNS row into a proxy or HTTP result.
	direct := &http.Client{Transport: &http.Transport{}}
	directTimeout := &http.Client{Transport: &http.Transport{}, Timeout: 50 * time.Millisecond}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer drop.Close()
	selfSigned := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer selfSigned.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedURL := "http://" + ln.Addr().String()
	_ = ln.Close()

	tests := []struct {
		name   string
		client *http.Client
		url    string
		want   string
	}{
		{"dns", direct, "http://host.invalid", codeDNS},
		{"refused", direct, refusedURL, codeConnect},
		{"client timeout", directTimeout, slow.URL, codeTimeout},
		{"dropped connection", direct, drop.URL, codeConnDropped},
		{"untrusted certificate", direct, selfSigned.URL, codeCert},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.client.Get(tc.url)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("expected a request error")
			}
			if got := netErrorCode(err); got != tc.want {
				t.Errorf("netErrorCode(%v) = %q, want %q", err, got, tc.want)
			}
		})
	}

	if got := netErrorCode(context.DeadlineExceeded); got != codeTimeout {
		t.Errorf("netErrorCode(DeadlineExceeded) = %q, want %q", got, codeTimeout)
	}
	if got := netErrorCode(errors.New("boom")); got != codeNetOther {
		t.Errorf("netErrorCode(unknown) = %q, want %q", got, codeNetOther)
	}
}

func TestHTTPStatusCode(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{204, codeHTTPOther},
		{301, codeHTTPOther},
		{399, codeHTTPOther},
		{400, codeHTTP4xx},
		{499, codeHTTP4xx},
		{500, codeHTTP5xx},
		{503, codeHTTP5xx},
	}
	for _, tc := range tests {
		if got := httpStatusCode(tc.status); got != tc.want {
			t.Errorf("httpStatusCode(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}
