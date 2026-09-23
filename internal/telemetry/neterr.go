package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
)

// Stable cause codes for network failures, carried in run-status error
// messages as "[code]". The agent-api loader scripts (bash and PowerShell)
// emit the same set, so failures group by cause across the loader and the
// agent. codeBadResponse is agent-only: the loaders report malformed API
// responses under their own error types.
const (
	codeDNS         = "net_dns"
	codeProxy       = "net_proxy"
	codeConnect     = "net_connect"
	codeTimeout     = "net_timeout"
	codeTLS         = "net_tls"
	codeCert        = "net_cert"
	codeConnDropped = "net_conn_dropped"
	codeHTTP4xx     = "http_4xx"
	codeHTTP5xx     = "http_5xx"
	codeBadResponse = "bad_response"
	codeNetOther    = "net_other"
)

func httpStatusCode(status int) string {
	if status >= 500 {
		return codeHTTP5xx
	}
	return codeHTTP4xx
}

// netErrorCode classifies an error returned by http.Client.Do.
func netErrorCode(err error) string {
	var (
		opErr     *net.OpError
		dnsErr    *net.DNSError
		verifyErr *tls.CertificateVerificationError
		authErr   x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		alertErr  tls.AlertError
		recordErr tls.RecordHeaderError
		netErr    net.Error
	)
	switch {
	case errors.As(err, &opErr) && opErr.Op == "proxyconnect":
		return codeProxy
	case errors.As(err, &dnsErr):
		return codeDNS
	case errors.As(err, &verifyErr), errors.As(err, &authErr), errors.As(err, &hostErr):
		return codeCert
	case errors.As(err, &alertErr), errors.As(err, &recordErr):
		return codeTLS
	// Includes "TLS handshake timeout", which net/http reports as a timeout.
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return codeTimeout
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return codeConnect
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &opErr):
		return codeConnDropped
	}
	return codeNetOther
}
