package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	wheelFilename     = "example_package-1.0-py3-none-any.whl"
	distInfoDir       = "example_package-1.0.dist-info"
	metadataPath      = distInfoDir + "/METADATA"
	wheelMetadataPath = distInfoDir + "/WHEEL"
	recordPath        = distInfoDir + "/RECORD"
	simpleRootPath    = "/python/simple/"
	packagePath       = simpleRootPath + "example-package/"
	wheelPath         = "/python/packages/" + wheelFilename
)

type resultRecord struct {
	Path      string `json:"path"`
	Client    string `json:"client"`
	AuthMatch bool   `json:"auth_match"`
	Status    int    `json:"status"`
}

type indexHandler struct {
	password   string
	wheel      []byte
	result     io.Writer
	onComplete func()

	mu        sync.Mutex
	seenWheel map[string]bool
	completed bool
	resultErr error
}

func newIndexHandler(password string, wheel []byte, result io.Writer, onComplete func()) *indexHandler {
	return &indexHandler{
		password:   password,
		wheel:      wheel,
		result:     result,
		onComplete: onComplete,
		seenWheel:  make(map[string]bool),
	}
}

func (h *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client := clientFamily(r.UserAgent())
	username, password, ok := r.BasicAuth()
	authMatch := ok && username == "step-security" && subtle.ConstantTimeCompare([]byte(password), []byte(h.password)) == 1
	status := http.StatusOK

	if !authMatch {
		w.Header().Set("WWW-Authenticate", `Basic realm="python-index"`)
		status = http.StatusUnauthorized
		http.Error(w, http.StatusText(status), status)
		h.record(r.URL.Path, client, false, status, false)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		status = http.StatusMethodNotAllowed
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(status), status)
		h.record(r.URL.Path, client, true, status, false)
		return
	}

	var body []byte
	switch r.URL.Path {
	case simpleRootPath:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body = []byte(`<html><body><a href="example-package/">example-package</a></body></html>`)
	case packagePath:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body = []byte(`<html><body><a href="../../packages/` + wheelFilename + `">` + wheelFilename + `</a></body></html>`)
	case wheelPath:
		w.Header().Set("Content-Type", "application/octet-stream")
		body = h.wheel
	default:
		status = http.StatusNotFound
		http.NotFound(w, r)
		h.record(r.URL.Path, client, true, status, false)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	wroteBody := false
	if r.Method == http.MethodGet {
		n, err := w.Write(body)
		wroteBody = err == nil && n == len(body)
	}
	h.record(r.URL.Path, client, true, status, r.Method == http.MethodGet && r.URL.Path == wheelPath && wroteBody)
}

func (h *indexHandler) record(requestPath, client string, authMatch bool, status int, wheelFetched bool) {
	path := "<other>"
	switch requestPath {
	case simpleRootPath, packagePath, wheelPath:
		path = requestPath
	}

	h.mu.Lock()
	if err := json.NewEncoder(h.result).Encode(resultRecord{Path: path, Client: client, AuthMatch: authMatch, Status: status}); err != nil && h.resultErr == nil {
		h.resultErr = err
	}
	if wheelFetched && (client == "pip" || client == "uv") {
		h.seenWheel[client] = true
	}
	completeNow := !h.completed && h.seenWheel["pip"] && h.seenWheel["uv"]
	if completeNow {
		h.completed = true
	}
	h.mu.Unlock()

	if completeNow && h.onComplete != nil {
		h.onComplete()
	}
}

func (h *indexHandler) complete() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.completed
}

func (h *indexHandler) seen(client string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seenWheel[client]
}

func (h *indexHandler) resultError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.resultErr
}

func (h *indexHandler) missingClients() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	missing := make([]string, 0, 2)
	for _, client := range []string{"pip", "uv"} {
		if !h.seenWheel[client] {
			missing = append(missing, client)
		}
	}
	return strings.Join(missing, ", ")
}

func clientFamily(userAgent string) string {
	userAgent = strings.ToLower(userAgent)
	switch {
	case strings.HasPrefix(userAgent, "pip/"):
		return "pip"
	case strings.HasPrefix(userAgent, "uv/"):
		return "uv"
	default:
		return "unknown"
	}
}

func generateWheel() ([]byte, error) {
	files := []struct {
		name string
		body []byte
	}{
		{"example_package/__init__.py", []byte("__version__ = \"1.0\"\n")},
		{metadataPath, []byte("Metadata-Version: 2.1\nName: example-package\nVersion: 1.0\nSummary: Controlled DMG integration package\n\n")},
		{wheelMetadataPath, []byte("Wheel-Version: 1.0\nGenerator: dev-machine-guard\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n")},
	}

	var record bytes.Buffer
	csvWriter := csv.NewWriter(&record)
	for _, file := range files {
		if err := csvWriter.Write([]string{file.name, recordHash(file.body), strconv.Itoa(len(file.body))}); err != nil {
			return nil, fmt.Errorf("writing wheel record: %w", err)
		}
	}
	if err := csvWriter.Write([]string{recordPath, "", ""}); err != nil {
		return nil, fmt.Errorf("writing wheel record: %w", err)
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return nil, fmt.Errorf("writing wheel record: %w", err)
	}
	files = append(files, struct {
		name string
		body []byte
	}{recordPath, record.Bytes()})

	var wheel bytes.Buffer
	zw := zip.NewWriter(&wheel)
	for _, file := range files {
		entry, err := zw.Create(file.name)
		if err != nil {
			return nil, fmt.Errorf("creating wheel entry: %w", err)
		}
		if _, err := entry.Write(file.body); err != nil {
			return nil, fmt.Errorf("writing wheel entry: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing wheel: %w", err)
	}
	return wheel.Bytes(), nil
}

func recordHash(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256=" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func generateCertificates(hostname string) (tls.Certificate, []byte, error) {
	if hostname == "" || strings.ContainsAny(hostname, "/\\\x00\r\n") {
		return tls.Certificate{}, nil, errors.New("hostname must be a non-empty host name")
	}
	now := time.Now()
	caSerial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generating CA serial: %w", err)
	}
	caPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generating CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Dev Machine Guard test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivate.PublicKey, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	serverSerial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generating server serial: %w", err)
	}
	serverPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generating server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		serverTemplate.IPAddresses = []net.IP{ip}
	} else {
		serverTemplate.DNSNames = []string{hostname}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverPrivate.PublicKey, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("creating server certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("marshalling server key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("loading server key pair: %w", err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func tlsConfig(certificate tls.Certificate) tls.Config {
	return tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
}

type options struct {
	hostname  string
	listen    string
	caOut     string
	resultOut string
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("python-index-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.hostname, "hostname", "", "TLS hostname")
	flags.StringVar(&opts.listen, "listen", "127.0.0.1:443", "listen address")
	flags.StringVar(&opts.caOut, "ca-out", "", "CA certificate output path")
	flags.StringVar(&opts.resultOut, "result-out", "", "redacted result log path")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	if opts.hostname == "" || opts.caOut == "" || opts.resultOut == "" {
		return options{}, errors.New("--hostname, --ca-out, and --result-out are required")
	}
	return opts, nil
}

func runtimeSelfTest(handler *indexHandler, wheel []byte) error {
	req := httptest.NewRequest(http.MethodGet, wheelPath, nil)
	req.Header.Set("User-Agent", "pip/self-test")
	req.SetBasicAuth("wrong-user", "")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized || bytes.Contains(resp.Body.Bytes(), wheel) {
		return errors.New("wrong-auth self-test failed")
	}
	if err := handler.resultError(); err != nil {
		return fmt.Errorf("writing self-test result: %w", err)
	}
	return nil
}

func createOutput(path string) (*os.File, error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspecting output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("output directory must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("opening output directory: %w", err)
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("creating output: %w", err)
	}
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("setting output permissions: %w", err)
	}
	return file, nil
}

func run(ctx context.Context, args []string, password string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("DMG_TEST_EXPECTED_PASSWORD is required")
	}
	certificate, caPEM, err := generateCertificates(opts.hostname)
	if err != nil {
		return err
	}
	caOutput, err := createOutput(opts.caOut)
	if err != nil {
		return fmt.Errorf("creating CA output: %w", err)
	}
	if _, err := caOutput.Write(caPEM); err != nil {
		_ = caOutput.Close()
		return fmt.Errorf("writing CA certificate: %w", err)
	}
	if err := caOutput.Close(); err != nil {
		return fmt.Errorf("closing CA certificate: %w", err)
	}
	result, err := createOutput(opts.resultOut)
	if err != nil {
		return fmt.Errorf("creating result log: %w", err)
	}
	defer result.Close()
	wheel, err := generateWheel()
	if err != nil {
		return err
	}
	complete := make(chan struct{})
	var completeOnce sync.Once
	handler := newIndexHandler(password, wheel, result, func() { completeOnce.Do(func() { close(complete) }) })
	if err := runtimeSelfTest(handler, wheel); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeTLS(listener, "", "") }()

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("stopping server: %w", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serving: %w", err)
		}
		return nil
	}

	select {
	case <-complete:
		if err := shutdown(); err != nil {
			return err
		}
		if err := handler.resultError(); err != nil {
			return fmt.Errorf("writing result log: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serving: %w", err)
		}
	case <-ctx.Done():
		if err := shutdown(); err != nil {
			return err
		}
	}
	if handler.complete() {
		if err := handler.resultError(); err != nil {
			return fmt.Errorf("writing result log: %w", err)
		}
		return nil
	}
	return fmt.Errorf("missing successful authenticated wheel fetches from: %s", handler.missingClients())
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv("DMG_TEST_EXPECTED_PASSWORD")); err != nil {
		fmt.Fprintln(os.Stderr, "python-index-server:", err)
		os.Exit(1)
	}
}
