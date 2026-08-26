package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCreateOutputRejectsSymlinksAndIsReadable(t *testing.T) {
	t.Run("existing output symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		mustWriteFile(t, target, []byte("unchanged"), 0o600)
		path := filepath.Join(dir, "output")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := createOutput(path); err == nil {
			t.Fatal("createOutput() error = nil, want symlink rejection")
		}
		body, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read target: %v", err)
		}
		if got, want := string(body), "unchanged"; got != want {
			t.Errorf("target = %q, want %q", got, want)
		}
	})

	t.Run("symlinked output directory", func(t *testing.T) {
		dir := t.TempDir()
		realDir := filepath.Join(dir, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		linkDir := filepath.Join(dir, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := createOutput(filepath.Join(linkDir, "output")); err == nil {
			t.Fatal("createOutput() error = nil, want parent symlink rejection")
		}
	})

	t.Run("new output", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "output")
		file, err := createOutput(path)
		if err != nil {
			t.Fatalf("createOutput() error = %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close output: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat output: %v", err)
		}
		if got, want := info.Mode().Perm(), os.FileMode(0o644); got != want {
			t.Errorf("output mode = %o, want %o", got, want)
		}
	})
}

func TestIndexHandler_AuthPEP503AndClientAccounting(t *testing.T) {
	const password = "expected-password"
	wheel := []byte("wheel")
	var result bytes.Buffer
	completed := 0
	handler := newIndexHandler(password, wheel, &result, func() { completed++ })

	unauthorized := authenticatedRequest(handler, wheelPath, "pip/25.0", "wrong-password")
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" || bytes.Contains(unauthorized.Body.Bytes(), wheel) {
		t.Fatalf("wrong credentials response = %d %q", unauthorized.Code, unauthorized.Body.Bytes())
	}

	for _, path := range []string{simpleRootPath, packagePath} {
		resp := authenticatedRequest(handler, path, "pip/25.0", password)
		if got, want := resp.Code, http.StatusOK; got != want {
			t.Fatalf("GET %s status = %d, want %d", path, got, want)
		}
	}
	for _, tc := range []struct {
		userAgent string
		client    string
	}{
		{"pip/25.0", "pip"},
		{"uv/0.10.0", "uv"},
	} {
		resp := authenticatedRequest(handler, wheelPath, tc.userAgent, password)
		if got, want := resp.Code, http.StatusOK; got != want {
			t.Fatalf("%s wheel status = %d, want %d", tc.client, got, want)
		}
		if !bytes.Equal(resp.Body.Bytes(), wheel) {
			t.Errorf("%s wheel body = %q, want %q", tc.client, resp.Body.Bytes(), wheel)
		}
	}
	if got, want := completed, 1; got != want {
		t.Errorf("completion calls = %d, want %d", got, want)
	}
	if !handler.complete() {
		t.Error("handler did not account for both clients")
	}

	for _, forbidden := range []string{password, "wrong-password", "Authorization", base64.StdEncoding.EncodeToString([]byte("step-security:" + password))} {
		if strings.Contains(result.String(), forbidden) {
			t.Error("result log contains credential material")
		}
	}
}

func TestRealClientsUseUserConfigAndNetrc(t *testing.T) {
	password := "real-client-secret"
	wheel, err := generateWheel()
	if err != nil {
		t.Fatalf("generateWheel() error = %v", err)
	}
	certificate, caPEM, err := generateCertificates("localhost")
	if err != nil {
		t.Fatalf("generateCertificates() error = %v", err)
	}
	handler := newIndexHandler(password, wheel, io.Discard, nil)
	server := httptest.NewUnstartedServer(handler)
	config := tlsConfig(certificate)
	server.TLS = &config
	server.StartTLS()
	defer server.Close()
	indexURL := "https://localhost" + strings.TrimPrefix(server.URL, "https://127.0.0.1") + simpleRootPath

	t.Run("pip", func(t *testing.T) {
		python := availablePythonWithPip(t)
		home := t.TempDir()
		caPath := filepath.Join(home, "ca.pem")
		mustWriteFile(t, caPath, caPEM, 0o600)
		writeNetrc(t, home, password)
		writePipConfig(t, home, indexURL)
		dest := filepath.Join(home, "download")
		if err := os.Mkdir(dest, 0o700); err != nil {
			t.Fatalf("mkdir download: %v", err)
		}
		runClient(t, home, caPath, password, python, "-m", "pip", "download", "--no-deps", "--no-cache-dir", "example-package==1.0", "--dest", dest)
		if !handler.seen("pip") {
			t.Error("pip did not fetch the wheel with matching authentication")
		}
	})

	t.Run("uv", func(t *testing.T) {
		uv := availableUV(t)
		home := t.TempDir()
		caPath := filepath.Join(home, "ca.pem")
		mustWriteFile(t, caPath, caPEM, 0o600)
		writeNetrc(t, home, password)
		writeUVConfig(t, home, indexURL)
		venv := filepath.Join(home, "venv")
		runClient(t, home, caPath, password, uv, "venv", venv)
		python := filepath.Join(venv, "bin", "python")
		if runtime.GOOS == "windows" {
			python = filepath.Join(venv, "Scripts", "python.exe")
		}
		runClient(t, home, caPath, password, uv, "pip", "install", "--python", python, "--no-cache", "example-package==1.0")
		if !handler.seen("uv") {
			t.Error("uv did not fetch the wheel with matching authentication")
		}
	})
}

func authenticatedRequest(handler http.Handler, path, userAgent, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", userAgent)
	req.SetBasicAuth("step-security", password)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func runClient(t *testing.T, home, caPath, password, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = home
	cmd.Env = clientEnv(home, caPath)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("%s timed out", filepath.Base(name))
	}
	if err != nil {
		t.Fatalf("%s failed: %v: %s", filepath.Base(name), err, redactClientOutput(out, password))
	}
}

func pipVersionSupported(text string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(text, "pip %d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 20 || major == 20 && minor >= 2
}

func availablePythonWithPip(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python", "py"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "-m", "pip", "--version").Output()
		if err == nil && pipVersionSupported(string(out)) {
			return path
		}
	}
	t.Skip("supported pip client unavailable")
	return ""
}

func availableUV(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv client unavailable")
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		t.Skip("uv client unavailable")
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(out), "uv %d.%d", &major, &minor); err != nil || major == 0 && minor < 10 {
		t.Skipf("unsupported uv version: %s", strings.TrimSpace(string(out)))
	}
	return path
}

func writeNetrc(t *testing.T, home, password string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(home, ".netrc"), []byte("machine localhost\nlogin step-security\npassword "+password+"\n"), 0o600)
}

func pipConfigPath(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "pip", "pip.conf")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "pip", "pip.ini")
	}
	return filepath.Join(home, ".config", "pip", "pip.conf")
}

func writePipConfig(t *testing.T, home, indexURL string) {
	t.Helper()
	mustWriteFile(t, pipConfigPath(home), []byte("[global]\nindex-url = "+indexURL+"\nno-index = false\n"), 0o600)
}

func uvConfigPath(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "uv", "uv.toml")
	}
	return filepath.Join(home, ".config", "uv", "uv.toml")
}

func writeUVConfig(t *testing.T, home, indexURL string) {
	t.Helper()
	body := "index-strategy = \"first-index\"\n\n[[index]]\nname = \"stepsecurity\"\nurl = \"" + indexURL + "\"\ndefault = true\nauthenticate = \"always\"\n"
	mustWriteFile(t, uvConfigPath(home), []byte(body), 0o600)
}

func mustWriteFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func clientEnv(home, caPath string) []string {
	blocked := map[string]bool{
		"HOME": true, "USERPROFILE": true, "APPDATA": true, "XDG_CONFIG_HOME": true,
		"NETRC": true, "SSL_CERT_FILE": true, "VIRTUAL_ENV": true,
	}
	env := make([]string, 0, len(os.Environ())+9)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !blocked[name] && !strings.HasPrefix(name, "PIP_") && !strings.HasPrefix(name, "UV_") {
			env = append(env, item)
		}
	}
	return append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"PIP_CERT="+caPath,
		"SSL_CERT_FILE="+caPath,
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
	)
}

func redactClientOutput(out []byte, password string) string {
	value := strings.ReplaceAll(string(out), password, "[REDACTED]")
	return strings.ReplaceAll(value, base64.StdEncoding.EncodeToString([]byte("step-security:"+password)), "[REDACTED]")
}
