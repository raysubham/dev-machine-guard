package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCopilotStandaloneMCP(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, "copilot-custom")
	project := filepath.Join(testHome, "project")
	m.SetEnv("COPILOT_HOME", root)
	fs.addFile(filepath.Join(root, "mcp-config.json"), `// JSONC
 {"mcpServers":{"local":{"type":"local","command":"node","args":["server.js"],"env":{"TOKEN":"SECRET_SENTINEL"}},"remote":{"type":"http","url":"https://docs.example/mcp","headers":{"Authorization":"SECRET_SENTINEL"}},"invalid":false,},}`)
	fs.addFile(filepath.Join(project, ".github/mcp.json"), `{"project":{"type":"sse","url":"https://project.example/mcp"}}`)
	fs.addFile(filepath.Join(testHome, ".claude.json"), `{"projects":{`+jsonQuote(project)+`:{}}}`)
	fs.addFile(filepath.Join(project, ".mcp.json"), `{"mcpServers":{"shared":{"command":"node"}}}`)
	fs.commit()
	results := NewMCPDetector(m).DetectEnterprise(context.Background(), nil)
	sources := map[string]string{}
	for _, config := range results {
		sources[config.ConfigPath] = config.ConfigSource
		body, err := base64.StdEncoding.DecodeString(config.ConfigContentBase64)
		if err != nil || strings.Contains(string(body), "SECRET_SENTINEL") {
			t.Fatalf("unsafe MCP: %s", body)
		}
		if config.ConfigPath == filepath.Join(root, "mcp-config.json") {
			if !strings.Contains(string(body), "local") || !strings.Contains(string(body), "remote") || strings.Contains(string(body), "invalid") {
				t.Fatalf("valid siblings lost: %s", body)
			}
		}
	}
	if sources[filepath.Join(root, "mcp-config.json")] != "copilot" || sources[filepath.Join(project, ".github/mcp.json")] != "copilot_project" || sources[filepath.Join(project, ".mcp.json")] != "project_mcp" {
		t.Fatalf("MCP attribution: %v", sources)
	}
}

func jsonQuote(value string) string { data, _ := json.Marshal(value); return string(data) }

func TestCopilotBareMCPIsPathLimited(t *testing.T) {
	d := &MCPDetector{}
	raw := []byte(`{"docs":{"type":"http","url":"https://docs.example/mcp"}}`)
	for _, tc := range []struct {
		file string
		ok   bool
	}{{"/repo/.mcp.json", true}, {"/repo/.github/mcp.json", true}, {"/repo/.vscode/mcp.json", false}, {"/repo/settings.json", false}} {
		if _, ok := d.filterMCPContent("discovered_mcp", tc.file, raw); ok != tc.ok {
			t.Errorf("%s: accepted=%v", tc.file, ok)
		}
	}
}

func TestCopilotProjectMCPKeepsValidSiblings(t *testing.T) {
	d := &MCPDetector{}
	content := []byte(`{"mcpServers":{"good":{"type":"local","command":"node"},"bad":42},"mcp":null}`)
	data, ok := d.filterMCPContent("discovered_mcp", "/project/.github/mcp.json", content)
	if !ok || !strings.Contains(string(data), `"good"`) || strings.Contains(string(data), `"bad"`) || !strings.Contains(string(data), `"mcp":{}`) {
		t.Fatalf("shared keys or valid siblings lost: %s", data)
	}
	for _, raw := range []string{`{"type":null,"command":"node"}`, `{"type":7,"command":"node"}`, `{"command":"node","args":null}`} {
		if validCopilotMCP(json.RawMessage(raw)) {
			t.Errorf("invalid server accepted: %s", raw)
		}
	}
}

func TestSharedMCPRelativeSymlink(t *testing.T) {
	for _, protected := range []bool{false, true} {
		name := "shared"
		if protected {
			name = "protected"
		}
		t.Run(name, func(t *testing.T) {
			if protected && runtime.GOOS != "darwin" {
				t.Skip("macOS TCC paths")
			}
			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			target := "shared.json"
			if protected {
				target = "Library/shared.json"
			}
			for _, dir := range []string{filepath.Join(project, ".github"), filepath.Dir(filepath.Join(project, target))} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(project, target), []byte(`{"mcpServers":{"docs":{"command":"node"}}}`), 0600); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(project, ".github/mcp.json")
			if err := os.Symlink("../"+target, file); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			detector := NewMCPDetector(mcpFixtureExecutor{Executor: executor.NewReal(), home: project}).WithSkipper(tcc.New(project))
			found := false
			for _, config := range detector.DetectEnterprise(context.Background(), []string{project}) {
				if config.ConfigPath == file && config.ConfigContentBase64 != "" {
					found = true
				}
			}
			if found == protected {
				t.Fatalf("collected=%v, protected=%v", found, protected)
			}
		})
	}
}

type mcpFixtureExecutor struct {
	executor.Executor
	home string
}

func (e mcpFixtureExecutor) LoggedInUser() (*user.User, error) {
	return &user.User{HomeDir: e.home}, nil
}
func (e mcpFixtureExecutor) Getenv(string) string { return "" }
