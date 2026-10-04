package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func copilotContext(t *testing.T, result SkillsResult) model.AgentPluginContext {
	t.Helper()
	if result.Plugins != nil {
		for _, c := range result.Plugins.Contexts {
			if c.Agent == model.AgentCopilot {
				return c
			}
		}
	}
	t.Fatal("missing Copilot context")
	return model.AgentPluginContext{}
}

func TestCopilotRecordedInstallComponents(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	payload := filepath.Join(root, "installed-plugins", "_direct", "release-checks")
	record := fmt.Sprintf(`{"name":"release-checks","marketplace":"","cache_path":%q,"version":"1.0.0","installed_at":"2026-10-05T00:00:00Z","enabled":false,"source":{"source":"local","path":%q}}`, payload, filepath.Join(testHome, "source"))
	fs.addFile(filepath.Join(root, "config.json"), "// Generated state\n{\"installedPlugins\":["+record+",null]}")
	fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"release-checks","skills":["custom"],"mcpServers":{"loser":{"url":"https://inline.example/mcp"}}}`)
	fs.addFile(filepath.Join(payload, "skills/ignored/SKILL.md"), validFrontmatter("ignored", "Ignored default"))
	fs.addFile(filepath.Join(payload, "custom/check/SKILL.md"), validFrontmatter("declared-check", "Check releases"))
	fs.addFile(filepath.Join(payload, "agents/reviewer.agent.md"), "---\nname: Display name\ndescription: Review a release\nmcp-servers:\n  'agent/docs~v1':\n    type: http\n    url: https://agent.example/mcp\n    headers:\n      Authorization: FAKE_SECRET_SENTINEL\n---\nPROMPT_MUST_NOT_LEAVE_DEVICE\n")
	fs.addFile(filepath.Join(payload, ".mcp.json"), `{"mcpServers":{"winner":{"type":"http","url":"https://docs.example/mcp","env":{"TOKEN":"FAKE_SECRET_SENTINEL"}},"invalid":42}}`)
	fs.addFile(filepath.Join(payload, ".github/mcp.json"), `{"mcpServers":{"loser":{"url":"https://github.example/mcp"}}}`)
	fs.addFile(filepath.Join(root, "installed-plugins/orphan/.plugin/plugin.json"), `{"name":"orphan"}`)
	fs.commit()
	versions := AgentVersions([]model.AITool{{Name: "github-copilot-cli", Version: "1.0.91"}})
	c := copilotContext(t, NewSkillsDetector(m).WithAgentVersions(versions).DetectAll(context.Background(), nil, nil))
	if c.AgentVersion != "1.0.91" {
		t.Fatal("existing CLI version was not mapped to Copilot")
	}
	if c.InstallationStatus == model.AgentScanStatusComplete || len(c.Plugins) != 1 {
		t.Fatalf("registry siblings: %+v", c)
	}
	p := c.Plugins[0]
	if p.Installed == nil || !*p.Installed || p.FilesPresent == nil || !*p.FilesPresent || p.ConfiguredEnabled == nil || *p.ConfiguredEnabled || p.EffectiveEnabled != nil || p.InstalledAtMs == nil {
		t.Fatalf("installation observations: %+v", p)
	}
	if p.SourcePath != filepath.Join(testHome, "source") || p.ComponentStatus == model.AgentScanStatusComplete || len(p.Components) != 4 {
		t.Fatalf("components: %+v", p)
	}
	found := map[string]bool{}
	for _, component := range p.Components {
		found[component.Name] = true
		if component.Skill != nil && (component.Skill.Agent != model.AgentCopilot || component.Skill.Source != "copilot_plugin" || component.Skill.Usage != nil || len(component.CallableNames) != 0) {
			t.Fatalf("skill attribution: %+v", component)
		}
		if component.Name == "agent/docs~v1" && component.DeclarationPointer != "/mcp-servers/agent~1docs~0v1" {
			t.Fatalf("agent pointer: %+v", component)
		}
		if component.MCPConfig != nil {
			body, err := base64.StdEncoding.DecodeString(component.MCPConfig.ConfigContentBase64)
			if err != nil || strings.Contains(string(body), "FAKE_SECRET_SENTINEL") || component.MCPConfig.ConfigSource != "copilot_plugin" {
				t.Fatalf("MCP content: %s", body)
			}
		}
	}
	for _, name := range []string{"declared-check", "reviewer", "winner", "agent/docs~v1"} {
		if !found[name] {
			t.Errorf("missing %s", name)
		}
	}
	body, _ := json.Marshal(c)
	if strings.Contains(string(body), "PROMPT_MUST_NOT_LEAVE_DEVICE") || strings.Contains(string(body), "FAKE_SECRET_SENTINEL") {
		t.Fatal("private contents leaked")
	}
}

func TestCopilotCanonicalStateAndMissingPayload(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		count       int
		complete    bool
	}{
		{"empty", `{"installedPlugins":[]}`, 0, true},
		{"canonical invalid beats alias", `{"installedPlugins":{},"installed_plugins":[{"name":"old","marketplace":""}]}`, 0, false},
		{"canonical null beats alias", `{"installedPlugins":null,"installed_plugins":[{"name":"old","marketplace":""}]}`, 0, false},
		{"malformed", `{`, 0, false},
		{"legacy", `{"installed_plugins":[{"name":"legacy","marketplace":""}]}`, 1, false},
		{"missing payload", fmt.Sprintf(`{"installedPlugins":[{"name":"missing","marketplace":"","cache_path":%q}]}`, filepath.Join(testHome, "missing")), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			fs.addFile(filepath.Join(testHome, ".copilot/config.json"), tc.state)
			fs.commit()
			c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
			if len(c.Plugins) != tc.count || (c.InstallationStatus == model.AgentScanStatusComplete) != tc.complete {
				t.Fatalf("coverage: %+v", c)
			}
			for _, p := range c.Plugins {
				if p.ComponentStatus == model.AgentScanStatusComplete || len(p.Components) != 0 {
					t.Fatalf("missing payload complete: %+v", p)
				}
			}
		})
	}
}

func TestCopilotLiveSelectionAndProjectPreferences(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".copilot")
			catalog := filepath.Join(testHome, "catalog")
			project := filepath.Join(testHome, "project")
			fs.addFile(filepath.Join(root, "config.json"), `{"installedPlugins":[]}`)
			fs.addFile(filepath.Join(project, ".github/copilot/settings.json"), fmt.Sprintf(`{"extraKnownMarketplaces":{"engineering":{"source":{"source":"directory","path":%q}}},"enabledPlugins":{"review@engineering":%t}}`, catalog, enabled))
			fs.addFile(filepath.Join(catalog, "marketplace.json"), `{"name":"engineering","owner":{"name":"Example Engineering"},"plugins":[{"name":"review","source":"./plugins/review"},{"name":"unselected","source":"./plugins/unused"}]}`)
			fs.addFile(filepath.Join(catalog, "plugins/review/.plugin/plugin.json"), `{"name":"review"}`)
			fs.addFile(filepath.Join(catalog, "plugins/review/skills/check/SKILL.md"), validFrontmatter("check", "Check releases"))
			fs.commit()
			c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), []string{project}, nil))
			if len(c.Plugins) != 1 || c.InstallationStatus != model.AgentScanStatusComplete {
				t.Fatalf("live discovery: %+v", c)
			}
			p := c.Plugins[0]
			if p.Scope != model.PluginScopeProject || p.ProjectPath != project || p.InstallationEvidence != model.PluginEvidenceLocalConfig || p.ConfiguredEnabled == nil || *p.ConfiguredEnabled != enabled || p.EffectiveEnabled != nil || len(p.Components) != 1 {
				t.Fatalf("live selection: %+v", p)
			}
		})
	}
}

func TestCopilotManifestPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, rootManifest, legacy, mcp string
		count                           int
		format                          string
	}{
		{"portable 1.1", `{"$schema":"https://agent-plugins.org/schemas/1.1.0/plugin.schema.json","name":"portable","version":"1.0.0"}`, `{"name":"legacy","skills":"custom"}`, `{"$schema":"https://agent-plugins.org/schemas/1.1.0/mcp.schema.json","mcpServers":{"docs":{"type":"streamable-http","url":"https://docs.example/mcp"},"events":{"type":"sse","url":"https://docs.example/events"}}}`, 3, model.PluginManifestPortable},
		{"unknown portable", `{"$schema":"https://agent-plugins.org/schemas/9.0.0/plugin.schema.json","name":"future"}`, `{"name":"legacy"}`, "", 0, ""},
		{"malformed root", `{`, `{"name":"legacy"}`, "", 0, ""},
		{"legacy priority", `{"name":"root","skills":"custom"}`, `{"name":"preferred"}`, "", 1, model.PluginManifestCopilot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".copilot")
			payload := filepath.Join(root, "installed-plugins/fixture")
			fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"fixture","marketplace":"","cache_path":%q}]}`, payload))
			fs.addFile(filepath.Join(payload, "plugin.json"), tc.rootManifest)
			fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), tc.legacy)
			fs.addFile(filepath.Join(payload, "skills/check/SKILL.md"), validFrontmatter("check", "Check releases"))
			if tc.mcp != "" {
				fs.addFile(filepath.Join(payload, "mcp.json"), tc.mcp)
			}
			fs.commit()
			c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
			p := c.Plugins[0]
			if len(p.Components) != tc.count || p.ManifestFormat != tc.format {
				t.Fatalf("manifest selection: %+v", p)
			}
			if tc.count == 0 && p.ComponentStatus == model.AgentScanStatusComplete {
				t.Fatal("invalid preferred manifest reported complete")
			}
		})
	}
}

func TestCopilotSameNameOrigins(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	var records []map[string]any
	for _, suffix := range []string{"one", "two"} {
		payload := filepath.Join(root, "installed-plugins", suffix)
		records = append(records, map[string]any{"name": "same", "marketplace": "", "cache_path": payload, "source": map[string]string{"source": "local", "path": filepath.Join(testHome, "sources", suffix)}})
		fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"same"}`)
	}
	data, _ := json.Marshal(map[string]any{"installedPlugins": records})
	fs.addFile(filepath.Join(root, "config.json"), string(data))
	fs.commit()
	c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
	if len(c.Plugins) != 2 || c.Plugins[0].InstanceID == c.Plugins[1].InstanceID {
		t.Fatalf("origins merged: %+v", c)
	}
}

func TestCopilotRoots(t *testing.T) {
	m := executor.NewMock()
	m.SetEnv("COPILOT_HOME", filepath.Join(testHome, "custom"))
	m.SetGOOS(model.PlatformDarwin)
	if got := copilotCacheRoot(m, testHome); got != filepath.Join(testHome, "Library/Caches/copilot") {
		t.Fatalf("config override moved cache: %s", got)
	}
	for _, goos := range []string{model.PlatformLinux, model.PlatformDarwin, model.PlatformWindows} {
		m.SetGOOS(goos)
		m.SetEnv("COPILOT_CACHE_HOME", filepath.Join(testHome, "cache"))
		if got := copilotCacheRoot(m, testHome); got != filepath.Join(testHome, "cache") {
			t.Fatalf("%s cache override: %s", goos, got)
		}
	}
	m.SetEnv("COPILOT_HOME", "relative")
	if got := copilotConfigRoot(m, testHome); got != filepath.Join(testHome, ".copilot") {
		t.Fatalf("relative root accepted: %s", got)
	}
}

func TestCopilotEscapingSkillLink(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("symlink creation requires privileges")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".copilot")
	payload := filepath.Join(root, "installed-plugins/test")
	for _, dir := range []string{filepath.Join(payload, ".plugin"), filepath.Join(home, "unrelated/check")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for file, body := range map[string]string{filepath.Join(root, "config.json"): fmt.Sprintf(`{"installedPlugins":[{"name":"test","marketplace":"","cache_path":%q}]}`, payload), filepath.Join(payload, ".plugin/plugin.json"): `{"name":"test"}`, filepath.Join(home, "unrelated/check/SKILL.md"): validFrontmatter("unrelated", "Unrelated skill")} {
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "unrelated"), filepath.Join(payload, "skills")); err != nil {
		t.Fatal(err)
	}
	d := NewSkillsDetector(executor.NewReal())
	definitions := 0
	s := &pluginScan{d: d, ctx: context.Background(), home: home, goos: runtime.GOOS, memo: map[string]*skillScan{}, definitions: &definitions, evidence: newPluginEvidence()}
	c := s.detectCopilot()
	if c == nil || len(c.Plugins) != 1 || c.Plugins[0].ComponentStatus == model.AgentScanStatusComplete || len(c.Plugins[0].Components) != 0 {
		t.Fatalf("escaping link: %+v", c)
	}
}

func TestCopilotFailedCatalogProtectsRecordedComponents(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	catalog := filepath.Join(testHome, "catalog")
	payload := filepath.Join(root, "installed-plugins/test")
	fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"test","marketplace":"engineering","cache_path":%q}]}`, payload))
	fs.addFile(filepath.Join(root, "settings.json"), fmt.Sprintf(`{"extraKnownMarketplaces":{"engineering":{"source":{"source":"directory","path":%q}}}}`, catalog))
	fs.addFile(filepath.Join(catalog, "marketplace.json"), `{`)
	fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"test"}`)
	fs.addFile(filepath.Join(payload, "skills/check/SKILL.md"), validFrontmatter("check", "Check releases"))
	fs.commit()
	c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
	if len(c.Plugins) != 1 || len(c.Plugins[0].Components) != 1 || c.Plugins[0].ComponentStatus == model.AgentScanStatusComplete {
		t.Fatalf("failed catalog gave complete component coverage: %+v", c)
	}
}

func TestCopilotInvalidLivePayloadIsNotInstalled(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	catalog := filepath.Join(testHome, "catalog")
	fs.addFile(filepath.Join(root, "settings.json"), fmt.Sprintf(`{"extraKnownMarketplaces":{"engineering":{"source":{"source":"directory","path":%q}}},"enabledPlugins":{"test@engineering":false}}`, catalog))
	fs.addFile(filepath.Join(catalog, "marketplace.json"), `{"name":"engineering","owner":{"name":"Example Engineering"},"plugins":[{"name":"test","source":"./plugins/test"}]}`)
	fs.addFile(filepath.Join(catalog, "plugins/test/.plugin/plugin.json"), `{`)
	fs.commit()
	c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
	if len(c.Plugins) != 0 || c.InstallationStatus == model.AgentScanStatusComplete {
		t.Fatalf("invalid payload invented installation: %+v", c)
	}
}

func TestCopilotNativeRootSkillFallback(t *testing.T) {
	for _, tc := range []struct {
		name, manifest string
		skillsDir      bool
		count          int
	}{
		{"no skills directory", `{"name":"fixture"}`, false, 1},
		{"empty skills directory", `{"name":"fixture"}`, true, 0},
		{"explicit missing override", `{"name":"fixture","skills":"missing"}`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".copilot")
			payload := filepath.Join(root, "installed-plugins/fixture")
			fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"fixture","marketplace":"","cache_path":%q}]}`, payload))
			fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), tc.manifest)
			fs.addFile(filepath.Join(payload, "SKILL.md"), validFrontmatter("check", "Check release"))
			if tc.skillsDir {
				fs.addFile(filepath.Join(payload, "skills/.keep"), "")
			}
			fs.commit()
			c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
			if len(c.Plugins[0].Components) != tc.count {
				t.Fatalf("native root fallback: %+v", c.Plugins[0])
			}
		})
	}
}

func TestCopilotNativePathMCPPrecedence(t *testing.T) {
	for _, tc := range []struct{ name, defaultFile, winner string }{
		{"manifest path", "", "path-server"}, {"dot file wins", ".mcp.json", "default-server"}, {"github file wins", ".github/mcp.json", "default-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".copilot")
			payload := filepath.Join(root, "installed-plugins/fixture")
			fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"fixture","marketplace":"","cache_path":%q}]}`, payload))
			fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"fixture","mcpServers":"./servers.json"}`)
			fs.addFile(filepath.Join(payload, "servers.json"), `{"mcpServers":{"path-server":{"type":"http","url":"https://path.example/mcp"}}}`)
			if tc.defaultFile != "" {
				fs.addFile(filepath.Join(payload, tc.defaultFile), `{"mcpServers":{"default-server":{"url":"https://default.example/mcp"}}}`)
			}
			fs.commit()
			p := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)).Plugins[0]
			if len(p.Components) != 1 || p.Components[0].Name != tc.winner || p.ComponentStatus != model.AgentScanStatusComplete {
				t.Fatalf("native path precedence: %+v", p)
			}
		})
	}
}

func TestCopilotLegacyPreferencesFallback(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			m, fs := newPluginMock()
			root := filepath.Join(testHome, ".copilot")
			catalog := filepath.Join(testHome, "catalog")
			fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[],"extraKnownMarketplaces":{"engineering":{"source":{"source":"directory","path":%q}}},"enabledPlugins":{"review@engineering":true}}`, catalog))
			if malformed {
				fs.addFile(filepath.Join(root, "settings.json"), `{`)
			}
			fs.addFile(filepath.Join(catalog, "marketplace.json"), `{"name":"engineering","owner":{"name":"Example Engineering"},"metadata":{"pluginRoot":"./plugins"},"plugins":[{"name":"review","source":"./review"}]}`)
			fs.addFile(filepath.Join(catalog, "plugins/review/.plugin/plugin.json"), `{"name":"review"}`)
			fs.commit()
			c := copilotContext(t, NewSkillsDetector(m).DetectAll(context.Background(), nil, nil))
			if malformed {
				if len(c.Plugins) != 0 || c.InstallationStatus == model.AgentScanStatusComplete {
					t.Fatalf("malformed preferred settings fell back: %+v", c)
				}
			} else if len(c.Plugins) != 1 || c.Plugins[0].Enablement[0].SourcePath != filepath.Join(root, "config.json") {
				t.Fatalf("legacy fallback missing: %+v", c)
			}
		})
	}
}

func TestCopilotDefinitionLimitAndRecovery(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	payload := filepath.Join(root, "installed-plugins/test")
	state := fmt.Sprintf(`{"installedPlugins":[{"name":"test","marketplace":"","cache_path":%q}]}`, payload)
	fs.addFile(filepath.Join(root, "config.json"), state)
	fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"test"}`)
	fs.addFile(filepath.Join(payload, "skills/check/SKILL.md"), validFrontmatter("check", "Check release"))
	fs.commit()
	d := NewSkillsDetector(m)
	definitions := maxNewDefinitions
	s := &pluginScan{d: d, ctx: context.Background(), home: testHome, goos: model.PlatformLinux, memo: map[string]*skillScan{}, definitions: &definitions, evidence: newPluginEvidence()}
	c := s.detectCopilot()
	if c.Plugins[0].ComponentStatus == model.AgentScanStatusComplete || definitions != maxNewDefinitions {
		t.Fatal("definition cap reported complete or kept growing")
	}
	recovered := copilotContext(t, d.DetectAll(context.Background(), nil, nil))
	if recovered.Plugins[0].ComponentStatus != model.AgentScanStatusComplete || recovered.Plugins[0].InstanceID != c.Plugins[0].InstanceID {
		t.Fatal("recovery changed identity or remained partial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.ctx = ctx
	cancelled := s.detectCopilot()
	if cancelled == nil || cancelled.InstallationStatus == model.AgentScanStatusComplete {
		t.Fatal("cancelled scan authorized removal")
	}
}

func TestCopilotProtectedPayloadAndMCP(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skip("macOS TCC guard")
	}
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	payload := filepath.Join(testHome, "Library/Caches/copilot/private")
	fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"test","marketplace":"","cache_path":%q}]}`, payload))
	fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"test"}`)
	fs.addFile(filepath.Join(payload, "skills/check/SKILL.md"), validFrontmatter("check", "Check release"))
	fs.commit()
	c := copilotContext(t, NewSkillsDetector(m).WithSkipper(tcc.New(testHome)).DetectAll(context.Background(), nil, nil))
	if c.Plugins[0].FilesPresent != nil || c.Plugins[0].ComponentStatus == model.AgentScanStatusComplete || len(c.Plugins[0].Components) != 0 {
		t.Fatalf("protected payload read: %+v", c.Plugins[0])
	}
	m.SetEnv("COPILOT_HOME", payload)
	fs.addFile(filepath.Join(payload, "mcp-config.json"), `{"mcpServers":{"private":{"command":"node"}}}`)
	fs.commit()
	for _, config := range NewMCPDetector(m).WithSkipper(tcc.New(testHome)).DetectEnterprise(context.Background(), nil) {
		if config.ConfigPath == filepath.Join(payload, "mcp-config.json") {
			t.Fatal("protected standalone config read")
		}
	}
}

func TestCopilotPluginMCPSuppression(t *testing.T) {
	m, fs := newPluginMock()
	root := filepath.Join(testHome, ".copilot")
	payload := filepath.Join(root, "installed-plugins/test")
	fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"test","marketplace":"","cache_path":%q}]}`, payload))
	fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"test"}`)
	fs.addFile(filepath.Join(payload, ".mcp.json"), `{"mcpServers":{"docs":{"url":"https://docs.example/mcp"}}}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	unrelated := filepath.Join(testHome, "project/.mcp.json")
	configs := []model.MCPConfig{{ConfigSource: "discovered_mcp", ConfigPath: filepath.Join(payload, ".mcp.json")}, {ConfigSource: "discovered_mcp", ConfigPath: filepath.Join(root, "installed-plugins/orphan/.mcp.json")}, {ConfigSource: "project_mcp", ConfigPath: unrelated}}
	kept := result.ReconcilePluginMCPCommunity(configs)
	if len(kept) != 1 || kept[0].ConfigPath != unrelated {
		t.Fatalf("MCP reconciliation: %+v", kept)
	}
	StripNestedMCPContent(result.Plugins)
	for _, c := range result.Plugins.Contexts {
		for _, p := range c.Plugins {
			for _, component := range p.Components {
				if component.MCPConfig != nil && component.MCPConfig.ConfigContentBase64 != "" {
					t.Fatal("community retained MCP body")
				}
			}
		}
	}
}

func TestCopilotCatalogKeepsIndependentMCP(t *testing.T) {
	m, fs := newPluginMock()
	catalog := filepath.Join(testHome, "catalog")
	fs.addFile(filepath.Join(testHome, ".copilot/settings.json"), fmt.Sprintf(`{"extraKnownMarketplaces":{"engineering":{"source":{"source":"directory","path":%q}}},"enabledPlugins":{"review@engineering":true}}`, catalog))
	fs.addFile(filepath.Join(catalog, "marketplace.json"), `{"name":"engineering","owner":{"name":"Engineering"},"plugins":[{"name":"review","source":"./plugins/review"}]}`)
	fs.addFile(filepath.Join(catalog, "plugins/review/.plugin/plugin.json"), `{"name":"review"}`)
	fs.commit()
	result := NewSkillsDetector(m).DetectAll(context.Background(), nil, nil)
	file := filepath.Join(catalog, ".github/mcp.json")
	configs := result.ReconcilePluginMCP([]model.MCPConfigEnterprise{{ConfigSource: "discovered_mcp", ConfigPath: file}})
	if len(configs) != 1 || configs[0].ConfigPath != file {
		t.Fatalf("independent catalog MCP suppressed: %+v", configs)
	}
}

func TestCopilotRemoteCatalogCoverage(t *testing.T) {
	for _, tc := range []struct{ name, source, dir, location string }{
		{"github", `{"source":"github","repo":"test-org/catalog","ref":"release"}`, "test-org-catalog", "https://github.com/test-org/catalog"},
		{"git", `{"source":"url","url":"https://git.example.com/catalog.git","ref":"release"}`, "https---git-example-com-catalog-git", "https://git.example.com/catalog.git"},
	} {
		for _, state := range []string{"complete", "removed", "missing", "malformed", "wrong name", "protected"} {
			t.Run(tc.name+"/"+state, func(t *testing.T) {
				m, fs := newPluginMock()
				root := filepath.Join(testHome, ".copilot")
				cache := filepath.Join(testHome, "copilot-cache")
				if state == "protected" {
					if runtime.GOOS != model.PlatformDarwin {
						t.Skip("macOS TCC paths")
					}
					cache = filepath.Join(testHome, "Library/Caches/copilot")
				}
				m.SetEnv("COPILOT_CACHE_HOME", cache)
				payload := filepath.Join(root, "installed-plugins/fixture")
				catalog := filepath.Join(cache, "marketplaces", tc.dir, "marketplace.json")
				fs.addFile(filepath.Join(root, "config.json"), fmt.Sprintf(`{"installedPlugins":[{"name":"fixture","marketplace":"engineering","cache_path":%q}]}`, payload))
				fs.addFile(filepath.Join(root, "settings.json"), fmt.Sprintf(`{"extraKnownMarketplaces":{"engineering":{"source":%s}}}`, tc.source))
				fs.addFile(filepath.Join(payload, ".plugin/plugin.json"), `{"name":"fixture"}`)
				if state != "removed" {
					fs.addFile(filepath.Join(payload, "skills/check/SKILL.md"), validFrontmatter("check", "Check releases"))
					fs.addFile(filepath.Join(payload, ".mcp.json"), `{"mcpServers":{"docs":{"command":"node"}}}`)
				}
				switch state {
				case "missing":
				case "malformed":
					fs.addFile(catalog, `{`)
				case "wrong name":
					fs.addFile(catalog, `{"name":"unrelated","owner":{"name":"Example"},"plugins":[{"name":"fixture","source":"./plugins/fixture"}]}`)
				default:
					fs.addFile(catalog, `{"name":"engineering","owner":{"name":"Example"},"metadata":{"pluginRoot":"./packages"},"plugins":[{"name":"fixture","source":"./plugins/fixture","mcpServers":{"ignored":{"command":"ignored"}}}]}`)
				}
				fs.commit()
				c := copilotContext(t, NewSkillsDetector(m).WithSkipper(tcc.New(testHome)).DetectAll(context.Background(), nil, nil))
				if len(c.Plugins) != 1 {
					t.Fatalf("registry installation lost: %+v", c)
				}
				p := c.Plugins[0]
				complete := state == "complete" || state == "removed"
				if (p.ComponentStatus == model.AgentScanStatusComplete) != complete {
					t.Fatalf("component coverage: %+v", p)
				}
				want := 2
				if state == "removed" {
					want = 0
				}
				if len(p.Components) != want {
					t.Fatalf("readable components lost or catalog fallback invented: %+v", p.Components)
				}
				if complete && (p.Source == nil || p.Source.Location != tc.location || p.Source.Subdirectory != "packages/plugins/fixture" || p.Source.RequestedRef != "release" || c.MarketplaceStatus != model.AgentScanStatusComplete) {
					t.Fatalf("remote provenance: %+v / %+v", p, c)
				}
			})
		}
	}
}

func TestCopilotNativeCachePaths(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`"test-org/catalog"`, "test-org-catalog"},
		{`{"source":"github","repo":"Test_Org/Catalog.git","ref":"release"}`, "Test_Org-Catalog.git"},
		{`{"source":"url","url":"https://example.com/a_b.git"}`, "https---example-com-a-b-git"},
	} {
		cache := filepath.Join(testHome, "cache")
		if got := copilotCatalogRoot(json.RawMessage(tc.source), cache); got != filepath.Join(cache, "marketplaces", tc.want) {
			t.Errorf("source %s: %s", tc.source, got)
		}
	}
}
