package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestPretty_ContainsHeaders(t *testing.T) {
	result := &model.ScanResult{
		AgentVersion:     "1.9.1",
		ScanTimestamp:    1700000000,
		ScanTimestampISO: "2023-11-14T22:13:20Z",
		Device: model.Device{
			Hostname:     "test-host",
			SerialNumber: "ABC123",
			OSVersion:    "14.1",
			Platform:     "darwin",
			UserIdentity: "testuser",
		},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		Summary:          model.Summary{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")

	output := buf.String()
	for _, header := range []string{"DEVICE", "SUMMARY", "AI AGENTS", "IDE & AI DESKTOP APPS", "MCP SERVERS", "IDE EXTENSIONS"} {
		if !strings.Contains(output, header) {
			t.Errorf("output missing header: %s", header)
		}
	}
}

func TestPretty_ContainsBanner(t *testing.T) {
	result := &model.ScanResult{
		AgentVersion:     "1.9.1",
		ScanTimestamp:    1700000000,
		Device:           model.Device{Hostname: "test"},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")
	output := buf.String()

	if !strings.Contains(output, "StepSecurity Dev Machine Guard") {
		t.Error("output missing banner title")
	}
}

func TestPretty_ShowsDeviceInfo(t *testing.T) {
	result := &model.ScanResult{
		ScanTimestamp: 1700000000,
		Device: model.Device{
			Hostname:     "my-host",
			SerialNumber: "SN123",
			OSVersion:    "14.1",
			UserIdentity: "dev-user",
		},
		AIAgentsAndTools: []model.AITool{},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")
	output := buf.String()

	for _, expected := range []string{"my-host", "SN123", "14.1", "dev-user"} {
		if !strings.Contains(output, expected) {
			t.Errorf("output missing device info: %s", expected)
		}
	}
}

func TestPretty_PlatformLabels(t *testing.T) {
	tests := []struct {
		platform  string
		wantLabel string
	}{
		{"darwin", "macOS"},
		{"windows", "Windows"},
		{"linux", "Linux"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			result := &model.ScanResult{
				ScanTimestamp: 1700000000,
				Device: model.Device{
					Hostname:  "test",
					OSVersion: "1.0",
					Platform:  tt.platform,
				},
			}

			var buf bytes.Buffer
			_ = Pretty(&buf, result, "never")
			output := buf.String()

			if !strings.Contains(output, tt.wantLabel) {
				t.Errorf("platform %q: output missing label %q", tt.platform, tt.wantLabel)
			}
		})
	}
}

// agentSkillsSection slices the AGENT SKILLS block out of the pretty output so
// assertions cannot false-match the "None detected" lines of other sections.
func agentSkillsSection(t *testing.T, output string) string {
	t.Helper()
	start := strings.Index(output, "AGENT SKILLS")
	end := strings.Index(output, "IDE EXTENSIONS")
	if start < 0 || end < start {
		t.Fatal("output missing AGENT SKILLS / IDE EXTENSIONS headers")
	}
	return output[start:end]
}

func TestPretty_AgentSkillsNotScanned(t *testing.T) {
	// Nil AgentSkillScan means the scan never ran (feature gate off) — rendered
	// as "Not scanned", distinct from a completed scan that found nothing.
	result := &model.ScanResult{
		ScanTimestamp: 1700000000,
		Device:        model.Device{Hostname: "test"},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")

	section := agentSkillsSection(t, buf.String())
	if !strings.Contains(section, "Not scanned") {
		t.Errorf("nil AgentSkillScan must render 'Not scanned', got %q", section)
	}
}

func TestPretty_AgentSkillsNoneDetected(t *testing.T) {
	result := &model.ScanResult{
		ScanTimestamp:  1700000000,
		Device:         model.Device{Hostname: "test"},
		AgentSkillScan: &model.AgentSkillScanInfo{},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")

	section := agentSkillsSection(t, buf.String())
	if !strings.Contains(section, "None detected") {
		t.Errorf("completed empty scan must render 'None detected', got %q", section)
	}
	if strings.Contains(section, "Not scanned") {
		t.Errorf("completed scan must not render 'Not scanned', got %q", section)
	}
}

func TestPretty_AgentSkillsPopulated(t *testing.T) {
	result := &model.ScanResult{
		ScanTimestamp:  1700000000,
		Device:         model.Device{Hostname: "test"},
		AgentSkillScan: &model.AgentSkillScanInfo{SkillsFound: 1},
		AgentSkills: []model.AgentSkill{
			{SkillName: "pdf-tools", Source: "claude_user", Agent: "claude-code", Scope: "global", ManagedBy: "skills.sh"},
		},
	}

	var buf bytes.Buffer
	_ = Pretty(&buf, result, "never")

	section := agentSkillsSection(t, buf.String())
	for _, want := range []string{"pdf-tools", "claude_user", "[skills.sh]"} {
		if !strings.Contains(section, want) {
			t.Errorf("populated skills section missing %q: %q", want, section)
		}
	}
	for _, absent := range []string{"Not scanned", "None detected"} {
		if strings.Contains(section, absent) {
			t.Errorf("populated skills section must not contain %q: %q", absent, section)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"a very long string", 10, "a very ..."},
		{"exactly10!", 10, "exactly10!"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestIdeDisplayName(t *testing.T) {
	tests := map[string]string{
		"vscode":                    "Visual Studio Code",
		"cursor":                    "Cursor",
		"claude_desktop":            "Claude",
		"microsoft_copilot_desktop": "Microsoft Copilot",
		"intellij_idea":             "IntelliJ IDEA",
		"intellij_idea_ce":          "IntelliJ IDEA CE",
		"pycharm":                   "PyCharm",
		"pycharm_ce":                "PyCharm CE",
		"webstorm":                  "WebStorm",
		"goland":                    "GoLand",
		"rider":                     "Rider",
		"phpstorm":                  "PhpStorm",
		"rubymine":                  "RubyMine",
		"clion":                     "CLion",
		"datagrip":                  "DataGrip",
		"fleet":                     "Fleet",
		"android_studio":            "Android Studio",
		"eclipse":                   "Eclipse",
		"xcode":                     "Xcode",
		"unknown":                   "unknown",
	}
	for input, expected := range tests {
		got := ideDisplayName(input)
		if got != expected {
			t.Errorf("ideDisplayName(%q) = %q, want %q", input, got, expected)
		}
	}
}
