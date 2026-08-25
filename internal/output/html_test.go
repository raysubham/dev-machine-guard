package output

import (
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestHTML_GeneratesFile(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-report.html"
	defer func() { _ = os.Remove(tmpFile) }()

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
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary:          model.Summary{},
	}

	if err := HTML(tmpFile, result); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	html := string(content)
	if !strings.Contains(html, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("missing </html> tag")
	}
	if !strings.Contains(html, "StepSecurity") {
		t.Error("missing StepSecurity title")
	}
}

func TestHTML_PlatformLabels(t *testing.T) {
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
			tmpFile := os.TempDir() + "/test-dmg-platform-" + tt.platform + ".html"
			defer func() { _ = os.Remove(tmpFile) }()

			result := &model.ScanResult{
				ScanTimestamp: 1700000000,
				Device: model.Device{
					Hostname:  "test",
					OSVersion: "1.0",
					Platform:  tt.platform,
				},
			}

			if err := HTML(tmpFile, result); err != nil {
				t.Fatal(err)
			}

			content, _ := os.ReadFile(tmpFile)
			html := string(content)

			if !strings.Contains(html, tt.wantLabel) {
				t.Errorf("platform %q: HTML missing label %q", tt.platform, tt.wantLabel)
			}
		})
	}
}

// htmlAgentSkillsSection slices the Agent Skills table out of the report so
// assertions cannot false-match the "None detected" cells of other tables.
// "Agent Skills <span" anchors on the section <h2>, not the summary card label.
func htmlAgentSkillsSection(t *testing.T, html string) string {
	t.Helper()
	start := strings.Index(html, "Agent Skills <span")
	if start < 0 {
		t.Fatal("HTML missing Agent Skills section header")
	}
	rest := html[start:]
	end := strings.Index(rest, "</table>")
	if end < 0 {
		t.Fatal("HTML missing Agent Skills table close")
	}
	return rest[:end]
}

func TestHTML_AgentSkillsStates(t *testing.T) {
	cases := []struct {
		name       string
		scan       *model.AgentSkillScanInfo
		skills     []model.AgentSkill
		want       string
		wantAbsent []string
	}{
		// Nil scan info = scan never ran (feature gate off), distinct from a
		// completed scan that found nothing.
		{"not scanned", nil, nil, "Not scanned", []string{"None detected"}},
		{"none detected", &model.AgentSkillScanInfo{}, nil, "None detected", []string{"Not scanned"}},
		{"populated", &model.AgentSkillScanInfo{SkillsFound: 1},
			[]model.AgentSkill{{SkillName: "pdf-tools", Agent: "claude-code", Source: "claude_user", Scope: "global"}},
			"pdf-tools", []string{"Not scanned", "None detected"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile := os.TempDir() + "/test-dmg-skills-" + strings.ReplaceAll(tc.name, " ", "-") + ".html"
			defer func() { _ = os.Remove(tmpFile) }()

			result := &model.ScanResult{
				ScanTimestamp:  1700000000,
				Device:         model.Device{Hostname: "test"},
				AgentSkills:    tc.skills,
				AgentSkillScan: tc.scan,
			}
			if err := HTML(tmpFile, result); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(tmpFile)
			if err != nil {
				t.Fatal(err)
			}
			section := htmlAgentSkillsSection(t, string(content))
			if !strings.Contains(section, tc.want) {
				t.Errorf("skills section missing %q: %q", tc.want, section)
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(section, absent) {
					t.Errorf("skills section must not contain %q: %q", absent, section)
				}
			}
		})
	}
}

func TestHTML_ContainsData(t *testing.T) {
	tmpFile := os.TempDir() + "/test-dmg-data.html"
	defer func() { _ = os.Remove(tmpFile) }()

	result := &model.ScanResult{
		ScanTimestamp: 1700000000,
		Device: model.Device{
			Hostname: "my-host",
		},
		AIAgentsAndTools: []model.AITool{
			{Name: "claude-code", Vendor: "Anthropic", Type: "cli_tool", Version: "1.0"},
		},
		IDEInstallations: []model.IDE{},
		IDEExtensions:    []model.Extension{},
		MCPConfigs:       []model.MCPConfig{},
		NodePkgManagers:  []model.PkgManager{},
		NodePackages:     []any{},
		Summary:          model.Summary{AIAgentsAndToolsCount: 1},
	}

	_ = HTML(tmpFile, result)
	content, _ := os.ReadFile(tmpFile)
	html := string(content)

	if !strings.Contains(html, "claude-code") {
		t.Error("missing AI tool name")
	}
	if !strings.Contains(html, "my-host") {
		t.Error("missing hostname")
	}
}
