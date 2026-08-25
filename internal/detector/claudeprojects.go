package detector

import (
	"encoding/json"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// discoverClaudeProjects reads the "projects" map from ~/.claude.json and
// returns its keys — the absolute root paths of every project the user has
// opened in Claude Code. This is Claude Code's own project registry and the
// highest-signal source of project roots for per-project scanning (MCP configs,
// agent skills, …).
//
// It never fails a scan: any read error, parse error, or empty/missing map
// yields a nil slice. Paths are returned verbatim and unsorted — callers that
// need determinism must sort/dedupe (both the MCP and skills detectors do).
//
// homeDir is resolved via getHomeDir(exec) internally so callers need not thread
// it through; the result is identical to expanding "~/.claude.json" against the
// scanning user's home.
func discoverClaudeProjects(exec executor.Executor) []string {
	claudeJSONPath := expandTilde("~/.claude.json", getHomeDir(exec))

	content, err := exec.ReadFile(claudeJSONPath)
	if err != nil || len(content) == 0 {
		return nil
	}

	var parsed struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil || len(parsed.Projects) == 0 {
		return nil
	}

	paths := make([]string, 0, len(parsed.Projects))
	for projectPath := range parsed.Projects {
		paths = append(paths, projectPath)
	}
	return paths
}
