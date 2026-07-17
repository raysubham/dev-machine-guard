package telemetry

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// TestCollectProjectRoots_MapsVenvToProjectDir proves the skills bridge maps a
// python venv path up to its project root (skills live under
// <project>/.claude/skills, not <venv>/.claude/skills), dedupes against the node
// root, and drops empties without injecting a bogus "." root.
func TestCollectProjectRoots_MapsVenvToProjectDir(t *testing.T) {
	node := []model.NodeScanResult{{ProjectPath: "/repo"}}
	python := []model.ProjectInfo{
		{Path: "/repo/.venv"},         // maps to /repo — dup of the node root, deduped
		{Path: "/repo/backend/.venv"}, // maps to /repo/backend
		{Path: ""},                    // dropped (no bogus "." root)
	}

	got := collectProjectRoots(node, python)

	want := map[string]bool{"/repo": true, "/repo/backend": true}
	if len(got) != len(want) {
		t.Fatalf("collectProjectRoots = %v, want the 2 roots %v", got, want)
	}
	seen := map[string]int{}
	for _, p := range got {
		seen[p]++
		if !want[p] {
			t.Errorf("unexpected root %q (venv path not mapped to its project dir?)", p)
		}
		if p == "/repo/.venv" || p == "/repo/backend/.venv" {
			t.Errorf("venv dir %q leaked into roots; want its parent", p)
		}
		if p == "." {
			t.Error(`empty venv path produced a bogus "." root`)
		}
	}
	if seen["/repo"] != 1 {
		t.Errorf("/repo should appear once (node root + venv parent deduped), got %d", seen["/repo"])
	}
}
