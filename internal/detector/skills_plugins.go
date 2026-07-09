package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// walkPlugins expands the plugin roots. It depth-bounds-walks the two
// Claude Code plugin subtrees (~/.claude/plugins/{cache,repos}) for (a) skills/
// directories and (b) .claude-plugin/plugin.json manifests whose "skills" array
// names extra dirs (resolved relative to the plugin root). It NEVER descends
// into plugins/marketplaces/ — that is the catalog of available-but-not-
// installed plugins, and inventorying it would report skills the user never
// installed. Returned roots are enumerated like any other root, tagged with the
// owning plugin name.
func (d *SkillsDetector) walkPlugins(ctx context.Context, info *model.AgentSkillScanInfo) []skillsRoot {
	home := getHomeDir(d.exec)
	pluginsBase := filepath.Join(home, ".claude", "plugins")
	bases := []string{
		filepath.Join(pluginsBase, "cache"),
		filepath.Join(pluginsBase, "repos"),
	}

	var roots []skillsRoot
	seen := map[string]bool{}
	addRoot := func(dir, pluginName string) {
		if !d.exec.DirExists(dir) {
			return
		}
		resolved := d.resolvePath(dir)
		if seen[resolved] {
			return
		}
		seen[resolved] = true
		roots = append(roots, skillsRoot{
			path: dir, source: "claude_plugin", agent: "claude-code", scope: "global", pluginName: pluginName,
		})
		info.RootsScanned = append(info.RootsScanned, dir)
	}

	dirsVisited := 0
	for _, base := range bases {
		if !d.exec.DirExists(base) {
			continue
		}
		var walk func(cur string, depth int)
		walk = func(cur string, depth int) {
			if depth > maxSkillWalkDepth || ctx.Err() != nil {
				return
			}
			dirsVisited++
			if dirsVisited > maxDirsPerRoot {
				info.Truncated = true
				d.addError(info, fmt.Sprintf("plugin walk truncated at %d dirs", maxDirsPerRoot))
				return
			}
			entries, err := d.exec.ReadDir(cur)
			if err != nil {
				return
			}

			// A .claude-plugin/plugin.json here declares the owning plugin and
			// may list extra skill dirs relative to the plugin root.
			if filepath.Base(cur) == ".claude-plugin" {
				if _, ok := findFileEntry(entries, "plugin.json"); ok {
					d.addManifestSkillDirs(filepath.Join(cur, "plugin.json"), filepath.Dir(cur), addRoot)
				}
			}

			for _, name := range sortedEntryNames(entries) {
				if name == "marketplaces" || name == ".git" || name == "node_modules" {
					continue
				}
				e := entryByName(entries, name)
				if e == nil || e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
					continue
				}
				child := filepath.Join(cur, name)
				if name == "skills" {
					// enumerateRoot applies the SKILL.md criterion inside; don't
					// descend further here.
					addRoot(child, filepath.Base(filepath.Dir(child)))
					continue
				}
				walk(child, depth+1)
			}
		}
		walk(base, 0)
	}
	return roots
}

// addManifestSkillDirs reads a plugin.json and registers each string entry in
// its "skills" array as a skills root, resolved relative to pluginRoot. Unknown
// and non-string entries are ignored (lenient parse). The plugin's declared
// "name" is used as the owning plugin name when present.
func (d *SkillsDetector) addManifestSkillDirs(manifestPath, pluginRoot string, addRoot func(dir, pluginName string)) {
	// Bound the read like every other file the detector touches — an oversized
	// .claude-plugin/plugin.json in an installed plugin must not balloon RSS.
	if fi, err := d.exec.Stat(manifestPath); err == nil && fi.Size() > maxJSONConfigBytes {
		return
	}
	content, err := d.exec.ReadFile(manifestPath)
	if err != nil || len(content) == 0 {
		return
	}
	var manifest struct {
		Name   string `json:"name"`
		Skills []any  `json:"skills"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return
	}
	pluginName := manifest.Name
	if pluginName == "" {
		pluginName = filepath.Base(pluginRoot)
	}
	cleanRoot := filepath.Clean(pluginRoot)
	for _, s := range manifest.Skills {
		rel, ok := s.(string)
		if !ok || rel == "" {
			continue
		}
		dir := filepath.Join(pluginRoot, filepath.FromSlash(rel))
		// Clamp to the plugin root: a "skills" entry containing ".." must not
		// escape the plugin folder (the contract is "resolved relative to the
		// plugin root"). filepath.Join already cleans, so a "../" climbing above
		// cleanRoot is the only possible escape — reject it.
		if dir != cleanRoot && !strings.HasPrefix(dir, cleanRoot+string(os.PathSeparator)) {
			continue
		}
		addRoot(dir, pluginName)
	}
}

// findFileEntry returns the entry for a regular file named `name` (exact match)
// if present.
func findFileEntry(entries []os.DirEntry, name string) (os.DirEntry, bool) {
	for _, e := range entries {
		if !e.IsDir() && e.Name() == name {
			return e, true
		}
	}
	return nil, false
}

// entryByName returns the entry named `name`, or nil.
func entryByName(entries []os.DirEntry, name string) os.DirEntry {
	for _, e := range entries {
		if e.Name() == name {
			return e
		}
	}
	return nil
}
