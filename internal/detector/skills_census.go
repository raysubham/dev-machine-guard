package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// skillScan is the per-skill collected result, memoized per resolved skill-dir
// path within a run so a skill exposed through N symlinked roots is read,
// parsed, and hashed exactly once.
type skillScan struct {
	meta   skillMeta
	census *skillCensus
}

// skillCensus holds the per-skill stat-only file census. Every field is derived
// from ReadDir + Stat — no file bytes are read here. The skill's only hash
// (skill_md_hash) comes from the SKILL.md already read during frontmatter parse,
// not from this walk.
type skillCensus struct {
	fileCount         int
	codeFileCount     int
	symlinkCount      int
	totalSizeBytes    int64
	hasPluginManifest bool
	lastModified      int64
}

// census walks a skill directory (depth ≤10, never following symlinks) and
// collects only stat-derivable facts: file/code/symlink counts, total size, max
// mtime, and whether a .claude-plugin/plugin.json is present. It reads no file
// contents. It excludes .git/**, .DS_Store and Thumbs.db. ctx is checked per
// directory so the 60s phase budget truncates gracefully.
func (d *SkillsDetector) census(ctx context.Context, dir string) *skillCensus {
	c := &skillCensus{}

	var walk func(cur, rel string, depth int)
	walk = func(cur, rel string, depth int) {
		if depth > maxSkillWalkDepth || ctx.Err() != nil {
			return
		}
		entries, err := d.exec.ReadDir(cur)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			// Exclude the VCS tree, vendored deps, and OS cruft from the census —
			// matches the discovery walk's hygiene and keeps the stat-only census
			// fast even when a skill vendors a large node_modules.
			if name == ".git" || name == "node_modules" || hashExcludedNames[name] {
				continue
			}
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			childAbs := filepath.Join(cur, name)

			if e.Type()&os.ModeSymlink != 0 {
				c.symlinkCount++
				continue // never follow symlinks intra-skill (cycles, ~/ escape)
			}
			if e.IsDir() {
				walk(childAbs, childRel, depth+1)
				continue
			}
			fi, err := d.exec.Stat(childAbs)
			if err != nil {
				continue // TOCTOU: file vanished mid-walk — re-stat and skip
			}
			c.fileCount++
			c.totalSizeBytes += fi.Size()
			if mt := fi.ModTime().Unix(); mt > c.lastModified {
				c.lastModified = mt
			}
			if codeExtensions[strings.ToLower(filepath.Ext(name))] {
				c.codeFileCount++
			}
			if childRel == ".claude-plugin/plugin.json" {
				c.hasPluginManifest = true
			}
		}
	}
	walk(dir, "", 0)
	return c
}
