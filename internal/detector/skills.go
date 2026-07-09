package detector

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Caps and budgets. A hostile skill folder must
// never DoS the run or balloon the payload; every walk and read is bounded.
const (
	maxSkillWalkDepth   = 10      // recursive discovery + intra-skill walk
	maxDirsPerRoot      = 2000    // dirs visited per root before truncating
	maxSkillsPerRoot    = 500     // skill dirs emitted per root before truncating
	maxProjects         = 200     // project roots probed (sorted, deterministic)
	maxSkillMDReadBytes = 1 << 20 // 1 MiB SKILL.md frontmatter read cap
	maxJSONConfigBytes  = 5 << 20 // 5 MiB cap on a parsed JSON config (lock file / plugin manifest)
	maxDescriptionRunes = 1024    // standard hard max
	maxNameRunes        = 128     // standard max is 64; we tolerate + record nonconforming
	maxLicenseRunes     = 128
	maxScanErrors       = 50               // bounded error list
	maxScanErrorLen     = 256              // per-error char cap
	skillsPhaseBudget   = 60 * time.Second // overall phase deadline
)

// codeExtensions are files agents execute directly.
var codeExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".sh": true,
}

// hashExcludedNames are files excluded from the census (VCS noise / OS cruft).
// Everything else — including hidden files — is counted, since hidden files can
// hide payloads and are legitimate census members.
var hashExcludedNames = map[string]bool{
	".DS_Store": true,
	"Thumbs.db": true,
}

// SkillsDetector discovers installed AI agent skills across every recognized
// root (global, project, plugin, and skills.sh lock-managed). It performs pure
// filesystem reads only — no subprocesses — so it needs no user shell.
type SkillsDetector struct {
	exec executor.Executor
}

// NewSkillsDetector constructs a SkillsDetector.
func NewSkillsDetector(exec executor.Executor) *SkillsDetector {
	return &SkillsDetector{exec: exec}
}

// CollectProjectRoots flattens the Path of one or more ProjectInfo lists into a
// deduplicated []string, dropping empties. It is the bridge from the node and
// python project scanners to the skills detector's extraProjectRoots argument
// on the community scan path (internal/scan). The enterprise telemetry path has
// its own twin (telemetry.collectProjectRoots) because it carries NodeScanResult
// rather than ProjectInfo. First occurrence wins for ordering — the skills
// detector re-resolves, re-dedupes and sorts internally, so callers need not.
func CollectProjectRoots(lists ...[]model.ProjectInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, p := range list {
			if p.Path == "" || seen[p.Path] {
				continue
			}
			seen[p.Path] = true
			out = append(out, p.Path)
		}
	}
	return out
}

// skillsRoot is one resolved, existing directory to enumerate for skills.
type skillsRoot struct {
	path        string // absolute, existing directory
	source      string // model.AgentSkill.Source value
	agent       string // owning directory convention
	scope       string // "global" | "project" | "system"
	projectPath string // project root for project scope; "" otherwise
	pluginName  string // owning plugin for claude_plugin roots
	excludeName string // a direct child name to skip (codex .system carve-out)
}

// Detect discovers skills across all roots. extraProjectRoots are additional
// project roots surfaced by the node/python scanners (may be nil); the detector
// also self-discovers projects from ~/.claude.json. It never returns a hard
// error — every failure degrades to an AgentSkillScanInfo.Errors entry and the
// phase keeps going. A non-nil scan info is always returned (the backend "scan
// ran" sentinel), even on partial results.
func (d *SkillsDetector) Detect(ctx context.Context, extraProjectRoots []string) (skills []model.AgentSkill, info *model.AgentSkillScanInfo) {
	start := time.Now()
	info = &model.AgentSkillScanInfo{}

	ctx, cancel := context.WithTimeout(ctx, skillsPhaseBudget)
	defer cancel()

	// Defense-in-depth: the walk is designed panic-free — every per-root and
	// per-skill failure degrades to an Errors entry rather than a panic — but if
	// one still escapes we must NOT leave AgentSkillScan nil. A nil scan info
	// means "no information" and would strand the device's skill state; a non-nil
	// info (even with partial or zero records) means "scan ran". Record the panic
	// and finalize whatever we gathered. Registered after `defer cancel()` so it
	// runs first (LIFO), recovering before the context is torn down; `skills` is
	// the named accumulator below, so partial discovery survives the unwind.
	// Containing the panic here keeps a skills bug from failing the whole
	// telemetry run via telemetry.Run. The recorded error also marks an
	// early-panic "scan ran, 0 skills" result as partial rather than complete.
	defer func() {
		if r := recover(); r != nil {
			d.addError(info, fmt.Sprintf("panic in skills detect: %v", r))
			sortSkills(skills)
			info.SkillsFound = len(skills)
			info.DurationMs = time.Since(start).Milliseconds()
		}
	}()

	// Per-resolved-path census+hash memo: a skill linked from N roots is hashed
	// exactly once and all N records share the result (symlink dedup).
	memo := map[string]*skillScan{}

	// Global + system roots.
	for _, root := range d.resolveGlobalRoots(info) {
		skills = append(skills, d.enumerateRoot(ctx, root, info, memo)...)
	}

	// Plugin roots: walk the two plugin subtrees for skills/ dirs and
	// plugin.json-declared skill dirs.
	for _, root := range d.walkPlugins(ctx, info) {
		skills = append(skills, d.enumerateRoot(ctx, root, info, memo)...)
	}

	// Project roots: Claude Code registry ∪ node/python roots, deduped, capped,
	// then the candidate skill dirs are probed on each.
	projects := d.discoverProjects(extraProjectRoots, info)
	info.ProjectsScanned = len(projects)
	for _, proj := range projects {
		for _, root := range d.resolveProjectRoots(proj, info) {
			skills = append(skills, d.enumerateRoot(ctx, root, info, memo)...)
		}
	}

	// Lock files: parse the global lock + each project lock, then join
	// provenance onto folder records and synthesize lock-only records.
	skills = d.applyLocks(skills, projects, info)

	// Deterministic ordering: (source, project_path, skill_slug).
	sortSkills(skills)

	info.SkillsFound = len(skills)
	info.DurationMs = time.Since(start).Milliseconds()
	return skills, info
}

// resolveGlobalRoots expands the global/system source table for the
// scanning user's home, per-OS, filtering to directories that exist. Existing
// roots are appended to info.RootsScanned.
func (d *SkillsDetector) resolveGlobalRoots(info *model.AgentSkillScanInfo) []skillsRoot {
	home := getHomeDir(d.exec)
	win := d.exec.GOOS() == model.PlatformWindows
	var roots []skillsRoot

	add := func(pathStr, source, agent, scope, excludeName string) {
		if pathStr == "" || !d.exec.DirExists(pathStr) {
			return
		}
		roots = append(roots, skillsRoot{
			path: pathStr, source: source, agent: agent, scope: scope, excludeName: excludeName,
		})
		info.RootsScanned = append(info.RootsScanned, pathStr)
	}

	// claude_user: ~/.claude/skills, honoring CLAUDE_CONFIG_DIR when the env
	// var is visible to this process (not under a daemon that can't see it).
	claudeBase := filepath.Join(home, ".claude")
	if cfg := d.exec.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
		claudeBase = cfg
	}
	add(filepath.Join(claudeBase, "skills"), "claude_user", "claude-code", "global", "")

	// agents_user: ~/.agents/skills (skills.sh + cross-client convention).
	add(filepath.Join(home, ".agents", "skills"), "agents_user", "shared", "global", "")

	// codex_user: ~/.codex/skills, excluding the vendor .system subdir from
	// the normal walk; .system is emitted separately as codex_system.
	codexSkills := filepath.Join(home, ".codex", "skills")
	add(codexSkills, "codex_user", "codex", "global", ".system")
	add(filepath.Join(codexSkills, ".system"), "codex_system", "codex", "global", "")

	// opencode_user: ~/.config/opencode/{skills,skill} (both honored).
	add(filepath.Join(home, ".config", "opencode", "skills"), "opencode_user", "opencode", "global", "")
	add(filepath.Join(home, ".config", "opencode", "skill"), "opencode_user", "opencode", "global", "")

	// codex_admin: machine-global admin scope.
	if win {
		add(resolveEnvPath(d.exec, `%ProgramData%\OpenAI\Codex`), "codex_admin", "codex", "system", "")
	} else {
		add("/etc/codex/skills", "codex_admin", "codex", "system", "")
	}

	// cursor_user: ~/.cursor/skills.
	add(filepath.Join(home, ".cursor", "skills"), "cursor_user", "cursor", "global", "")

	return roots
}

// resolveProjectRoots expands the project-relative skill dirs for one project
// root, filtering to existing dirs and appending them to info.RootsScanned.
func (d *SkillsDetector) resolveProjectRoots(project string, info *model.AgentSkillScanInfo) []skillsRoot {
	var roots []skillsRoot
	add := func(rel []string, source, agent string) {
		p := filepath.Join(append([]string{project}, rel...)...)
		if !d.exec.DirExists(p) {
			return
		}
		roots = append(roots, skillsRoot{
			path: p, source: source, agent: agent, scope: "project", projectPath: project,
		})
		info.RootsScanned = append(info.RootsScanned, p)
	}
	add([]string{".claude", "skills"}, "claude_project", "claude-code")
	add([]string{".agents", "skills"}, "agents_project", "shared")
	add([]string{".opencode", "skills"}, "opencode_project", "opencode")
	add([]string{".opencode", "skill"}, "opencode_project", "opencode")
	add([]string{".cursor", "skills"}, "cursor_project", "cursor")
	return roots
}

// discoverProjects unions Claude Code's project registry with node/python
// roots, dedupes on absolute symlink-resolved path, drops stale (missing) dirs
// and the home directory itself, and caps at maxProjects (sorted,
// deterministic). Home is excluded because its dotfile skill dirs
// (~/.claude/skills, ~/.agents/skills, …) are already the global roots; treating
// home as a project would re-scan those same dirs and re-emit every global skill
// as a project-scoped duplicate.
func (d *SkillsDetector) discoverProjects(extra []string, info *model.AgentSkillScanInfo) []string {
	seen := map[string]bool{}
	home := d.resolvePath(getHomeDir(d.exec))
	var out []string
	consider := func(p string) {
		if p == "" {
			return
		}
		resolved := d.resolvePath(p)
		if home != "" && resolved == home {
			return // home is never a project — its skill dirs are the global roots
		}
		if seen[resolved] {
			return
		}
		seen[resolved] = true
		if !d.exec.DirExists(resolved) {
			return // stale ~/.claude.json entry — skip silently
		}
		out = append(out, resolved)
	}
	for _, p := range discoverClaudeProjects(d.exec) {
		consider(p)
	}
	for _, p := range extra {
		consider(p)
	}
	sort.Strings(out)
	if len(out) > maxProjects {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("project roots truncated: %d discovered, capped at %d", len(out), maxProjects))
		out = out[:maxProjects]
	}
	return out
}

// enumerateRoot performs the depth-bounded recursive SKILL.md discovery
// under one root: a directory directly containing a SKILL.md (case-sensitive)
// is a skill (stop-at-skill), .git/node_modules are never descended, symlinked
// skill dirs are resolved, and the 2000-dir / 500-skill caps trip truncation.
func (d *SkillsDetector) enumerateRoot(ctx context.Context, root skillsRoot, info *model.AgentSkillScanInfo, memo map[string]*skillScan) []model.AgentSkill {
	var records []model.AgentSkill
	dirsVisited := 0
	rootTruncated := false

	var walk func(dir, rel string, depth int)
	walk = func(dir, rel string, depth int) {
		if rootTruncated || ctx.Err() != nil {
			return
		}
		dirsVisited++
		if dirsVisited > maxDirsPerRoot {
			rootTruncated = true
			info.Truncated = true
			d.addError(info, fmt.Sprintf("root %s: dir walk truncated at %d dirs", root.path, maxDirsPerRoot))
			return
		}

		entries, err := d.exec.ReadDir(dir)
		if err != nil {
			d.addError(info, fmt.Sprintf("read dir %s: %v", dir, err))
			return
		}

		// Stop-at-skill: if this dir (below the root) directly contains a
		// SKILL.md, it is a skill and its subdirs are its own files, not
		// separate skills.
		if depth > 0 {
			if mdName, ok := findSkillMD(entries); ok {
				if !d.emitSkill(ctx, &records, root, dir, rel, mdName, false, info, memo) {
					rootTruncated = true
				}
				return
			}
		}

		// Recurse into subdirectories (sorted for deterministic truncation).
		entMap := make(map[string]os.DirEntry, len(entries))
		for _, e := range entries {
			entMap[e.Name()] = e
		}
		for _, name := range sortedEntryNames(entries) {
			if rootTruncated || ctx.Err() != nil {
				return
			}
			if name == ".git" || name == "node_modules" {
				continue
			}
			if depth == 0 && root.excludeName != "" && name == root.excludeName {
				continue // codex .system carve-out
			}
			ent := entMap[name]
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			childDir := filepath.Join(dir, name)

			// Depth cap applies to the skill entry at this level, symlinked or
			// not: a symlinked skill dir at level >10 must be excluded exactly
			// as a regular dir at that level is (depth ≤10). Checked before
			// the symlink branch so both paths honor the same bound.
			if depth+1 > maxSkillWalkDepth {
				continue
			}

			if ent.Type()&os.ModeSymlink != 0 {
				d.handleSymlinkEntry(ctx, &records, root, childDir, childRel, info, memo, &rootTruncated)
				continue
			}
			if !ent.IsDir() {
				continue // a plain file directly under a dir is not a skill
			}
			walk(childDir, childRel, depth+1)
		}
	}

	walk(root.path, "", 0)
	return records
}

// handleSymlinkEntry resolves a symlinked directory entry; if its target is a
// skill dir it is recorded with is_symlink=true (the skills.sh layout), the
// root-relative path is the link location, and the resolved target is the skill
// dir path. Symlinks are never descended through — cycles and ~/ escapes are
// impossible.
func (d *SkillsDetector) handleSymlinkEntry(ctx context.Context, records *[]model.AgentSkill, root skillsRoot, linkPath, rel string, info *model.AgentSkillScanInfo, memo map[string]*skillScan, rootTruncated *bool) {
	target, err := d.exec.EvalSymlinks(linkPath)
	if err != nil || target == "" {
		d.addError(info, fmt.Sprintf("dangling symlink %s: %v", linkPath, err))
		return
	}
	if !d.exec.DirExists(target) {
		return
	}
	entries, err := d.exec.ReadDir(target)
	if err != nil {
		d.addError(info, fmt.Sprintf("read symlink target %s: %v", target, err))
		return
	}
	mdName, ok := findSkillMD(entries)
	if !ok {
		return // symlink to a non-skill dir — not descended
	}
	if !d.emitSkill(ctx, records, root, target, rel, mdName, true, info, memo) {
		*rootTruncated = true
	}
}

// emitSkill builds one AgentSkill record for a discovered skill directory,
// applying the per-root 500-skill cap. dir is the resolved skill directory
// (the symlink target when isSymlink). Returns false when the per-root cap was
// hit (caller should stop enumerating this root).
func (d *SkillsDetector) emitSkill(ctx context.Context, records *[]model.AgentSkill, root skillsRoot, dir, rel, mdName string, isSymlink bool, info *model.AgentSkillScanInfo, memo map[string]*skillScan) bool {
	// Per-root cap. records is this root's own accumulator — enumerateRoot returns
	// a fresh slice per call and every record it holds carries this root's source
	// + project_path — so its length is exactly the count emitted for this root;
	// no need to re-scan and filter it on every emit.
	if len(*records) >= maxSkillsPerRoot {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("root %s: skills truncated at %d", root.path, maxSkillsPerRoot))
		return false
	}

	slug := path.Base(rel)
	mdPath := filepath.Join(dir, mdName)

	rec := model.AgentSkill{
		SkillSlug:     slug,
		SkillName:     slug,
		Agent:         root.agent,
		Source:        root.source,
		Scope:         root.scope,
		ProjectPath:   root.projectPath,
		PluginName:    root.pluginName,
		SkillDirPath:  dir,
		RootRelPath:   rel,
		IsSymlink:     isSymlink,
		SkillMDPath:   mdPath,
		PresentOnDisk: true,
	}

	// Frontmatter + skill_md_hash + stat-only census, all memoized per resolved
	// dir path so a skill exposed through N symlinked roots is read, parsed, and
	// hashed exactly once. SKILL.md is read via the resolved path — the only file
	// the detector ever reads; no other file contents are read.
	resolvedDir := d.resolvePath(dir)
	scan, ok := memo[resolvedDir]
	if !ok {
		scan = &skillScan{
			meta:   d.parseSkillMD(filepath.Join(resolvedDir, mdName)),
			census: d.census(ctx, resolvedDir),
		}
		memo[resolvedDir] = scan
	}
	meta, census := scan.meta, scan.census

	rec.HasFrontmatter = meta.hasFrontmatter
	rec.FrontmatterError = meta.frontmatterError
	if meta.name != "" {
		rec.SkillName = meta.name
	}
	rec.Description = meta.description
	rec.Version = meta.version
	rec.License = meta.license
	rec.AllowedTools = meta.allowedTools
	rec.DisableModelInvocation = meta.disableModelInvoc
	rec.UserInvocableDisabled = meta.userInvocDisabled
	rec.ContextFork = meta.contextFork
	rec.ModelOverride = meta.modelOverride
	rec.HasHooks = meta.hasHooks
	rec.HasShellInjection = meta.hasShellInjection
	rec.SkillMDHash = meta.skillMDHash

	rec.FileCount = census.fileCount
	rec.CodeFileCount = census.codeFileCount
	rec.SymlinkCount = census.symlinkCount
	rec.TotalSizeBytes = census.totalSizeBytes
	rec.HasCode = census.codeFileCount > 0
	rec.HasPluginManifest = census.hasPluginManifest
	rec.LastModified = census.lastModified

	*records = append(*records, rec)
	return true
}

// resolvePath resolves symlinks best-effort; on failure it returns the input
// unchanged (matching EvalSymlinks on a non-symlink).
func (d *SkillsDetector) resolvePath(p string) string {
	if resolved, err := d.exec.EvalSymlinks(p); err == nil && resolved != "" {
		return resolved
	}
	return p
}

// addError appends a bounded scan error (≤50 entries, each ≤256 chars) so a
// hostile filename cannot balloon the payload via error strings.
func (d *SkillsDetector) addError(info *model.AgentSkillScanInfo, msg string) {
	if len(info.Errors) >= maxScanErrors {
		return
	}
	if len(msg) > maxScanErrorLen {
		msg = msg[:maxScanErrorLen]
	}
	info.Errors = append(info.Errors, msg)
}

// findSkillMD reports whether a regular file named exactly "SKILL.md" is
// directly present in entries (case-sensitive), returning that name.
// Discovery is a literal name compare over the directory listing — not an
// open() — so a case-insensitive filesystem does not rescue a lowercase
// skill.md (see anthropics/skills#314). A directory named "SKILL.md" never
// qualifies; only regular files do.
func findSkillMD(entries []os.DirEntry) (string, bool) {
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if e.Name() == "SKILL.md" {
			return e.Name(), true
		}
	}
	return "", false
}

// sortedEntryNames returns the entry names sorted in byte order, so both the
// walk order and any cap-driven truncation are deterministic regardless of the
// order ReadDir yields.
func sortedEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// sortSkills orders records by (source, project_path, skill_slug) for
// deterministic, diff-stable payloads.
func sortSkills(records []model.AgentSkill) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.ProjectPath != b.ProjectPath {
			return a.ProjectPath < b.ProjectPath
		}
		if a.SkillSlug != b.SkillSlug {
			return a.SkillSlug < b.SkillSlug
		}
		// Stable tiebreak so two records sharing the triple (e.g. symlink farm)
		// keep a fixed order across runs.
		return a.RootRelPath < b.RootRelPath
	})
}
