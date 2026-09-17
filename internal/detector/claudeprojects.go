package detector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// claudeState is the selected content of Claude Code's .claude.json: the
// project registry keys and the recorded skill-use counters. One bounded read
// serves both consumers; nothing else in the file is retained.
type claudeState struct {
	path         string
	projects     []string
	skillUsage   map[string]json.RawMessage
	absent       bool
	code         string // whole-file read/parse failure
	projectsCode string
	usageCode    string
}

// readClaudeState reads <dir>/.claude.json through the same gate as the lock
// files: protected-path check, regular-file check, size cap, then the read.
func readClaudeState(exec executor.Executor, skipper *tcc.Skipper, dir string) claudeState {
	st := claudeState{path: filepath.Join(dir, ".claude.json")}
	if skipper.WithinProtected(st.path) {
		st.code = model.AgentScanErrUnsafePath
		return st
	}
	exec = exec.GuardedFiles([]string{dir}, func(p string) string {
		if skipper.WithinProtected(p) {
			return "tcc_protected"
		}
		return ""
	}, maxJSONConfigBytes)
	fi, err := exec.Stat(st.path)
	if errors.Is(err, os.ErrNotExist) {
		st.absent = true
		return st
	}
	if err != nil {
		st.code = readCode(err)
		return st
	}
	switch {
	case !fi.Mode().IsRegular():
		st.code = model.AgentScanErrReadFailed
		return st
	case fi.Size() > maxJSONConfigBytes:
		st.code = model.AgentScanErrLimitExceeded
		return st
	}
	content, err := exec.ReadFile(st.path)
	if err != nil {
		st.code = model.AgentScanErrReadFailed
		return st
	}
	if len(content) > maxJSONConfigBytes {
		st.code = model.AgentScanErrLimitExceeded
		return st
	}
	var parsed *struct {
		Projects   json.RawMessage `json:"projects"`
		SkillUsage json.RawMessage `json:"skillUsage"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil || parsed == nil {
		st.code = model.AgentScanErrParseFailed
		return st
	}
	var projects map[string]json.RawMessage
	if len(parsed.Projects) > 0 && (json.Unmarshal(parsed.Projects, &projects) != nil || projects == nil) {
		st.projectsCode = model.AgentScanErrParseFailed
	} else {
		for p := range projects {
			st.projects = append(st.projects, p)
		}
	}
	if len(parsed.SkillUsage) > 0 && (json.Unmarshal(parsed.SkillUsage, &st.skillUsage) != nil || st.skillUsage == nil) {
		st.usageCode = model.AgentScanErrParseFailed
	}
	return st
}

// discoverClaudeProjects returns the absolute root paths of every project the
// user has opened in Claude Code, verbatim and unsorted. Any failure yields nil.
func discoverClaudeProjects(exec executor.Executor) []string {
	return readClaudeState(exec, nil, getHomeDir(exec)).projects
}

// ---------------------------------------------------------------------------
// Recorded skill usage
// ---------------------------------------------------------------------------

var strictUintRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// strictUint parses a JSON number that is a plain non-negative integer no
// larger than max. Fractions, exponents, strings and negatives are rejected.
func strictUint(raw json.RawMessage, max int64) (int64, bool) {
	if !strictUintRE.Match(raw) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n > max {
		return 0, false
	}
	return n, true
}

// usageSource projects one state file's skillUsage map into a wire source. Each
// entry is validated on its own; a rejected entry makes the source partial
// without touching the valid keys beside it.
func (s *pluginScan) usageSource(st claudeState, status string) model.SkillUsageSource {
	src := model.SkillUsageSource{
		SourceID: s.usageSourceID(model.AgentClaudeCode, st.path), Agent: model.AgentClaudeCode, SourcePath: st.path,
		Status: status, AgentVersion: s.d.agentVersions[model.AgentClaudeCode],
		Counters: []model.SkillUsageCounter{}, Errors: []model.AgentScanError{},
	}
	code := st.code
	if code == "" {
		code = st.usageCode
	}
	if code != "" {
		src.Status = model.AgentScanStatusError
		scanError(&src.Errors, model.AgentScanError{Code: code, SourcePath: st.path})
		return src
	}
	keys := make([]string, 0, len(st.skillUsage))
	for k := range st.skillUsage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(src.Counters) >= maxUsageCounters {
			degrade(&src.Status, model.AgentScanStatusPartial)
			scanError(&src.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: st.path})
			break
		}
		var entry struct {
			UsageCount json.RawMessage `json:"usageCount"`
			LastUsedAt json.RawMessage `json:"lastUsedAt"`
		}
		count, ok := int64(0), key != "" && len(key) <= maxNameBytes && json.Unmarshal(st.skillUsage[key], &entry) == nil
		if ok {
			count, ok = strictUint(entry.UsageCount, maxRecordedUses)
		}
		var last *int64
		if ok && len(entry.LastUsedAt) > 0 && string(entry.LastUsedAt) != "null" {
			var ms int64
			if ms, ok = strictUint(entry.LastUsedAt, maxRecordedUses); ok {
				last = &ms
			}
		}
		if !ok {
			degrade(&src.Status, model.AgentScanStatusPartial)
			scanError(&src.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: st.path})
			continue
		}
		src.Counters = append(src.Counters, model.SkillUsageCounter{RawKey: key, RecordedUses: count, LastRecordedUseAtMs: last})
	}
	return src
}

// collectClaudeUsage builds the usage envelope from the home state file and,
// when a custom configuration root is visible, that root's state file. The
// custom layout is not a verified client fixture, so its coverage stays partial.
func (s *pluginScan) collectClaudeUsage(homeState claudeState) *model.AgentSkillUsageScan {
	var sources []model.SkillUsageSource
	if !homeState.absent {
		sources = append(sources, s.usageSource(homeState, model.AgentScanStatusComplete))
	}
	if cfg := s.d.exec.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
		if st := readClaudeState(s.d.exec, s.d.skipper, filepath.Clean(cfg)); !st.absent && st.path != homeState.path {
			sources = append(sources, s.usageSource(st, model.AgentScanStatusPartial))
		}
	}
	if len(sources) == 0 {
		return nil
	}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].SourcePath < sources[j].SourcePath })
	if len(sources) > maxUsageSources {
		sources = sources[:maxUsageSources]
	}
	remaining, errors := maxUsageCounters, 0
	for i := range sources {
		source := &sources[i]
		if len(source.Counters) > remaining {
			source.Counters = source.Counters[:remaining]
			degrade(&source.Status, model.AgentScanStatusPartial)
			scanError(&source.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: source.SourcePath})
		}
		remaining -= len(source.Counters)
		errors = capErrors(&source.Errors, errors)
	}
	scan := &model.AgentSkillUsageScan{SchemaVersion: agentPluginsSchemaVersion, CollectedAtMs: s.now.UnixMilli(), Sources: sources}
	if encodedSize(scan) > maxEnvelopeBytes {
		for i := len(scan.Sources) - 1; i >= 0 && encodedSize(scan) > maxEnvelopeBytes; i-- {
			source := &scan.Sources[i]
			degrade(&source.Status, model.AgentScanStatusPartial)
			scanError(&source.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: source.SourcePath})
			for len(source.Counters) > 0 && encodedSize(scan) > maxEnvelopeBytes {
				source.Counters = source.Counters[:len(source.Counters)/2]
			}
		}
	}
	errors = 0
	for i := range scan.Sources {
		errors = capErrors(&scan.Sources[i].Errors, errors)
	}
	return scan
}
