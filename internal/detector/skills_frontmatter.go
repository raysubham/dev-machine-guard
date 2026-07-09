package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// skillMeta is the parsed result of a SKILL.md frontmatter block plus the
// body-level risk scan.
type skillMeta struct {
	name              string
	description       string
	version           string
	license           string
	modelOverride     string
	allowedTools      []string
	disableModelInvoc bool
	userInvocDisabled bool
	contextFork       bool
	hasHooks          bool
	hasShellInjection bool
	hasFrontmatter    bool
	frontmatterError  string
	skillMDHash       string // hex(sha256(SKILL.md bytes)) — identity/drift key
}

// parseSkillMD reads and parses a SKILL.md: a 1 MiB read cap, lenient
// frontmatter detection, a quote-fix retry for unquoted-colon YAML, and a body
// scan for load-time shell execution. It also derives skillMDHash =
// hex(sha256(bytes)) from the same read (the only hash computed, at zero extra
// I/O). It never fails — malformed skills are surfaced via frontmatterError, not
// hidden.
func (d *SkillsDetector) parseSkillMD(mdPath string) skillMeta {
	var m skillMeta

	if fi, err := d.exec.Stat(mdPath); err != nil {
		m.frontmatterError = "unreadable"
		return m
	} else if fi.Size() > maxSkillMDReadBytes {
		m.frontmatterError = "file_too_large"
		return m
	}

	content, err := d.exec.ReadFile(mdPath)
	if err != nil {
		m.frontmatterError = "unreadable"
		return m
	}

	// skill_md_hash over the raw on-disk bytes (no normalization) so byte-
	// identical SKILL.md on any two machines/OSes hashes identically.
	sum := sha256.Sum256(content)
	m.skillMDHash = hex.EncodeToString(sum[:])

	fm, body, ok := splitFrontmatter(string(content))
	if !ok {
		// No frontmatter at all: scan the whole file as body, and report the
		// missing identity rather than dropping the skill.
		m.hasShellInjection = hasLoadTimeShellExec(string(content))
		m.frontmatterError = "missing_name"
		return m
	}
	m.hasFrontmatter = true
	m.hasShellInjection = hasLoadTimeShellExec(body)

	parsed, perr := parseYAMLMap(fm)
	if perr != nil {
		// Standard compatibility fallback: wrap unquoted colon-bearing values
		// and retry once (e.g. `description: Use when: …`).
		parsed, perr = parseYAMLMap(quoteFixYAML(fm))
		if perr != nil {
			m.frontmatterError = "invalid_yaml"
			return m
		}
	}

	m.name = truncRunes(stringField(parsed, "name"), maxNameRunes)
	m.description = truncRunes(stringField(parsed, "description"), maxDescriptionRunes)
	m.license = truncRunes(stringField(parsed, "license"), maxLicenseRunes)
	m.version = stringField(parsed, "version")
	if m.version == "" {
		if md, ok := parsed["metadata"].(map[string]any); ok {
			m.version = stringFromAny(md["version"])
		}
	}
	m.allowedTools = normalizeAllowedTools(parsed["allowed-tools"])
	m.disableModelInvoc = boolField(parsed, "disable-model-invocation")
	if v, ok := parsed["user-invocable"]; ok {
		if b, ok := v.(bool); ok && !b {
			m.userInvocDisabled = true
		}
	}
	if stringField(parsed, "context") == "fork" {
		m.contextFork = true
	}
	m.modelOverride = stringField(parsed, "model")
	if _, ok := parsed["hooks"]; ok {
		m.hasHooks = true
	}

	// Frontmatter health (structural errors already returned above).
	if m.name == "" {
		m.frontmatterError = "missing_name"
	} else if m.description == "" {
		m.frontmatterError = "missing_description"
	}
	return m
}

// splitFrontmatter detects a leading YAML frontmatter fence. Frontmatter exists
// only when the content (after leading whitespace) starts with "---" and a
// closing "---" fence follows (≥3 chunks when split), so a body horizontal-rule
// is not misread as frontmatter. Returns the YAML block,
// the remaining body, and whether frontmatter was found.
func splitFrontmatter(content string) (fm, body string, ok bool) {
	s := strings.TrimLeft(content, " \t\r\n")
	if !strings.HasPrefix(s, "---") {
		return "", "", false
	}
	parts := strings.Split(s, "---")
	if len(parts) < 3 {
		return "", "", false // unterminated fence
	}
	// parts[0] is "" (before the opening fence); parts[1] is the YAML block;
	// the body is everything after, rejoined so body "---" rules survive.
	return parts[1], strings.Join(parts[2:], "---"), true
}

// hasLoadTimeShellExec reports whether a skill body contains Claude Code
// load-time execution directives: a line-start or whitespace-preceded
// “ !`cmd` “ inline command, or a ` ```! ` fenced block. These run on the
// developer's machine at skill load time, before the model sees the content.
func hasLoadTimeShellExec(body string) bool {
	for i := 0; i+1 < len(body); i++ {
		if body[i] != '!' || body[i+1] != '`' {
			continue
		}
		if i == 0 {
			return true
		}
		switch body[i-1] {
		case ' ', '\t', '\n', '\r':
			return true
		}
	}
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "```!") {
			return true
		}
	}
	return false
}

// quoteFixYAML wraps unquoted, colon-bearing scalar values in double quotes so
// the YAML re-parses (the standard's compatibility fallback for `key: Use
// when: …`). Only lines whose value contains a colon and is not already quoted
// or structured are rewritten; keys and indentation are preserved verbatim.
func quoteFixYAML(fm string) string {
	lines := strings.Split(fm, "\n")
	for i, line := range lines {
		keyPart, valueRaw, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		key := strings.TrimSpace(keyPart)
		if key == "" || strings.ContainsAny(key, ":\"'#-") {
			continue // not a simple `key: value` line
		}
		value := strings.TrimSpace(valueRaw)
		if value == "" || !strings.Contains(value, ":") {
			continue
		}
		switch value[0] {
		case '"', '\'', '[', '{', '|', '>', '&', '*':
			continue // already quoted or structured
		}
		// Escape backslashes before quotes so a Windows drive path in the value
		// (e.g. `description: ...C:\Users\...`) survives double-quoting instead of
		// forming an invalid escape that fails the retry and drops all frontmatter.
		// Order matters: backslash first, else the quote-escape's backslashes double.
		escaped := strings.ReplaceAll(value, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		lines[i] = keyPart + ": \"" + escaped + "\""
	}
	return strings.Join(lines, "\n")
}

// parseYAMLMap unmarshals a YAML mapping into a string-keyed map. A block that
// is empty or not a mapping yields an empty map with no error.
func parseYAMLMap(s string) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// stringField returns m[key] when it is a string, else "" (non-string scalars
// like numbers or bools are ignored rather than coerced).
func stringField(m map[string]any, key string) string {
	return stringFromAny(m[key])
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// boolField returns m[key] when it is a bool, else false.
func boolField(m map[string]any, key string) bool {
	if b, ok := m[key].(bool); ok {
		return b
	}
	return false
}

// normalizeAllowedTools coerces the standard's space-separated string, Claude
// Code's comma-separated string, or a YAML list into a []string. Empty and
// non-string entries are dropped; nil in → nil out.
func normalizeAllowedTools(v any) []string {
	var raw []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s := stringFromAny(e); s != "" {
				raw = append(raw, s)
			}
		}
	case string:
		sep := strings.Fields // space-separated (the standard)
		if strings.Contains(t, ",") {
			sep = func(s string) []string { return strings.Split(s, ",") }
		}
		for _, tok := range sep(t) {
			if tok = strings.TrimSpace(tok); tok != "" {
				raw = append(raw, tok)
			}
		}
	default:
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// truncRunes truncates s to at most n runes (rune-safe, never splits a
// multibyte sequence).
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
