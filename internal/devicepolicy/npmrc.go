package devicepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// This file backs the package_config#npm policy category: it converges a
// managed block inside the console user's ~/.npmrc so npm (and the pnpm / yarn
// v1 / bun tools that read the same file) resolves packages through the
// tenant's StepSecurity secure registry. It parallels the VS Code
// settings.json writer (settings_writer.go) but the target is a file the agent
// may run as root against a user-owned tree, so every file operation goes
// through os.Root rather than atomicfile — see the security notes on
// NPMRCWriter below.

// Ownership markers for the managed block. The BEGIN/END pair delimits exactly
// the bytes the agent owns; nothing outside it is ever rewritten. BEGIN carries
// the "-- managed by dmg" suffix so it is distinguishable from the MDM script's
// own header (which ends "-- managed by mdm") — the two lanes must never claim
// each other's block.
const (
	npmrcBeginMarker = "# BEGIN StepSecurity Secure Registry -- managed by dmg"
	npmrcEndMarker   = "# END StepSecurity Secure Registry"
	// npmrcMDMMarker is the header the published MDM remediation script writes.
	// The probe treats its presence (outside our block) as the first signal
	// that the MDM lane is managing this file.
	npmrcMDMMarker = "# StepSecurity Secure Registry -- managed by mdm"
)

// NPMOwnedKey is the WrittenSettings key the npm lane records ownership under.
// The managed block is ONE atomic unit (its BEGIN/END markers bound it), so the
// lane owns exactly one entry — value = the rendered block body — where the VS
// Code lane owns one entry per setting id. Wired as Reconciler.OwnershipKey so
// drift, adoption, persistence, and the value-based clear all read the same key.
const NPMOwnedKey = "npmrc"

// The observed-bag keys and auth verdicts of the MDM verify-only report. They are
// WIRE-PERMANENT: the backend validates exactly these three keys and rejects any
// other (a secret-ingest guard), and maps auth_token_status to a redacted auth
// change. auth_token_status is the ONLY axis decided on-device, because deciding
// it backend-side would mean transmitting a token.
const (
	observedKeyEcosystem   = "ecosystem"
	observedKeyRegistryURL = "registry_url"
	// #nosec G101 -- a JSON field NAME, not a credential; the value it carries is
	// one of the three verdicts below and never token material.
	observedKeyAuthTokenStatus = "auth_token_status"

	authTokenMatch    = "match"
	authTokenMismatch = "mismatch"
	authTokenAbsent   = "absent"
)

// npmrcMaxRegistryURLBytes caps the observed registry_url before transmission.
// The value is read off a user-writable file and the backend rejects anything
// longer, so an oversize value is refused on-device rather than sent to fail
// there.
const npmrcMaxRegistryURLBytes = 2048

// npmrcDMGPrefix is prepended to a user's active bare `registry=` line when the
// managed block is applied, so the original survives (commented) and can be
// restored on clear. It is deliberately distinct from the MDM script's
// `# [stepsecurity] ` prefix: each lane only ever un-comments its own prefix,
// so they cannot resurrect each other's work.
const (
	npmrcDMGPrefix = "# [stepsecurity-dmg] "
	npmrcMDMPrefix = "# [stepsecurity] "
)

const (
	npmrcMaxBytes         = maxManagedUserFileBytes
	npmrcMaxRenderedBytes = 4 << 10
	npmrcMaxKeyBytes      = 256
	npmrcMaxSerialBytes   = 128
	npmrcMaxHostBytes     = 253
	npmrcMaxSymlinkDepth  = secureUserFileMaxSymlinkDepth
	npmrcMaxBackups       = secureUserFileMaxBackups
	npmrcFileMode         = secureUserFileMode
)

// NPMRCWriter converges the managed block in one user's ~/.npmrc. Format
// transforms remain npm-specific; all byte and metadata operations are shared.
type NPMRCWriter struct {
	file *secureUserFile
	logf func(format string, args ...any)
}

func NewNPMRCWriter(exec executor.Executor) (*NPMRCWriter, error) {
	home, err := newSecureUserHome(exec)
	if err != nil {
		return nil, err
	}
	file, err := home.open(".npmrc", ".dmg-", npmrcMaxBytes)
	if err != nil {
		_ = home.Close()
		return nil, err
	}
	return &NPMRCWriter{file: file}, nil
}

func (w *NPMRCWriter) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	return w.file.home.Close()
}

func (w *NPMRCWriter) Location() string {
	if w == nil || w.file == nil {
		return ""
	}
	return w.file.Location() + " [npm secure registry]"
}

func (w *NPMRCWriter) SetLogf(logf func(format string, args ...any)) {
	w.logf = logf
	if w.file != nil {
		w.file.home.logf = logf
	}
}

func (w *NPMRCWriter) log(format string, args ...any) {
	if w.logf != nil {
		w.logf(format, args...)
	}
}

// Read returns the managed block body and whether it is present.
func (w *NPMRCWriter) Read() (string, bool, error) {
	data, existed, _, err := w.file.Read()
	if err != nil || !existed {
		return "", false, err
	}
	body, present := extractManagedBody(string(data))
	return body, present, nil
}

// Write applies the npm transform, atomically commits it, and verifies the block.
func (w *NPMRCWriter) Write(value string) (string, error) {
	current, _, _, err := w.file.Read()
	if err != nil {
		return "", err
	}
	next, err := w.rewriteContent(current, value)
	if err != nil {
		return "", err
	}
	if err := w.file.Commit(next, npmrcFileMode); err != nil {
		return "", err
	}
	data, existed, _, err := w.file.Read()
	if err != nil || !existed {
		if err == nil {
			err = errors.New("npmrc: file absent after write")
		}
		if restoreErr := w.file.RestoreSnapshot(); restoreErr != nil {
			return "", fmt.Errorf("npmrc: readback failed and rollback failed (%v): %w", err, ErrWriteUnverified)
		}
		return "", err
	}
	body, present := extractManagedBody(string(data))
	if !present {
		if restoreErr := w.file.RestoreSnapshot(); restoreErr != nil {
			return "", fmt.Errorf("npmrc: managed block missing after write and rollback failed: %w", ErrWriteUnverified)
		}
		return "", errors.New("npmrc: managed block missing after write")
	}
	return body, nil
}

// Clear removes the managed block and restores npm settings displaced by this lane.
func (w *NPMRCWriter) Clear() (bool, error) {
	current, existed, _, err := w.file.Read()
	if err != nil {
		return false, err
	}
	if !existed {
		w.purgeBackups()
		return false, nil
	}
	next, err := w.clearContent(current)
	if err != nil {
		return false, err
	}
	if bytes.Equal(next, current) {
		w.purgeBackups()
		return false, nil
	}
	if err := w.file.Commit(next, npmrcFileMode); err != nil {
		return false, err
	}
	w.purgeBackups()
	return true, nil
}

func (w *NPMRCWriter) RestoreSnapshot() error { return w.file.RestoreSnapshot() }

func (w *NPMRCWriter) purgeBackups() {
	if err := w.file.PurgeBackups(); err != nil {
		w.log("npmrc: backup purge failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Content transforms (rewrite / clear) and the INI classifier
// ---------------------------------------------------------------------------

// rewriteContent produces the new file bytes from the current bytes and the
// rendered block body: strip any existing managed block, fail closed on an INI
// section header, comment out active bare `registry=` lines, and append a fresh
// block at the very bottom on its own line. Preserves all other bytes exactly.
func (w *NPMRCWriter) rewriteContent(current []byte, body string) ([]byte, error) {
	rest, bom := stripBOM(current)
	if hasLoneCR(string(rest)) {
		return nil, fmt.Errorf("npmrc: file contains a bare CR npm would treat as a line break; cannot safely transform: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")

	lines, strippedToEOF := stripManagedBlock(lines)
	if strippedToEOF {
		w.log("npmrc: managed block had no END marker; stripped to EOF and rewriting")
	}
	if containsSection(lines) {
		// An INI section header scopes every following key to section.key, which
		// npm ignores — our appended block would be inert while a line-based
		// check reported it applied. There is no way to close a section, so the
		// only safe outcome is to refuse.
		return nil, fmt.Errorf("npmrc: file contains an INI [section] header; cannot safely append: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		return nil, fmt.Errorf("npmrc: file has a quoted key npm would coerce from non-string JSON; cannot safely transform: %w", ErrTargetUnusable)
	}
	if _, tokKey, _, _ := parseExpected(body); hasArrayAppendOverride(lines, tokKey) {
		// npm folds `registry[]=` and our block's `registry=` into one array, so the
		// block would be present and last-wins yet npm would not resolve to the
		// tenant registry alone. Commenting the array line out is not enough (npm
		// arrays are order-independent), so refuse the transform.
		return nil, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key; cannot safely transform: %w", ErrTargetUnusable)
	}
	lines = commentBareRegistry(lines)

	base := strings.Join(lines, "\n")
	var buf bytes.Buffer
	buf.Write(bom)
	buf.WriteString(base)
	if len(base) > 0 && !strings.HasSuffix(base, "\n") {
		// Start the block on a fresh line, but never squash a pre-existing
		// trailing newline (blank lines are content and are preserved).
		buf.WriteByte('\n')
	}
	buf.WriteString(npmrcBeginMarker)
	buf.WriteByte('\n')
	buf.WriteString(body)
	buf.WriteByte('\n')
	buf.WriteString(npmrcEndMarker)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// clearContent removes the managed block and un-comments only our own
// `# [stepsecurity-dmg] ` lines. It never touches the MDM script's
// `# [stepsecurity] ` lines and never deletes the file. The one permitted byte
// deviation from "restore the world" is that a missing original final newline
// is not restored — the remainder keeps the newline enforce added before the
// block.
//
// It fails closed on a bare CR for a reason specific to clearing: a CR-delimited
// file collapses to a single line under the '\n' split, so no marker line matches
// and the block is not FOUND — the transform would return the input unchanged,
// Clear would report the nothing-to-do success, and the reconciler would drop
// ownership state while the token stayed on disk. Refusing keeps the failure
// visible and the ownership record intact, so a later run can retry.
func (w *NPMRCWriter) clearContent(current []byte) ([]byte, error) {
	rest, bom := stripBOM(current)
	if hasLoneCR(string(rest)) {
		return nil, fmt.Errorf("npmrc: file contains a bare CR npm treats as a line break; the managed block cannot be located to remove it: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	lines, _ = stripManagedBlock(lines)
	lines = unprefixDMG(lines)
	var buf bytes.Buffer
	buf.Write(bom)
	buf.WriteString(strings.Join(lines, "\n"))
	return buf.Bytes(), nil
}

// stripBOM splits a leading UTF-8 BOM off the content. The BOM is removed for
// parsing (an INI key on the first line is matched correctly, a JSON document
// starts on a value) and re-prepended on rewrite so the bytes are preserved.
// Used by both the ~/.npmrc block writer and the settings.json writer.
func stripBOM(b []byte) (rest, bom []byte) {
	const bomSeq = "\ufeff"
	if bytes.HasPrefix(b, []byte(bomSeq)) {
		return b[len(bomSeq):], []byte(bomSeq)
	}
	return b, nil
}

// stripManagedBlock removes EVERY managed block (each BEGIN marker through its
// matching END, inclusive), not just the first. A BEGIN with no matching END
// anywhere after it is a truncated block and is stripped to EOF, reported via the
// returned flag. Removing all blocks is what makes offboarding revoke every
// token: a duplicated block — a user copy, or a partial prior write — must never
// survive a clear still carrying a live token, and must never make a rewrite
// oscillate forever between one block and two.
func stripManagedBlock(lines []string) ([]string, bool) {
	out := make([]string, 0, len(lines))
	strippedToEOF := false
	for i := 0; i < len(lines); {
		if !isMarkerLine(lines[i], npmrcBeginMarker) {
			out = append(out, lines[i])
			i++
			continue
		}
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if isMarkerLine(lines[j], npmrcEndMarker) {
				end = j
				break
			}
		}
		if end < 0 {
			// Truncated block: no END exists past this BEGIN. Drop it to EOF so no
			// partial token lingers; bytes past a genuine truncation are not
			// recoverable structure.
			strippedToEOF = true
			break
		}
		i = end + 1
	}
	return out, strippedToEOF
}

// isMarkerLine matches a marker tolerantly of surrounding whitespace and a
// trailing CR, so a marker survives being read back from a CRLF file.
func isMarkerLine(line, marker string) bool {
	return strings.TrimSpace(line) == marker
}

// containsSection reports whether any line is an INI section header.
func containsSection(lines []string) bool {
	for _, l := range lines {
		if isSectionLine(l) {
			return true
		}
	}
	return false
}

// hasLoneCR reports whether s contains a bare carriage return — a '\r' not
// immediately followed by '\n'. npm's INI parser splits logical lines on '\r\n',
// '\n', AND a lone '\r', so a bare CR begins a new line for npm that our
// '\n'-only split does not see. That split mismatch is exploitable: `[global]\r`
// is a section header to npm (scoping, and thus nullifying, our appended block)
// but one opaque line to us, and `k=v\rregistry=evil` hides an overriding
// registry from us while npm honors it. We cannot safely transform such a file,
// so the enforce/convergence/probe paths treat a bare CR the way they treat an
// INI section: fail closed. A CRLF ('\r\n') file is NOT a lone CR and still
// round-trips through the '\n' split with its trailing '\r' preserved.
func hasLoneCR(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' && (i+1 >= len(s) || s[i+1] != '\n') {
			return true
		}
	}
	return false
}

// hasCoercibleQuotedKey reports whether any active line's key is a single-quoted
// token whose inner text npm's unsafe() JSON-parses to a NON-string value. npm
// strips the single quotes, JSON-parses the bare inner, and then coerces the
// result to a string when it is used as a config key — a single-element array
// like `'["registry"]'` becomes the JS array ["registry"], which coerces to the
// key `registry`, forging an override. Replicating JS's String() coercion for
// every shape (arrays join, objects → "[object Object]", numbers, bools) is
// fragile, and our own keys are never quoted, so we fail closed on any such line
// the same way we do on an INI section or a bare CR. (A double-quoted token is
// itself a JSON string literal, so it always decodes to a string — jsonDecodeString
// already handles it — and is not coercible-non-string.)
func hasCoercibleQuotedKey(lines []string) bool {
	for _, l := range lines {
		if isCommentLine(l) || isSectionLine(l) {
			continue
		}
		i := strings.IndexByte(l, '=')
		if i < 0 {
			continue
		}
		if quotedNonStringInner(strings.TrimSpace(l[:i])) {
			return true
		}
	}
	return false
}

// hasArrayAppendOverride reports whether any active line uses npm's `key[]=`
// array-append form on a key this writer's precedence model treats as a scalar.
// npm's ini reader turns `registry[]=…` into an ARRAY and then folds the plain
// `registry=` assignment into that same array, so BOTH orders leave the effective
// registry a comma-joined list containing the injected value while a last-wins
// scalar scan still sees the block's own `registry=` as the winner — i.e. we would
// report converged (or observe a clean registry_url) on a file where npm no longer
// resolves to the tenant registry alone. Verified against npm 10.9.7:
//
//	registry=<ours> + registry[]=<theirs> → "<ours>,<theirs>"
//	registry[]=<theirs> + registry=<ours> → "<theirs>,<ours>"
//
// Only the keys we manage are judged, so an unrelated array config (`omit[]=dev`)
// is left alone. tokenKey is the single `//host/path/:_authToken` this writer
// manages: npm consults exactly that key for the tenant registry's credential, so
// an array-append on any OTHER registry's token cannot perturb what we render or
// read, and refusing the file over it would be a false unenforceable. When the
// desired pair does not parse, which key is ours is unknown, so every token key is
// judged rather than none.
//
// The `[]` suffix is tested AFTER npmUnsafe, matching npm's own order (it unquotes
// before checking for `[]`), which is what catches the quoted `"registry[]"=…` form;
// `registry [] = …` is NOT flagged because npm stores that under the distinct key
// "registry " and it overrides nothing.
func hasArrayAppendOverride(lines []string, tokenKey string) bool {
	for _, l := range lines {
		key, _, ok := activeKV(l)
		if !ok {
			continue
		}
		base, isAppend := strings.CutSuffix(key, "[]")
		if !isAppend {
			continue
		}
		if base == "registry" {
			return true
		}
		if tokenKey != "" {
			if base == tokenKey {
				return true
			}
		} else if strings.HasSuffix(base, ":_authToken") {
			return true
		}
	}
	return false
}

// quotedNonStringInner reports whether s is a single-quoted token whose bare inner
// is valid JSON that is NOT a string (array, object, number, bool, null) — the
// shape npm coerces to a string key. A parse failure (e.g. the bare word in
// `'registry'`) or a JSON string is not coercible-non-string and is left to the
// normal npmUnsafe path.
func quotedNonStringInner(s string) bool {
	if len(s) < 2 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return false
	}
	var v any
	if err := json.Unmarshal([]byte(s[1:len(s)-1]), &v); err != nil {
		return false
	}
	_, isStr := v.(string)
	return !isStr
}

// commentBareRegistry prefixes every active bare `registry=` line with the DMG
// prefix, preserving the original (including any trailing CR) after the prefix.
// Scoped `@scope:registry=` lines, token lines, cooldown keys, env-ref lines,
// and every comment are left untouched.
func commentBareRegistry(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if key, _, ok := activeKV(l); ok && key == "registry" {
			out[i] = npmrcDMGPrefix + l
			continue
		}
		out[i] = l
	}
	return out
}

// unprefixDMG restores lines the writer previously commented out, removing only
// an exact leading DMG prefix.
func unprefixDMG(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if strings.HasPrefix(l, npmrcDMGPrefix) {
			out[i] = l[len(npmrcDMGPrefix):]
			continue
		}
		out[i] = l
	}
	return out
}

// isCommentLine reports whether a line is an npm INI comment (first non-space
// rune is '#' or ';') or blank.
func isCommentLine(line string) bool {
	t := strings.TrimLeft(line, " \t")
	if t == "" {
		return true
	}
	return t[0] == '#' || t[0] == ';'
}

// isSectionLine reports whether a line is an INI section header `[...]`.
func isSectionLine(line string) bool {
	t := strings.TrimSpace(line)
	return len(t) >= 2 && t[0] == '[' && t[len(t)-1] == ']'
}

// activeKV parses an active (uncommented, non-section) key=value line the way
// npm's INI parser does: split on the FIRST '=', then run BOTH sides through
// npmUnsafe — npm's own key/value normalization (trim, unquote a fully quoted
// token, or strip an unescaped inline ';'/'#' comment). ok is false for comments,
// sections, and lines with no '=' or an empty key. This one classifier backs
// every key-matching path (comment-out, clear, probe precedence, convergence);
// parsing keys exactly as npm does is what keeps a disguised override like
// `registry#x=evil` or `"registry"=evil` — both of which npm reads as the key
// `registry` — from slipping past the precedence checks as an unrecognized key,
// and a spaced form like `registry = https://evil/` from being mistaken for inert.
func activeKV(line string) (key, value string, ok bool) {
	if isCommentLine(line) || isSectionLine(line) {
		return "", "", false
	}
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	key = npmUnsafe(line[:i])
	if key == "" {
		return "", "", false
	}
	value = npmUnsafe(line[i+1:])
	return key, value, true
}

// npmUnsafe mirrors the npm `ini` package's unsafe(): the normalization npm
// applies to BOTH the key and the value of every line before storing it. A fully
// quoted token is unquoted (one layer); otherwise everything from the first
// UNESCAPED ';' or '#' is dropped as an inline comment and '\;', '\#', '\\'
// escapes are resolved (any other '\x' is kept verbatim). Our classifier must
// match npm here or it fails to recognize a disguised override: npm reads
// `registry#x=evil` as key `registry` and `"registry"=evil` as key `registry`, so
// a naive first-'=' split keeping `registry#x` / `"registry"` would let a later
// poisoned line defeat last-wins while Converged/ProbeExpected still reported
// compliant. Every key and value this writer itself renders is drawn from a
// comment-, quote-, and backslash-free alphabet, so this is the identity function
// on our own content.
func npmUnsafe(s string) string {
	s = strings.TrimSpace(s)
	if inner, ok := unquoteININToken(s); ok {
		return inner
	}
	var b strings.Builder
	b.Grow(len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			if c == '\\' || c == ';' || c == '#' {
				b.WriteByte(c)
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
			esc = false
		case c == ';' || c == '#':
			return strings.TrimSpace(b.String())
		case c == '\\':
			esc = true
		default:
			b.WriteByte(c)
		}
	}
	if esc {
		b.WriteByte('\\')
	}
	return strings.TrimSpace(b.String())
}

// unquoteININToken mirrors npm ini unsafe()'s quoted branch, which JSON-parses a
// quoted token rather than merely stripping the quotes. A double-quoted token is
// JSON-decoded whole, so string escapes resolve — `"registry"` decodes to
// `registry`, an active override we must recognize — and falls back to the
// ORIGINAL quoted string when it is not a valid JSON string (npm keeps the quoted
// form on a JSON.parse failure). A single-quoted token has its quotes stripped
// and the inside JSON-decoded only if that inside is itself a valid JSON string,
// else kept verbatim. ok is false when s is not fully quoted, so the caller falls
// through to inline-comment handling. Merely trimming the quotes (the previous
// behavior) would read `"registry"` as the key `registry` and miss the
// override npm honors as `registry`.
func unquoteININToken(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		if v, ok := jsonDecodeString(s); ok {
			return v, true
		}
		return s, true // npm keeps the quoted form when JSON.parse fails
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		inner := s[1 : len(s)-1]
		if v, ok := jsonDecodeString(inner); ok {
			return v, true
		}
		return inner, true
	}
	return "", false
}

// jsonDecodeString reports whether s is a valid JSON string literal and, if so,
// its decoded value — the string half of npm's JSON.parse(). A non-string JSON
// value (number, object, bool) or a parse error yields ok=false.
func jsonDecodeString(s string) (string, bool) {
	var v string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	return v, true
}

// extractManagedBody returns the canonical body between our markers (the two
// content lines, '\n'-joined, no markers) and whether a well-formed block is
// present. A BEGIN with no END yields present=false.
func extractManagedBody(content string) (string, bool) {
	rest, _ := stripBOM([]byte(content))
	lines := strings.Split(string(rest), "\n")
	begin := -1
	for i, l := range lines {
		if isMarkerLine(l, npmrcBeginMarker) {
			begin = i
			break
		}
	}
	if begin < 0 {
		return "", false
	}
	end := -1
	for i := begin + 1; i < len(lines); i++ {
		if isMarkerLine(lines[i], npmrcEndMarker) {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false
	}
	body := make([]string, 0, end-begin-1)
	for _, l := range lines[begin+1 : end] {
		body = append(body, strings.TrimRight(l, "\r"))
	}
	return strings.Join(body, "\n"), true
}

// ---------------------------------------------------------------------------
// Convergence
// ---------------------------------------------------------------------------

// Converged reports whether the file already reflects the desired block with no
// further work needed. It is stronger than block-body equality: the block must
// be present with body == expected, effective (nothing active overrides its
// registry/token after it, END marker intact, no displaced duplicate), and
// carry sane metadata (0600, target-user-owned on POSIX). A `registry=` line
// appended below an unchanged block (e.g. `aws codeartifact login`) leaves the
// body equal but defeats precedence — so body equality alone would report
// converged forever without ever re-running the transform.
func (w *NPMRCWriter) Converged(expected string) (bool, error) {
	data, existed, mode, err := w.file.Read()
	if err != nil {
		return false, err
	}
	if !existed {
		return false, nil
	}

	rest, _ := stripBOM(data)
	if hasLoneCR(string(rest)) {
		// A bare CR is a line break to npm but not to our '\n' split, so a section or
		// overriding line could hide behind it — the block would look present and
		// effective to us yet be scoped-out or overridden for npm. Fail closed, the
		// same refusal the rewrite path makes.
		return false, fmt.Errorf("npmrc: file contains a bare CR npm treats as a line break; managed block cannot be verified: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	if containsSection(lines) {
		// An INI [section] header scopes our registry/token keys to section.key,
		// which npm ignores for the global registry: the block would be present and
		// body-equal yet inert, so reporting it converged would loop on a false
		// 'compliant'. Fail closed — the same refusal the rewrite path makes — so
		// enforce classifies it write_failed rather than silently accepting it.
		return false, fmt.Errorf("npmrc: file contains an INI [section] header; managed block cannot be effective: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		// A single-quoted key npm coerces from non-string JSON (e.g. '["registry"]')
		// could override our registry/token invisibly to a line-based check. Fail
		// closed, the same refusal the rewrite path makes.
		return false, fmt.Errorf("npmrc: file has a quoted key npm would coerce from non-string JSON; managed block cannot be verified: %w", ErrTargetUnusable)
	}
	if _, tokKey, _, _ := parseExpected(expected); hasArrayAppendOverride(lines, tokKey) {
		// npm folds an array-append line into the same key as the block's scalar
		// assignment, so last-wins would report converged while npm resolves to a
		// list containing someone else's registry. Fail closed, as the rewrite path
		// does.
		return false, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key; managed block cannot be verified: %w", ErrTargetUnusable)
	}

	body, present := extractManagedBody(string(data))
	if !present || body != expected {
		return false, nil
	}

	if countMarker(lines, npmrcBeginMarker) != 1 || countMarker(lines, npmrcEndMarker) != 1 {
		// A duplicate or displaced block: converge by rewriting.
		return false, nil
	}
	if !blockIsLastEffective(lines, expected) {
		return false, nil
	}

	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		return false, nil
	}
	// Ownership is not re-checked here: readCurrent already required the resolved
	// leaf to be owned by the target user, from the same identity-verified handle
	// it read the content through. A second open to re-read the owner would race
	// the very content check it is meant to corroborate.
	return true, nil
}

// blockIsLastEffective reports whether, after our block, no active line
// overrides the block's registry or token — i.e. the block's own keys are the
// last-wins values for the file.
func blockIsLastEffective(lines []string, expected string) bool {
	expReg, expTokKey, expTokVal, ok := parseExpected(expected)
	if !ok {
		return false
	}
	endIdx := -1
	for i, l := range lines {
		if isMarkerLine(l, npmrcEndMarker) {
			endIdx = i
		}
	}
	if endIdx < 0 {
		return false
	}
	for _, l := range lines[endIdx+1:] {
		key, val, ok := activeKV(l)
		if !ok {
			continue
		}
		if key == "registry" && val != expReg {
			return false
		}
		if key == expTokKey && val != expTokVal {
			return false
		}
	}
	return true
}

func countMarker(lines []string, marker string) int {
	n := 0
	for _, l := range lines {
		if isMarkerLine(l, marker) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// MDM probe
// ---------------------------------------------------------------------------

// ProbeExpected reports whether the MDM lane has actually achieved the current
// desired state for this device — not merely that an MDM marker exists. Because
// ~/.npmrc is user-writable (unlike the privileged VS Code policy locations),
// trusting a marker alone would let a user pin permanent mdm_managed while
// pointing npm anywhere. Managed requires all of: the MDM marker outside our
// block, the MDM block's own registry/token lines equal to the expected
// rendered content, those keys effective (last-wins) with nothing overriding
// them, and sane metadata (0600, target-user-owned on POSIX).
func (w *NPMRCWriter) ProbeExpected(expected string) (bool, string) {
	data, existed, mode, err := w.file.Read()
	if err != nil || !existed {
		return false, ""
	}

	managed, detail := probeNPMRCContent(string(data), expected)
	if !managed {
		return false, ""
	}
	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		return false, ""
	}
	// Ownership is already enforced by readCurrent's checkOwner on the same
	// identity-verified handle; re-opening to re-read the owner would race the
	// content probe above.
	return true, detail
}

// probeNPMRCContent is the pure content logic behind ProbeExpected. It takes the
// whole file and the expected rendered body and reports whether the MDM lane
// owns an effective, current block.
func probeNPMRCContent(content, expected string) (bool, string) {
	expReg, expTokKey, expTokVal, ok := parseExpected(expected)
	if !ok {
		return false, ""
	}
	rest, _ := stripBOM([]byte(content))
	if hasLoneCR(string(rest)) {
		// A bare CR hides a section/override from our '\n' split; a marker plus
		// matching lines is then not proof the MDM lane governs npm. Fail closed.
		return false, ""
	}
	lines := strings.Split(string(rest), "\n")

	if containsSection(lines) {
		// A section scopes every following key to section.key; npm then ignores the
		// MDM block's registry/token for the global registry, so a marker plus
		// matching lines under a section is NOT proof the MDM lane governs npm. Fail
		// closed (not managed) — enforce then refuses the sectioned file too.
		return false, ""
	}
	if hasCoercibleQuotedKey(lines) {
		// A single-quoted key npm coerces from non-string JSON could override the
		// registry/token below the MDM block invisibly to the precedence loop. A
		// marker plus matching lines is then not proof; fail closed (not managed).
		return false, ""
	}
	if hasArrayAppendOverride(lines, expTokKey) {
		// npm folds an array-append line into the MDM block's own key, so a marker
		// plus matching lines is not proof the MDM lane governs npm. Fail closed.
		return false, ""
	}

	// Our own block boundaries, so the MDM marker search can exclude it (a user
	// planting the marker inside our block must not count).
	ourBegin, ourEnd := managedBlockBounds(lines)

	mdmIdx := -1
	for i, l := range lines {
		if i >= ourBegin && i <= ourEnd {
			continue
		}
		if isMarkerLine(l, npmrcMDMMarker) {
			mdmIdx = i
			break
		}
	}
	if mdmIdx < 0 {
		return false, ""
	}

	// The MDM block's own lines (contiguous config after its header, stopping at
	// a blank line, our block, or a section) must carry the expected content.
	mdmReg, mdmTok := false, false
	for i := mdmIdx + 1; i < len(lines); i++ {
		if i >= ourBegin && i <= ourEnd {
			break
		}
		l := lines[i]
		if strings.TrimSpace(l) == "" || isSectionLine(l) {
			break
		}
		key, val, ok := activeKV(l)
		if !ok {
			continue
		}
		if key == "registry" && val == expReg {
			mdmReg = true
		}
		if key == expTokKey && val == expTokVal {
			mdmTok = true
		}
	}
	if !mdmReg || !mdmTok {
		return false, ""
	}

	// Effective precedence: the last active registry and token in the whole
	// file must be the expected ones. A later override (poisoned token, bare
	// registry) defeats this and we enforce instead.
	lastReg, lastRegOK := "", false
	lastTok, lastTokOK := "", false
	for _, l := range lines {
		key, val, ok := activeKV(l)
		if !ok {
			continue
		}
		if key == "registry" {
			lastReg, lastRegOK = val, true
		}
		if key == expTokKey {
			lastTok, lastTokOK = val, true
		}
	}
	if !lastRegOK || lastReg != expReg || !lastTokOK || lastTok != expTokVal {
		return false, ""
	}
	return true, "mdm-managed npmrc block present and effective"
}

// managedBlockBounds returns the [begin, end] line indices of our block, or
// (len, -1) when absent (so the "i >= begin && i <= end" exclusion is empty).
func managedBlockBounds(lines []string) (int, int) {
	begin := -1
	for i, l := range lines {
		if isMarkerLine(l, npmrcBeginMarker) {
			begin = i
			break
		}
	}
	if begin < 0 {
		return len(lines), -1
	}
	for i := begin + 1; i < len(lines); i++ {
		if isMarkerLine(lines[i], npmrcEndMarker) {
			return begin, i
		}
	}
	return begin, len(lines) - 1
}

// parseExpected splits the rendered body (two content lines) into the registry
// value, the token key, and the token value used by the precedence checks.
func parseExpected(expected string) (registry, tokenKey, tokenVal string, ok bool) {
	lines := strings.Split(expected, "\n")
	if len(lines) != 2 {
		return "", "", "", false
	}
	rk, rv, rok := activeKV(lines[0])
	tk, tv, tok := activeKV(lines[1])
	if !rok || rk != "registry" || !tok {
		return "", "", "", false
	}
	return rv, tk, tv, true
}

// ProbeContentNPM is the MDM verify-only reader. It reports whether a
// StepSecurity MDM-managed block is present in ~/.npmrc and, if so, the effective
// (last-wins) configuration as the observed bag {ecosystem, registry_url,
// auth_token_status}. It NEVER writes, patches, or clears — in MDM mode the agent
// owns nothing on this file — and it never touches the ownership state store.
//
// expected is the rendered desired block. Only its tenant key (the api_key before
// `::dev:<serial>`) is used, to decide auth_token_status here on the device; no
// token, hash, or fingerprint is ever returned or logged.
//
// The three outcomes are deliberately distinct:
//
//   - genuinely absent file, or present with no MDM marker → (false, nil, nil) →
//     policy_not_applied. Nothing is managing this file.
//   - unreadable file — permission failure, a leaf that became a symlink or
//     changed across the open, a non-regular leaf, an ownership mismatch, the size
//     cap — or a construct we cannot reason about → error → verification_failed.
//     We could not establish the effective config, so we must not report the clean
//     policy_not_applied.
//   - MDM marker present and the file parses → (true, bag, nil) → mdm_managed.
//
// Unlike the DMG-mode ProbeExpected this does NOT require 0600: perms are outside
// the locked observed contract, so a correctly-deployed-but-lax file must still
// report its real registry and auth status rather than be hidden behind a
// synthetic failure. Ownership IS still enforced — readCurrent refuses a leaf the
// target user does not own, because another user's file is not this user's
// effective npm config.
func (w *NPMRCWriter) ProbeContentNPM(expected string) (bool, map[string]json.RawMessage, error) {
	data, existed, mode, err := w.file.Read()
	if err != nil {
		return false, nil, err
	}
	if !existed {
		return false, nil, nil
	}
	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		// Not a verification failure (see the doc comment), and not reportable — the
		// observed bag has no perms field. Log it so support can spot a token file
		// other local users can read; the mode only, never the content.
		w.log("npmrc: mdm-managed file mode is %#o, not %#o (token may be readable by other local users)", mode.Perm(), npmrcFileMode)
	}
	return probeNPMRCObserved(string(data), expected)
}

// probeNPMRCObserved is the pure content logic behind ProbeContentNPM. It shares
// the parse guards and the last-wins precedence scan with probeNPMRCContent, but
// returns the observed VALUES instead of a yield/no-yield verdict: the backend
// structurally compares registry_url and ecosystem against desired, so the agent
// reports them raw and judges only the secret axis.
func probeNPMRCObserved(content, expected string) (bool, map[string]json.RawMessage, error) {
	// The desired registry is deliberately unused: the backend compares
	// registry_url structurally. Only the token key (which _authToken line belongs
	// to the tenant registry) and its value (the tenant key) are needed here.
	_, expTokKey, expTokVal, ok := parseExpected(expected)
	if !ok {
		return false, nil, errors.New("npmrc: expected value is not a rendered registry/token pair")
	}

	rest, _ := stripBOM([]byte(content))
	// Fail closed on the same constructs the DMG probe rejects. Each one hides a
	// section or an override from the '\n'-split precedence scan below, so the
	// values we would report are not provably the effective ones. An honest
	// verification_failed beats a confident wrong observation.
	if hasLoneCR(string(rest)) {
		return false, nil, fmt.Errorf("npmrc: file contains a bare CR line break: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	if containsSection(lines) {
		return false, nil, fmt.Errorf("npmrc: file contains an INI section header: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		return false, nil, fmt.Errorf("npmrc: file contains a coercible quoted key: %w", ErrTargetUnusable)
	}
	if hasArrayAppendOverride(lines, expTokKey) {
		// The registry we would report is not the one npm resolves: it folds the
		// array-append line into the same key. Reporting the scalar last-wins value
		// would be a confident wrong observation.
		return false, nil, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key: %w", ErrTargetUnusable)
	}

	// Presence = an MDM marker OUTSIDE every DMG-owned block, so a marker planted
	// inside one of our own blocks cannot pass as MDM management.
	inDMGBlock, err := dmgBlockLines(lines)
	if err != nil {
		return false, nil, err
	}
	present := false
	for i, l := range lines {
		if inDMGBlock[i] {
			continue
		}
		if isMarkerLine(l, npmrcMDMMarker) {
			present = true
			break
		}
	}
	if !present {
		return false, nil, nil
	}

	// Effective precedence over the WHOLE file: npm takes the LAST active
	// assignment, so a line below the MDM block wins. Report what npm would
	// actually use — an override surfaces as drift at the backend, which is the
	// correct outcome, not something to hide.
	lastReg, lastRegOK := "", false
	lastTok, lastTokOK := "", false
	for _, l := range lines {
		key, val, ok := activeKV(l)
		if !ok {
			continue
		}
		switch key {
		case "registry":
			lastReg, lastRegOK = val, true
		case expTokKey:
			// The tenant registry's _authToken key. A block pointing at a DIFFERENT
			// registry carries a different token key, so its token does not count as
			// this policy's credential — it reports absent, alongside the registry drift.
			lastTok, lastTokOK = val, true
		}
	}
	if !lastRegOK {
		// A managed marker with no effective registry line is not a credible read,
		// and the backend requires registry_url to compare anything at all.
		return false, nil, errors.New("npmrc: mdm marker present but no effective registry line")
	}
	if err := transmittableRegistryURL(lastReg); err != nil {
		return false, nil, err
	}

	status := authTokenAbsent
	if lastTokOK {
		// Tenant-key PREFIX comparison on both sides: an admin-pushed shared token
		// carrying no ::dev:<serial> suffix is still the tenant's key, so it reads
		// match. The serial is device-specific and deliberately not part of the
		// verdict.
		status = authTokenMismatch
		if tenantKeyPrefix(lastTok) == tenantKeyPrefix(expTokVal) {
			status = authTokenMatch
		}
	}
	return npmObservedBag(lastReg, status)
}

// dmgBlockLines marks every line that falls inside a DMG-owned block, so the MDM
// marker search can exclude all of them. managedBlockBounds only locates the
// FIRST block, so a second BEGIN/END pair would leave its interior unexcluded and
// a marker planted there would read as MDM presence — refuse that file instead.
// The writer never produces two blocks, so this is a tampered/hand-edited file.
func dmgBlockLines(lines []string) ([]bool, error) {
	if countMarker(lines, npmrcBeginMarker) > 1 || countMarker(lines, npmrcEndMarker) > 1 {
		return nil, fmt.Errorf("npmrc: more than one dmg-managed block: %w", ErrTargetUnusable)
	}
	in := make([]bool, len(lines))
	begin, end := managedBlockBounds(lines)
	for i := begin; i <= end && i < len(lines); i++ {
		in[i] = true
	}
	return in, nil
}

// transmittableRegistryURL rejects an effective registry_url that must not leave
// the device. It is deliberately a SUBSET of validateRegistryURL's rules: the
// value is read off a user-writable file, so credential-bearing or
// parser-ambiguous forms (userinfo, a query, a fragment, control bytes) and
// oversize values are refused before transmission — a token smuggled into the URL
// must never reach the backend. The shape rules validateRegistryURL also enforces
// (host grammar, no port, an exact /javascript path) are NOT applied: a merely
// wrong registry is the drift the backend exists to detect, and erroring on it
// would destroy that signal.
//
// The SCHEME is likewise not judged beyond http/https: a device resolving to a
// plaintext http mirror is the most security-relevant drift an admin can have, so
// it must travel as evidence and surface as a registry_url diff rather than be
// discarded as malformed. validateRegistryURL stays https-only for the POLICY
// side, where we compose the URL and a non-https value is our own bug; here the
// URL is someone else's input, so it is data to report. What still fails is a
// value that is not a credible registry read at all — another scheme, or no host.
func transmittableRegistryURL(raw string) error {
	if len(raw) > npmrcMaxRegistryURLBytes {
		return fmt.Errorf("npmrc: effective registry_url exceeds %d bytes", npmrcMaxRegistryURLBytes)
	}
	if hasControlBytes(raw) {
		return errors.New("npmrc: effective registry_url contains control characters")
	}
	if strings.ContainsAny(raw, "#?") {
		return errors.New("npmrc: effective registry_url contains '#' or '?'")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("npmrc: effective registry_url is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("npmrc: effective registry_url is not an http(s) URL")
	}
	if u.Host == "" {
		return errors.New("npmrc: effective registry_url has no host")
	}
	if u.User != nil {
		return errors.New("npmrc: effective registry_url contains userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("npmrc: effective registry_url contains a query")
	}
	if u.Fragment != "" {
		return errors.New("npmrc: effective registry_url contains a fragment")
	}
	return nil
}

// tenantKeyPrefix returns the tenant api_key portion of a device token —
// everything before the "::dev:<serial>" suffix. A token with no suffix is
// already the bare tenant key and returns unchanged.
func tenantKeyPrefix(token string) string {
	return strings.SplitN(token, "::dev:", 2)[0]
}

// npmObservedBag builds the observed bag. Exactly three keys, JSON strings — the
// backend rejects any unknown key, and nothing derived from the token beyond the
// verdict is included.
func npmObservedBag(registryURL, authStatus string) (bool, map[string]json.RawMessage, error) {
	reg, err := json.Marshal(registryURL)
	if err != nil {
		return false, nil, fmt.Errorf("npmrc: encode observed registry_url: %w", err)
	}
	eco, err := json.Marshal("npm")
	if err != nil {
		return false, nil, fmt.Errorf("npmrc: encode observed ecosystem: %w", err)
	}
	status, err := json.Marshal(authStatus)
	if err != nil {
		return false, nil, fmt.Errorf("npmrc: encode observed auth_token_status: %w", err)
	}
	return true, map[string]json.RawMessage{
		observedKeyEcosystem:       eco,
		observedKeyRegistryURL:     reg,
		observedKeyAuthTokenStatus: status,
	}, nil
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// npmPolicy is the run-config policy payload for the npm ecosystem.
type npmPolicy struct {
	Ecosystem   string `json:"ecosystem"`
	RegistryURL string `json:"registry_url"`
	Auth        struct {
		Scheme string `json:"scheme"`
		APIKey string `json:"api_key"`
	} `json:"auth"`
}

// RenderNPMRCBlock validates a policy and returns the two content lines the
// writer wraps in its markers: the `registry=` line and the `//host/path/:_authToken=`
// line, '\n'-joined with no markers and no trailing newline. It fully validates
// the policy (the HTTP layer only checks "is a JSON object"): the token line's
// host and path derive from registry_url, and the composed device token is
// `<api_key>::dev:<serial>`. Any validation failure returns an error the
// reconciler reports as policy_not_applied; error messages never echo the key
// or the policy.
func RenderNPMRCBlock(policy json.RawMessage, serial string) (string, error) {
	var p npmPolicy
	if err := json.Unmarshal(policy, &p); err != nil {
		return "", errors.New("npmrc: policy is not a well-formed npm policy object")
	}
	if p.Ecosystem != "npm" {
		return "", errors.New("npmrc: policy ecosystem is not npm")
	}
	if p.Auth.Scheme != "stepsecurity_device_token" {
		return "", errors.New("npmrc: unsupported auth scheme")
	}

	key := p.Auth.APIKey
	if key == "" {
		return "", errors.New("npmrc: policy api_key is empty")
	}
	if len(key) > npmrcMaxKeyBytes {
		return "", errors.New("npmrc: policy api_key too long")
	}
	if !isNPMSafe(key) {
		return "", errors.New("npmrc: policy api_key contains unsupported characters")
	}
	if serial == "" {
		return "", errors.New("npmrc: device serial is empty")
	}
	if len(serial) > npmrcMaxSerialBytes {
		return "", errors.New("npmrc: device serial too long")
	}
	if !isNPMSafe(serial) {
		return "", errors.New("npmrc: device serial contains unsupported characters")
	}

	host, path, err := validateRegistryURL(p.RegistryURL)
	if err != nil {
		return "", err
	}

	token := key + "::dev:" + serial
	// npm's _authToken key is `//host/path/:_authToken` with a trailing slash
	// before the colon.
	tokenKey := "//" + host + path + "/:_authToken"
	body := "registry=" + p.RegistryURL + "\n" + tokenKey + "=" + token
	if len(body) > npmrcMaxRenderedBytes {
		return "", errors.New("npmrc: rendered block exceeds size limit")
	}
	return body, nil
}

// validateRegistryURL keeps npm's exact /javascript path contract while sharing
// the common secure-registry URL checks with the PyPI policy parser.
func validateRegistryURL(raw string) (host, path string, err error) {
	u, err := parsePolicyRegistryURL(raw)
	if err != nil {
		return "", "", fmt.Errorf("npmrc: policy %w", err)
	}
	if u.EscapedPath() != "/javascript" {
		return "", "", errors.New("npmrc: policy registry_url path must be /javascript")
	}
	return u.Hostname(), "/javascript", nil
}

// parsePolicyRegistryURL validates the URL properties shared by compiled npm
// and PyPI policies. Each caller retains its own exact path check.
func parsePolicyRegistryURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("registry_url is empty")
	}
	if hasControlBytes(raw) {
		return nil, errors.New("registry_url contains control characters")
	}
	// url.Parse does not expose a ForceFragment bit for a trailing bare '#'.
	if strings.ContainsAny(raw, "#?") {
		return nil, errors.New("registry_url must not contain '#' or '?'")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("registry_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("registry_url must be https")
	}
	if u.User != nil {
		return nil, errors.New("registry_url must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("registry_url must not contain a query")
	}
	if u.Fragment != "" {
		return nil, errors.New("registry_url must not contain a fragment")
	}
	if u.Port() != "" {
		return nil, errors.New("registry_url must not contain a port")
	}
	if !isValidHost(u.Hostname()) {
		return nil, errors.New("registry_url host is not a valid hostname")
	}
	return u, nil
}

// isNPMSafe reports whether every byte is in the unquoted npm-INI-safe alphabet
// [A-Za-z0-9._:@/-]. Anything outside it — spaces, quotes, '#', ';', '=',
// '$', control bytes — is rejected rather than escaped; v1 defines no escaping.
func isNPMSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '@' || c == '/' || c == '-':
		default:
			return false
		}
	}
	return true
}

func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// isValidHost validates a lowercase RFC 1123 hostname. The grammar is checked,
// not an allowlist — dedicated instances use custom domains, so no base domain
// can be pinned agent-side.
func isValidHost(host string) bool {
	if host == "" || len(host) > npmrcMaxHostBytes {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
