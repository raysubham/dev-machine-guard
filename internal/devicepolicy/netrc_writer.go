package devicepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/model"
)

const (
	dmgNetrcBegin = "# BEGIN StepSecurity PyPI Secure Registry credential - managed by dmg"
	dmgNetrcEnd   = "# END StepSecurity PyPI Secure Registry credential"

	mdmNetrcBegin = "# BEGIN StepSecurity PyPI Secure Registry credential - managed by mdm"
	mdmNetrcEnd   = "# END StepSecurity PyPI Secure Registry credential"

	dmgNetrcDisabledPrefix = "# [stepsecurity-pypi-dmg] "
	netrcBackupPrefix      = ".dmg-"
)

// NetrcWriter owns only the exact registry host entry inside one user's netrc.
type NetrcWriter struct {
	file      *secureUserFile
	alternate *secureUserFile
	host      string
	token     string
	expected  string
	lookupEnv func(string) string
}

func NewNetrcWriter(home *secureUserHome, policy PyPIPolicy) (*NetrcWriter, error) {
	if home == nil {
		return nil, errors.New("netrc: nil secure user home")
	}
	registry, registryErr := parsePolicyRegistryURL(policy.RegistryURL)
	host := policy.RegistryHost()
	token := policy.DeviceToken()
	if policy.Ecosystem != "pypi" || !canonicalPyPIClients(policy.Clients) || policy.Auth.Scheme != pypiAuthScheme ||
		registryErr != nil || registry.EscapedPath() != "/python/simple" || policy.Auth.APIKey == "" ||
		len(policy.Auth.APIKey) > npmrcMaxKeyBytes || policy.deviceID == "" || len(policy.deviceID) > npmrcMaxSerialBytes ||
		strings.Contains(policy.Auth.APIKey, "::") || !isNPMSafe(policy.Auth.APIKey) || !isNPMSafe(policy.deviceID) ||
		!isValidHost(host) || !isNetrcCredential(token) {
		return nil, errors.New("netrc: policy cannot render a safe credential entry")
	}
	expected := renderNetrcEntry(host, token)

	primary, err := home.openStrict(".netrc", netrcBackupPrefix, maxManagedUserFileBytes)
	if err != nil {
		return nil, err
	}
	w := &NetrcWriter{file: primary, host: host, token: token, expected: expected, lookupEnv: home.getenv}
	if runtime.GOOS != model.PlatformWindows {
		return w, nil
	}

	alternate, err := home.openStrict("_netrc", netrcBackupPrefix, maxManagedUserFileBytes)
	if err != nil {
		return nil, err
	}
	_, primaryExists, _, err := primary.Read()
	if err != nil {
		return nil, err
	}
	_, alternateExists, _, err := alternate.Read()
	if err != nil {
		return nil, err
	}
	if !primaryExists && alternateExists {
		w.file, w.alternate = alternate, primary
	} else {
		w.alternate = alternate
	}
	return w, nil
}

func renderNetrcEntry(host, token string) string {
	return "machine " + host + "\nlogin step-security\npassword " + token
}

func isNetrcCredential(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (w *NetrcWriter) Location() string {
	if w == nil || w.file == nil {
		return ""
	}
	return w.file.Location()
}

func (w *NetrcWriter) validateExpected(expected string) error {
	if w == nil || w.file == nil || expected != w.expected {
		return errors.New("netrc: expected entry does not match the validated policy")
	}
	return nil
}

// Read returns the DMG-managed entry without its markers.
func (w *NetrcWriter) Read() (string, bool, error) {
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed || analysis.markers.dmg == nil {
		return "", false, err
	}
	return analysis.markers.dmg.body, true, nil
}

// Write migrates at most one ordinary exact-host entry and installs the managed entry.
func (w *NetrcWriter) Write(expected string) (string, error) {
	if err := w.validateExpected(expected); err != nil {
		return "", err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return "", err
	}
	analysis, err := w.readSelected()
	if err != nil {
		return "", err
	}
	if analysis.markers.mdm {
		return "", fmt.Errorf("netrc: MDM marker conflicts with DMG ownership: %w", ErrTargetUnusable)
	}

	next, err := rewriteNetrc(analysis.data, w.host, expected)
	if err != nil {
		return "", err
	}
	if err := w.file.Commit(next, secureUserFileMode); err != nil {
		return "", err
	}
	readback, present, err := w.Read()
	if err != nil || !present || readback != expected {
		if err == nil {
			err = errors.New("netrc: managed credential did not match readback")
		}
		if restoreErr := w.file.RestoreSnapshot(); restoreErr != nil {
			return "", fmt.Errorf("netrc: readback failed and rollback failed: %w", ErrWriteUnverified)
		}
		return "", err
	}
	return readback, nil
}

// Clear removes this lane's block and restores only entries carrying its prefix.
func (w *NetrcWriter) Clear() (bool, error) {
	type candidate struct {
		file     *secureUserFile
		analysis netrcAnalysis
	}
	files := []*secureUserFile{w.file}
	if w.alternate != nil {
		files = append(files, w.alternate)
	}
	candidates := make([]candidate, 0, len(files))
	owned := -1
	conflict := false
	for _, file := range files {
		data, existed, _, err := file.Read()
		if err != nil {
			return false, err
		}
		analysis := netrcAnalysis{existed: existed}
		if existed {
			analysis, err = analyzeNetrc(data)
			if err != nil {
				return false, err
			}
			analysis.existed = true
		}
		candidates = append(candidates, candidate{file: file, analysis: analysis})
		if analysis.markers.dmg != nil {
			if owned >= 0 {
				return false, fmt.Errorf("netrc: multiple managed credential files: %w", ErrTargetUnusable)
			}
			owned = len(candidates) - 1
		} else if analysis.markers.mdm || len(exactHostEntries(analysis.entries, w.host)) != 0 {
			conflict = true
		}
	}
	if owned >= 0 {
		for i, candidate := range candidates {
			if i != owned && (candidate.analysis.markers.dmg != nil || candidate.analysis.markers.mdm || len(exactHostEntries(candidate.analysis.entries, w.host)) != 0) {
				return false, fmt.Errorf("netrc: alternate credential file conflicts with managed file: %w", ErrTargetUnusable)
			}
		}
	} else if conflict {
		return false, fmt.Errorf("netrc: exact-host credential exists without an owned block: %w", ErrTargetUnusable)
	}
	purge := func() error {
		var errs []error
		for _, candidate := range candidates {
			if err := candidate.file.PurgeBackups(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	if owned < 0 {
		return false, purge()
	}
	target := candidates[owned]
	next, changed, err := clearNetrc(target.analysis.data)
	if err != nil || !changed {
		return false, err
	}
	rest, _ := stripBOM(next)
	if len(bytes.TrimSpace(rest)) == 0 {
		err = target.file.Remove()
	} else {
		err = target.file.Commit(next, secureUserFileMode)
	}
	if err != nil {
		return false, err
	}
	if err := purge(); err != nil {
		return false, errors.Join(fmt.Errorf("netrc: purge backups: %w", err), target.file.RestoreSnapshot())
	}
	return true, nil
}

func (w *NetrcWriter) RestoreSnapshot() error { return w.file.RestoreSnapshot() }

func (w *NetrcWriter) Converged(expected string) (bool, error) {
	if err := w.validateExpected(expected); err != nil {
		return false, err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return false, err
	}
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed {
		return false, err
	}
	if analysis.markers.mdm || analysis.markers.dmg == nil || analysis.markers.dmg.body != expected {
		return false, nil
	}
	entries := exactHostEntries(analysis.entries, w.host)
	if len(entries) > 1 {
		return false, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if len(entries) != 1 || !entryMatches(entries[0], w.host, "step-security", w.token) {
		return false, nil
	}
	if w.netrcOverrideActive() {
		return false, nil
	}
	return w.file.MetadataSecure(secureUserFileMode)
}

// Observation returns only a secret-free credential verdict.
func (w *NetrcWriter) Observation(expected string) (string, error) {
	if err := w.validateExpected(expected); err != nil {
		return authTokenUnreadable, err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return authTokenUnreadable, err
	}
	analysis, err := w.readSelected()
	if err != nil {
		return authTokenUnreadable, err
	}
	if !analysis.existed {
		return authTokenAbsent, nil
	}
	entries := exactHostEntries(analysis.entries, w.host)
	if len(entries) == 0 {
		return authTokenAbsent, nil
	}
	if len(entries) > 1 {
		return authTokenUnreadable, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if !entryMatches(entries[0], w.host, "step-security", w.token) || w.netrcOverrideActive() {
		return authTokenMismatch, nil
	}
	secure, err := w.file.MetadataSecure(secureUserFileMode)
	if err != nil {
		return authTokenUnreadable, err
	}
	if !secure {
		return authTokenMismatch, nil
	}
	return authTokenMatch, nil
}

func (w *NetrcWriter) MDMOwned() (bool, error) {
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed || analysis.markers.mdmBlock == nil {
		return false, err
	}
	entries, err := parseNetrc([]byte(analysis.markers.mdmBlock.body))
	if err != nil {
		return false, err
	}
	return len(exactHostEntries(entries, w.host)) == 1, nil
}

func (w *NetrcWriter) HasMDMMarker() (bool, error) {
	for _, file := range []*secureUserFile{w.file, w.alternate} {
		if file == nil {
			continue
		}
		data, existed, _, err := file.Read()
		if err != nil {
			return false, err
		}
		if !existed {
			continue
		}
		markers, err := scanNetrcMarkers(data)
		if err != nil {
			return false, err
		}
		if markers.mdm {
			return true, nil
		}
	}
	return false, nil
}

func (w *NetrcWriter) netrcOverrideActive() bool {
	if w.lookupEnv == nil {
		return false
	}
	override := strings.TrimSpace(w.lookupEnv("NETRC"))
	if override == "" {
		return false
	}
	if !filepath.IsAbs(override) {
		absolute, err := filepath.Abs(override)
		if err != nil {
			return true
		}
		override = absolute
	}
	return filepath.Clean(override) != filepath.Clean(w.Location())
}

func (w *NetrcWriter) checkAlternateConflict() error {
	if w.alternate == nil {
		return nil
	}
	data, existed, _, err := w.alternate.Read()
	if err != nil || !existed {
		return err
	}
	analysis, err := analyzeNetrc(data)
	if err != nil {
		return err
	}
	if analysis.markers.dmg != nil || analysis.markers.mdm || len(exactHostEntries(analysis.entries, w.host)) != 0 {
		return fmt.Errorf("netrc: alternate credential file conflicts with selected file: %w", ErrTargetUnusable)
	}
	return nil
}

func (w *NetrcWriter) readSelected() (netrcAnalysis, error) {
	if w == nil || w.file == nil {
		return netrcAnalysis{}, errors.New("netrc: nil writer")
	}
	data, existed, _, err := w.file.Read()
	if err != nil || !existed {
		return netrcAnalysis{existed: existed}, err
	}
	analysis, err := analyzeNetrc(data)
	analysis.existed = true
	return analysis, err
}

const authTokenUnreadable = "unreadable"

type netrcAnalysis struct {
	data    []byte
	existed bool
	entries []netrcEntry
	markers netrcMarkers
}

type netrcMarkers struct {
	dmg      *netrcManagedBlock
	mdmBlock *netrcManagedBlock
	mdm      bool
}

type netrcManagedBlock struct {
	start int
	end   int
	body  string
}

type netrcEntry struct {
	host                       string
	login, account, pass       string
	startToken, startLine, end int
	isDefault                  bool
}

func analyzeNetrc(data []byte) (netrcAnalysis, error) {
	markers, err := scanNetrcMarkers(data)
	if err != nil {
		return netrcAnalysis{}, err
	}
	rest, _ := stripBOM(data)
	entries, err := parseNetrc(rest)
	if err != nil {
		return netrcAnalysis{}, err
	}
	for _, block := range []*netrcManagedBlock{markers.dmg, markers.mdmBlock} {
		if block == nil {
			continue
		}
		bodyEntries, err := parseNetrc([]byte(block.body))
		if err != nil || len(bodyEntries) != 1 || bodyEntries[0].isDefault {
			return netrcAnalysis{}, fmt.Errorf("netrc: malformed managed credential block: %w", ErrTargetUnusable)
		}
	}
	return netrcAnalysis{data: data, existed: true, entries: entries, markers: markers}, nil
}

func exactHostEntries(entries []netrcEntry, host string) []netrcEntry {
	out := make([]netrcEntry, 0, 1)
	for _, entry := range entries {
		if !entry.isDefault && entry.host == host {
			out = append(out, entry)
		}
	}
	return out
}

func entryMatches(entry netrcEntry, host, login, password string) bool {
	return !entry.isDefault && entry.host == host && entry.login == login && entry.pass == password
}

func rewriteNetrc(data []byte, host, expected string) ([]byte, error) {
	analysis, err := analyzeNetrc(data)
	if err != nil {
		return nil, err
	}
	if len(exactHostEntries(analysis.entries, host)) > 1 {
		return nil, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	rest, bom := stripBOM(data)
	if analysis.markers.dmg != nil {
		rest = append(append([]byte(nil), rest[:analysis.markers.dmg.start]...), rest[analysis.markers.dmg.end:]...)
	}
	entries, err := parseNetrc(rest)
	if err != nil {
		return nil, err
	}
	exact := exactHostEntries(entries, host)
	if len(exact) > 1 {
		return nil, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if len(exact) == 1 {
		entry := exact[0]
		if entry.end <= entry.startLine || len(bytes.TrimSpace(rest[entry.startLine:entry.startToken])) != 0 {
			return nil, fmt.Errorf("netrc: exact-host entry shares a line with another entry: %w", ErrTargetUnusable)
		}
		rest = prefixNetrcLines(rest, entry.startLine, entry.end)
	}

	newline := netrcNewline(data)
	var out bytes.Buffer
	out.Write(bom)
	out.Write(rest)
	if len(rest) != 0 {
		// This separator belongs to the managed block, so clear can remove it exactly.
		out.WriteString(newline)
	}
	out.WriteString(dmgNetrcBegin)
	out.WriteString(newline)
	out.WriteString(strings.ReplaceAll(expected, "\n", newline))
	out.WriteString(newline)
	out.WriteString(dmgNetrcEnd)
	out.WriteString(newline)
	return out.Bytes(), nil
}

func clearNetrc(data []byte) ([]byte, bool, error) {
	analysis, err := analyzeNetrc(data)
	if err != nil {
		return nil, false, err
	}
	rest, bom := stripBOM(data)
	changed := false
	if analysis.markers.dmg != nil {
		rest = append(append([]byte(nil), rest[:analysis.markers.dmg.start]...), rest[analysis.markers.dmg.end:]...)
		changed = true
	}
	restored, unprefixed := unprefixNetrcLines(rest)
	changed = changed || unprefixed
	if !changed {
		return data, false, nil
	}
	if _, err := parseNetrc(restored); err != nil {
		return nil, false, err
	}
	return append(append([]byte(nil), bom...), restored...), true, nil
}

func prefixNetrcLines(data []byte, start, end int) []byte {
	var out bytes.Buffer
	out.Grow(len(data) + (bytes.Count(data[start:end], []byte("\n"))+1)*len(dmgNetrcDisabledPrefix))
	out.Write(data[:start])
	for pos := start; pos < end; {
		lineEnd := bytes.IndexByte(data[pos:end], '\n')
		if lineEnd < 0 {
			lineEnd = end - pos
		} else {
			lineEnd++
		}
		out.WriteString(dmgNetrcDisabledPrefix)
		out.Write(data[pos : pos+lineEnd])
		pos += lineEnd
	}
	out.Write(data[end:])
	return out.Bytes()
}

func unprefixNetrcLines(data []byte) ([]byte, bool) {
	lines := splitNetrcLines(data)
	var out bytes.Buffer
	changed := false
	for _, line := range lines {
		content := data[line.start:line.contentEnd]
		if bytes.HasPrefix(content, []byte(dmgNetrcDisabledPrefix)) {
			out.Write(content[len(dmgNetrcDisabledPrefix):])
			out.Write(data[line.contentEnd:line.end])
			changed = true
		} else {
			out.Write(data[line.start:line.end])
		}
	}
	return out.Bytes(), changed
}

type netrcLine struct {
	start, contentEnd, end int
}

func splitNetrcLines(data []byte) []netrcLine {
	lines := make([]netrcLine, 0, bytes.Count(data, []byte("\n"))+1)
	for start := 0; start < len(data); {
		i := bytes.IndexByte(data[start:], '\n')
		end := len(data)
		contentEnd := end
		if i >= 0 {
			end = start + i + 1
			contentEnd = end - 1
			if contentEnd > start && data[contentEnd-1] == '\r' {
				contentEnd--
			}
		}
		lines = append(lines, netrcLine{start: start, contentEnd: contentEnd, end: end})
		start = end
	}
	return lines
}

func scanNetrcMarkers(data []byte) (netrcMarkers, error) {
	rest, _ := stripBOM(data)
	if !utf8.Valid(rest) || bytes.IndexByte(rest, 0) >= 0 || hasLoneCR(string(rest)) {
		return netrcMarkers{}, fmt.Errorf("netrc: invalid text encoding or line endings: %w", ErrTargetUnusable)
	}
	lines := splitNetrcLines(rest)
	var begins, ends, mdmBegins []netrcLine
	for _, line := range lines {
		text := strings.TrimSpace(string(rest[line.start:line.contentEnd]))
		switch text {
		case dmgNetrcBegin:
			begins = append(begins, line)
		case dmgNetrcEnd:
			ends = append(ends, line)
		case mdmNetrcBegin:
			mdmBegins = append(mdmBegins, line)
		}
	}
	if len(mdmBegins) > 1 || (len(mdmBegins) == 1 && len(begins) != 0) {
		return netrcMarkers{}, fmt.Errorf("netrc: duplicate or conflicting managed markers: %w", ErrTargetUnusable)
	}
	if len(begins) == 0 {
		if len(ends) == 0 {
			return netrcMarkers{}, nil
		}
		if len(mdmBegins) != 1 || len(ends) != 1 || mdmBegins[0].start >= ends[0].start {
			return netrcMarkers{}, fmt.Errorf("netrc: malformed managed markers: %w", ErrTargetUnusable)
		}
		block, err := netrcMarkerBlock(rest, mdmBegins[0], ends[0])
		return netrcMarkers{mdm: true, mdmBlock: block}, err
	}
	if len(begins) != 1 || len(ends) != 1 || begins[0].start >= ends[0].start {
		return netrcMarkers{}, fmt.Errorf("netrc: duplicate or malformed managed markers: %w", ErrTargetUnusable)
	}
	block, err := netrcMarkerBlock(rest, begins[0], ends[0])
	return netrcMarkers{dmg: block}, err
}

func netrcMarkerBlock(data []byte, begin, end netrcLine) (*netrcManagedBlock, error) {
	bodyBytes := trimOneNetrcNewline(data[begin.end:end.start])
	body := strings.ReplaceAll(string(bodyBytes), "\r\n", "\n")
	blockStart := begin.start
	if blockStart > 0 {
		switch {
		case blockStart >= 2 && bytes.Equal(data[blockStart-2:blockStart], []byte("\r\n")):
			blockStart -= 2
		case data[blockStart-1] == '\n':
			blockStart--
		default:
			return nil, fmt.Errorf("netrc: managed marker is not line-delimited: %w", ErrTargetUnusable)
		}
	}
	return &netrcManagedBlock{start: blockStart, end: end.end, body: body}, nil
}

func trimOneNetrcNewline(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return data[:len(data)-2]
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		return data[:len(data)-1]
	}
	return data
}

func netrcNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

type netrcToken struct {
	value     string
	start     int
	lineStart int
}

func lexNetrc(data []byte) ([]netrcToken, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || hasLoneCR(string(data)) {
		return nil, fmt.Errorf("netrc: invalid text encoding or line endings: %w", ErrTargetUnusable)
	}
	var tokens []netrcToken
	for i := 0; i < len(data); {
		for i < len(data) {
			if data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r' {
				i++
				continue
			}
			break
		}
		if i >= len(data) {
			break
		}
		start := i
		lineStart := bytes.LastIndexByte(data[:start], '\n') + 1
		var value strings.Builder
		quote := byte(0)
		for i < len(data) {
			c := data[i]
			if quote != 0 {
				switch c {
				case quote:
					quote = 0
					i++
				case '\\':
					if i+1 >= len(data) || data[i+1] == '\n' || data[i+1] == '\r' {
						return nil, fmt.Errorf("netrc: malformed quoted token: %w", ErrTargetUnusable)
					}
					value.WriteByte(data[i+1])
					i += 2
				default:
					value.WriteByte(c)
					i++
				}
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
				i++
			case '\\':
				if i+1 >= len(data) || data[i+1] == '\n' || data[i+1] == '\r' {
					return nil, fmt.Errorf("netrc: malformed escaped token: %w", ErrTargetUnusable)
				}
				value.WriteByte(data[i+1])
				i += 2
			case ' ', '\t', '\n', '\r':
				goto tokenDone
			default:
				value.WriteByte(c)
				i++
			}
		}
	tokenDone:
		if quote != 0 || value.Len() == 0 {
			return nil, fmt.Errorf("netrc: malformed tokenization: %w", ErrTargetUnusable)
		}
		tokens = append(tokens, netrcToken{value: value.String(), start: start, lineStart: lineStart})
	}
	return tokens, nil
}

func skipNetrcLine(tokens []netrcToken, i int) int {
	lineStart := tokens[i].lineStart
	for i < len(tokens) && tokens[i].lineStart == lineStart {
		i++
	}
	return i
}

func parseNetrc(data []byte) ([]netrcEntry, error) {
	tokens, err := lexNetrc(data)
	if err != nil {
		return nil, err
	}
	entries := make([]netrcEntry, 0)
	for i := 0; i < len(tokens); {
		token := tokens[i]
		if strings.HasPrefix(token.value, "#") {
			i = skipNetrcLine(tokens, i)
			continue
		}
		entry := netrcEntry{startToken: token.start, startLine: token.lineStart}
		switch token.value {
		case "machine":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("netrc: machine has no name: %w", ErrTargetUnusable)
			}
			entry.host = tokens[i].value
			i++
		case "default":
			entry.isDefault = true
			i++
		case "macdef":
			return nil, fmt.Errorf("netrc: macdef is unsupported: %w", ErrTargetUnusable)
		default:
			return nil, fmt.Errorf("netrc: directive outside an entry: %w", ErrTargetUnusable)
		}

		seen := map[string]bool{}
		for i < len(tokens) && tokens[i].value != "machine" && tokens[i].value != "default" && tokens[i].value != "macdef" {
			if strings.HasPrefix(tokens[i].value, "#") {
				i = skipNetrcLine(tokens, i)
				continue
			}
			directive := tokens[i].value
			if directive != "login" && directive != "account" && directive != "password" {
				return nil, fmt.Errorf("netrc: unsupported entry directive: %w", ErrTargetUnusable)
			}
			if seen[directive] {
				return nil, fmt.Errorf("netrc: duplicate entry directive: %w", ErrTargetUnusable)
			}
			seen[directive] = true
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("netrc: entry directive has no value: %w", ErrTargetUnusable)
			}
			value := tokens[i].value
			switch directive {
			case "login":
				entry.login = value
			case "account":
				entry.account = value
			case "password":
				entry.pass = value
			}
			i++
		}
		entry.end = len(data)
		if i < len(tokens) {
			entry.end = tokens[i].lineStart
		}
		entries = append(entries, entry)
	}
	defaultSeen := false
	for _, entry := range entries {
		if entry.isDefault {
			if defaultSeen {
				return nil, fmt.Errorf("netrc: duplicate default entries: %w", ErrTargetUnusable)
			}
			defaultSeen = true
		}
	}
	return entries, nil
}
