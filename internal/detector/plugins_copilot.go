package detector

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var copilotCatalogPaths = []string{"marketplace.json", ".plugin/marketplace.json", ".github/plugin/marketplace.json", ".claude-plugin/marketplace.json"}
var copilotManifestPaths = []string{".plugin/plugin.json", "plugin.json", ".github/plugin/plugin.json", ".claude-plugin/plugin.json"}

type copilotLayer struct {
	path, scope, project string
	enabled              map[string]json.RawMessage
	markets              map[string]json.RawMessage
	disabledMCP          []string
}

type copilotAdapter struct {
	s            *pluginScan
	gd           *SkillsDetector
	c            *model.AgentPluginContext
	root         string
	layers       []copilotLayer
	markets      map[string]*model.MarketplaceObservation
	cache        string
	catalogRoots map[string]string
}

func copilotConfigRoot(exec executor.Executor, home string) string {
	if root := exec.Getenv("COPILOT_HOME"); filepath.IsAbs(root) {
		return filepath.Clean(root)
	}
	return filepath.Join(home, ".copilot")
}

func copilotCacheRoot(exec executor.Executor, home string) string {
	if root := exec.Getenv("COPILOT_CACHE_HOME"); filepath.IsAbs(root) {
		return filepath.Clean(root)
	}
	switch exec.GOOS() {
	case model.PlatformDarwin:
		return filepath.Join(home, "Library", "Caches", "copilot")
	case model.PlatformWindows:
		if root := exec.Getenv("LOCALAPPDATA"); filepath.IsAbs(root) {
			return filepath.Join(root, "copilot")
		}
		return ""
	default:
		if root := exec.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(root) {
			return filepath.Join(root, "copilot")
		}
		return filepath.Join(home, ".cache", "copilot")
	}
}

func (s *pluginScan) detectCopilot() *model.AgentPluginContext {
	root := copilotConfigRoot(s.d.exec, s.home)
	store := filepath.Join(root, "installed-plugins")
	if executor.UserEnvironmentError(s.d.exec) != nil {
		return s.unresolvedContext(model.AgentCopilot, root, store)
	}
	cache := copilotCacheRoot(s.d.exec, s.home)
	gd := s.guarded(root, cache, filepath.Dir(copilotManagedSettingsPath(s.d.exec)))
	state, _, _ := s.stat(gd, root)
	// Project-only directory registrations can exist without a user config root.
	if state != fileDir && state != fileAbsent {
		return s.unresolvedContext(model.AgentCopilot, root, store)
	}
	a := &copilotAdapter{s: s, gd: gd, root: root, cache: cache}
	restore := s.snapshotRetry()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			restore()
		}
		s.reads = map[string]pluginMetadataStamp{}
		s.sourceChanged = false
		a.c = s.newContext(model.AgentCopilot, root, store)
		a.run()
		if !s.snapshotChanged() {
			break
		}
		if attempt == 1 {
			a.fail(model.AgentScanErrSourceChanged, filepath.Join(root, "config.json"))
			for i := range a.c.Plugins {
				degrade(&a.c.Plugins[i].ComponentStatus, model.AgentScanStatusPartial)
			}
			break
		}
	}
	s.evidence.suppress(store, filepath.Join(root, "plugin-data"))
	if cache != "" {
		s.evidence.suppress(filepath.Join(cache, "marketplaces"))
	}
	if state == fileAbsent && len(a.c.Plugins) == 0 && len(a.c.Marketplaces) == 0 && len(a.c.Errors) == 0 {
		return nil
	}
	return a.c
}

func (a *copilotAdapter) object(file string) (map[string]json.RawMessage, bool, string) {
	data, absent, code := a.s.readMetadata(a.gd, file)
	if absent || code != "" {
		return nil, absent, code
	}
	data, err := hujson.Standardize(data)
	var obj map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &obj) != nil || obj == nil {
		return nil, false, model.AgentScanErrParseFailed
	}
	return obj, false, ""
}

func (a *copilotAdapter) fail(code, file string) {
	degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
	degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
	scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: file})
}

func (a *copilotAdapter) run() {
	a.markets = map[string]*model.MarketplaceObservation{}
	a.catalogRoots = map[string]string{}
	a.layers = nil
	configPath := filepath.Join(a.root, "config.json")
	state, _, code := a.object(configPath)
	if code != "" {
		a.fail(code, configPath)
	}
	a.settings(state)
	records, exists := state["installedPlugins"]
	if !exists {
		records = state["installed_plugins"]
	}
	if len(records) > 0 {
		var rows []json.RawMessage
		if json.Unmarshal(records, &rows) != nil || rows == nil {
			a.fail(model.AgentScanErrParseFailed, configPath)
		} else {
			for i, row := range rows {
				if i >= maxPluginObs || a.s.ctx.Err() != nil {
					a.fail(model.AgentScanErrLimitExceeded, configPath)
					break
				}
				a.registry(row, configPath)
			}
		}
	}
	a.liveSelections()
	for _, name := range sortedMapKeys(a.markets) {
		a.c.Marketplaces = append(a.c.Marketplaces, *a.markets[name])
	}
}

func (a *copilotAdapter) settings(state map[string]json.RawMessage) {
	layers := []copilotLayer{{path: filepath.Join(a.root, "settings.json"), scope: model.PluginScopeUser}, {path: copilotManagedSettingsPath(a.s.d.exec), scope: model.PluginScopeSystem}}
	for _, project := range a.s.projects {
		for _, entry := range []struct{ rel, scope string }{{".github/copilot/settings.json", model.PluginScopeProject}, {".github/copilot/settings.local.json", model.PluginScopeLocal}, {".claude/settings.json", model.PluginScopeProject}, {".claude/settings.local.json", model.PluginScopeLocal}} {
			layers = append(layers, copilotLayer{path: filepath.Join(project, filepath.FromSlash(entry.rel)), scope: entry.scope, project: project})
		}
	}
	for _, layer := range layers {
		doc, absent, code := a.object(layer.path)
		if absent && layer.scope == model.PluginScopeUser && state != nil {
			doc, absent = state, false
			layer.path = filepath.Join(a.root, "config.json")
		}
		if absent {
			continue
		}
		if code != "" {
			a.fail(code, layer.path)
			continue
		}
		for key, dst := range map[string]*map[string]json.RawMessage{"enabledPlugins": &layer.enabled, "extraKnownMarketplaces": &layer.markets} {
			if raw, ok := doc[key]; ok && (json.Unmarshal(raw, dst) != nil || *dst == nil) {
				a.fail(model.AgentScanErrParseFailed, layer.path)
			}
		}
		if raw, ok := doc["disabledMcpServers"]; ok {
			if json.Unmarshal(raw, &layer.disabledMCP) != nil {
				a.fail(model.AgentScanErrParseFailed, layer.path)
			}
		}
		a.layers = append(a.layers, layer)
		for _, name := range sortedMapKeys(layer.markets) {
			if len(a.markets) >= maxMarketplaceObs {
				a.fail(model.AgentScanErrLimitExceeded, layer.path)
				break
			}
			var entry map[string]json.RawMessage
			if json.Unmarshal(layer.markets[name], &entry) != nil || entry == nil {
				a.fail(model.AgentScanErrParseFailed, layer.path)
				continue
			}
			source := copilotSource(entry["source"])
			m := a.market(name)
			m.Registered = true
			if m.Source != nil && source != nil {
				old, _ := json.Marshal(m.Source)
				current, _ := json.Marshal(source)
				if string(old) != string(current) {
					a.fail(model.AgentScanErrUnsupportedSchema, layer.path)
					m.Source = &model.SourceLocator{Kind: model.PluginSourceUnknown}
					continue
				}
			}
			m.Source = source
			a.catalogRoots[name] = copilotCatalogRoot(entry["source"], a.cache)
			if enabled := jsonBool(entry["autoUpdate"]); enabled != nil && len(m.AutoUpdatePreferences) < maxAutoUpdatePrefs {
				m.AutoUpdatePreferences = append(m.AutoUpdatePreferences, model.EnablementObservation{Scope: layer.scope, ProjectPath: layer.project, SourcePath: layer.path, Enabled: *enabled})
				if layer.scope == model.PluginScopeUser {
					m.AutoUpdateEnabled = enabled
				}
			}
		}
	}
}

func (a *copilotAdapter) market(name string) *model.MarketplaceObservation {
	if m := a.markets[name]; m != nil {
		return m
	}
	m := &model.MarketplaceObservation{MarketplaceID: marketplaceID(a.c.ContextID, name), Name: name}
	a.markets[name] = m

	return m
}

func copilotSource(raw json.RawMessage) *model.SourceLocator {
	if value := jsonString(raw); value != "" {
		switch {
		case isAbsPath(value):
			return &model.SourceLocator{Kind: model.PluginSourceLocal, NativeKind: "local", Location: cleanPluginPath(value)}
		case strings.Contains(value, "://"), scpLikeRE.MatchString(value):
			return &model.SourceLocator{Kind: model.PluginSourceGit, NativeKind: "url", Location: sanitizeLocation(value)}
		default:
			repo, sub, _ := strings.Cut(value, ":")
			if len(strings.Split(repo, "/")) == 2 && !strings.ContainsAny(repo, "?# ") {
				loc := &model.SourceLocator{Kind: model.PluginSourceGitHub, NativeKind: "github", Location: githubLocation(repo), Subdirectory: sub}
				if validSource(loc) {
					return loc
				}
			}
			return &model.SourceLocator{Kind: model.PluginSourceUnknown}
		}
	}

	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil
	}
	native := jsonString(fields["source"])
	loc := &model.SourceLocator{NativeKind: native, Kind: model.PluginSourceUnknown, RequestedRef: jsonString(fields["ref"]), RequestedSHA: jsonString(fields["sha"])}
	switch native {
	case "directory", "local":
		loc.Kind = model.PluginSourceLocal
		if p := jsonString(fields["path"]); isAbsPath(p) {
			loc.Location = cleanPluginPath(p)
		}
	case "github":
		loc.Kind = model.PluginSourceGitHub
		repo, sub, _ := strings.Cut(jsonString(fields["repo"]), ":")
		loc.Location = githubLocation(repo)
		loc.Subdirectory = sub
	case "git", "url":
		loc.Kind = model.PluginSourceGit
		loc.Location = sanitizeLocation(jsonString(fields["url"]))
	}
	if loc.Kind == model.PluginSourceGit || loc.Kind == model.PluginSourceGitHub {
		if sub := jsonString(fields["path"]); sub != "" {
			loc.Subdirectory = sub
		}
	}
	if !validSource(loc) {
		return &model.SourceLocator{Kind: model.PluginSourceUnknown, NativeKind: native}
	}
	return loc
}

// Copilot 1.0.91's native cache-path helper keys GitHub by repo and Git by URL.
func copilotCatalogRoot(raw json.RawMessage, cache string) string {
	source := copilotSource(raw)
	if source == nil {
		return ""
	}
	if source.Kind == model.PluginSourceLocal {
		return source.Location
	}
	if cache == "" {
		return ""
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	value := jsonString(raw)
	var key string
	switch source.Kind {
	case model.PluginSourceGitHub:
		if fields != nil {
			value = jsonString(fields["repo"])
		}
		if strings.ContainsAny(value, "?#@") {
			return ""
		}
		key = strings.Replace(value, "/", "-", 1)
	case model.PluginSourceGit:
		if fields != nil {
			value = jsonString(fields["url"])
		}
		if sanitizeLocation(value) != value {
			return ""
		}
		key = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, value)
	default:
		return ""
	}
	if key == "" {
		return ""
	}
	root, safe := insideRoot(filepath.Join(cache, "marketplaces"), key)
	if !safe {
		return ""
	}
	return root
}

func (a *copilotAdapter) registry(raw json.RawMessage, file string) {
	var record map[string]json.RawMessage
	if json.Unmarshal(raw, &record) != nil || record == nil {
		a.fail(model.AgentScanErrParseFailed, file)
		return
	}
	name := jsonString(record["name"])
	var market string
	if strings.TrimSpace(name) == "" || len(name) > maxNameBytes || !decodePortableValue(record["marketplace"], &market) {
		a.fail(model.AgentScanErrParseFailed, file)
		return
	}
	native, kind := name, model.PluginInstallDirectory
	if market != "" {
		native, kind = name+"@"+market, model.PluginInstallMarketplace
	}
	p := newPlugin(native, name, kind, model.PluginScopeUser)
	p.Installed = boolPtr(true)
	p.InstallationEvidence = model.PluginEvidenceRegistry
	p.InstallPath = cleanPluginPath(jsonString(record["cache_path"]))
	p.Source = copilotSource(record["source"])
	if p.Source != nil {
		if p.Source.Kind == model.PluginSourceLocal {
			p.SourcePath = p.Source.Location
		}
	}
	p.CacheVersion = jsonString(record["version"])
	p.InstalledAtMs = parseNativeTimeMs(jsonString(record["installed_at"]))
	p.ConfiguredEnabled = jsonBool(record["enabled"])
	if p.ConfiguredEnabled != nil {
		p.Enablement = append(p.Enablement, model.EnablementObservation{Scope: p.Scope, SourcePath: file, Enabled: *p.ConfiguredEnabled})
	}
	if market != "" {
		m := a.market(market)
		if m.Source == nil && !m.Registered && a.c.MarketplaceStatus == model.AgentScanStatusComplete && (market == "copilot-plugins" || market == "awesome-copilot") {
			raw, _ := json.Marshal("github/" + market)
			m.Source = copilotSource(raw)
			a.catalogRoots[market] = copilotCatalogRoot(raw, a.cache)
		}
		p.MarketplaceID = m.MarketplaceID
		root := a.catalogRoots[market]
		if root == "" || m.Source == nil || m.Source.Kind == model.PluginSourceUnknown {
			copilotComponentError(p, model.AgentScanErrRootUnresolved, a.root)
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
		} else if entry, found := a.catalogEntry(m, root, name); !found {
			copilotComponentError(p, model.AgentScanErrReadFailed, m.CatalogPath)
		} else if p.Source == nil {
			if declared := jsonString(entry["source"]); declared != "" && !isAbsPath(declared) && !strings.Contains(declared, ":") {
				if _, safe := insideRoot(root, declared); safe {
					source := *m.Source
					if source.Kind == model.PluginSourceLocal {
						source.Location, _ = insideRoot(root, declared)
						p.SourcePath = source.Location
					} else {
						source.Subdirectory = path.Join(source.Subdirectory, declared)
					}
					p.Source = &source
				}
			} else {
				p.Source = copilotSource(entry["source"])
			}
		}
	}
	if p.Source != nil {
		p.Source.ResolvedRevision = jsonString(record["source_sha"])
	}
	if p.InstallPath == "" || !isAbsPath(p.InstallPath) {
		p.InstallPath = ""
		a.fail(model.AgentScanErrRootUnresolved, file)
		p.ComponentStatus = model.AgentScanStatusPartial
		scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrRootUnresolved, SourcePath: file})
	}
	a.finish(p)
}

func (a *copilotAdapter) finish(p *model.PluginObservation) {
	p.InstanceID = a.s.instanceID(a.c.ContextID, p)
	for _, layer := range a.layers {
		if raw, ok := layer.enabled[p.NativeID]; ok {
			if enabled := jsonBool(raw); enabled != nil {
				p.Enablement = append(p.Enablement, model.EnablementObservation{Scope: layer.scope, SourcePath: layer.path, ProjectPath: layer.project, Enabled: *enabled})
			} else {
				a.fail(model.AgentScanErrParseFailed, layer.path)
			}
		}
	}
	if p.InstallPath != "" {
		p.FilesPresent = a.s.dirExists(a.gd, p.InstallPath)
		if p.FilesPresent != nil && *p.FilesPresent {
			a.components(p)
		} else {
			degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrReadFailed, SourcePath: p.InstallPath})
		}
	}
	for i := range p.Components {
		component := &p.Components[i]
		if component.Kind != model.PluginComponentMCP {
			continue
		}
		for _, layer := range a.layers {
			for _, name := range layer.disabledMCP {
				if name == component.Name {
					component.MCPEnablement = append(component.MCPEnablement, model.EnablementObservation{Scope: layer.scope, SourcePath: layer.path, ProjectPath: layer.project, Enabled: false})
					break
				}
			}
		}
	}
	if p.InstallationEvidence == model.PluginEvidenceLocalConfig && p.ManifestName == "" {
		a.fail(model.AgentScanErrParseFailed, p.InstallPath)
		return
	}
	if p.FilesPresent != nil && *p.FilesPresent && p.ManifestName != "" {
		a.s.evidence.suppress(p.InstallPath)
	}
	a.s.addPlugin(a.c, p)
}

func (a *copilotAdapter) liveSelections() {
	for _, layer := range a.layers {
		for _, native := range sortedMapKeys(layer.enabled) {
			if len(a.c.Plugins) >= maxPluginObs || a.s.ctx.Err() != nil {
				a.fail(model.AgentScanErrLimitExceeded, layer.path)
				return
			}
			enabled := jsonBool(layer.enabled[native])
			name, market, ok := strings.Cut(native, "@")
			if enabled == nil || !ok || name == "" || market == "" {
				a.fail(model.AgentScanErrParseFailed, layer.path)
				continue
			}
			registered := false
			for _, p := range a.c.Plugins {
				if p.NativeID == native && p.InstallationEvidence == model.PluginEvidenceRegistry {
					registered = true
					break
				}
			}
			if registered {
				if m := a.markets[market]; m != nil && m.Source != nil && m.Source.Kind == model.PluginSourceLocal {
					a.fail(model.AgentScanErrUnsupportedSchema, layer.path)
				}
				continue
			}
			m := a.markets[market]
			if m == nil || m.Source == nil || m.Source.Kind != model.PluginSourceLocal || m.Source.Location == "" {
				a.fail(model.AgentScanErrRootUnresolved, layer.path)
				continue
			}
			registeredForScope := false
			for _, registration := range a.layers {
				if _, ok := registration.markets[market]; ok && (registration.scope == model.PluginScopeUser || registration.scope == model.PluginScopeSystem || registration.project == layer.project && layer.project != "") {
					registeredForScope = true
					break
				}
			}
			if !registeredForScope {
				a.fail(model.AgentScanErrRootUnresolved, layer.path)
				continue
			}
			alreadySelected := false
			for _, p := range a.c.Plugins {
				if p.NativeID == native && p.InstallationEvidence == model.PluginEvidenceLocalConfig && (p.Scope == model.PluginScopeUser || p.Scope == model.PluginScopeSystem || p.ProjectPath == layer.project) {
					alreadySelected = true
					break
				}
			}
			if alreadySelected {
				continue
			}
			root := m.Source.Location
			entry, found := a.catalogEntry(m, root, name)
			if !found {
				continue
			}
			declared := jsonString(entry["source"])
			payload, safe := insideRoot(root, declared)
			if !safe {
				a.fail(model.AgentScanErrUnsafePath, m.CatalogPath)
				continue
			}
			gd := a.gd.componentReader(root)
			if st, _, _ := a.s.stat(gd, payload); st != fileDir {
				a.fail(model.AgentScanErrReadFailed, payload)
				continue
			}
			p := newPlugin(native, name, model.PluginInstallMarketplace, layer.scope)
			p.MarketplaceID = m.MarketplaceID
			p.ProjectPath = layer.project
			p.InstallPath, p.SourcePath = payload, payload
			p.Source = &model.SourceLocator{Kind: model.PluginSourceLocal, NativeKind: "local", Location: payload}
			p.Installed = boolPtr(true)
			p.InstallationEvidence = model.PluginEvidenceLocalConfig
			p.ConfiguredEnabled = enabled
			a.finish(p)
		}
	}
}

func (a *copilotAdapter) catalogEntry(m *model.MarketplaceObservation, root, name string) (map[string]json.RawMessage, bool) {
	if st, _, err := a.s.stat(a.gd, root); st != fileDir {
		a.fail(readCode(err), root)
		return nil, false
	}
	local := *a
	local.gd = a.gd.componentReader(root)
	for _, rel := range copilotCatalogPaths {
		file := filepath.Join(root, filepath.FromSlash(rel))
		doc, absent, code := local.object(file)
		if absent {
			continue
		}
		m.CatalogPath = file
		if code != "" {
			a.fail(code, file)
			return nil, false
		}
		var owner map[string]json.RawMessage
		if jsonString(doc["name"]) != m.Name || json.Unmarshal(doc["owner"], &owner) != nil || strings.TrimSpace(jsonString(owner["name"])) == "" {
			a.fail(model.AgentScanErrParseFailed, file)
			return nil, false
		}
		var entries []json.RawMessage
		if json.Unmarshal(doc["plugins"], &entries) != nil || entries == nil {
			a.fail(model.AgentScanErrParseFailed, file)
			return nil, false
		}
		payloadRoot := root
		if metadata := doc["metadata"]; len(metadata) > 0 {
			var fields map[string]json.RawMessage
			if json.Unmarshal(metadata, &fields) != nil {
				a.fail(model.AgentScanErrParseFailed, file)
				return nil, false
			}
			if raw, ok := fields["pluginRoot"]; ok {
				var safe bool
				payloadRoot, safe = insideRoot(root, jsonString(raw))
				if !safe {
					a.fail(model.AgentScanErrUnsafePath, file)
					return nil, false
				}
			}
		}
		var selected map[string]json.RawMessage
		for i, raw := range entries {
			if i >= maxPluginObs {
				a.fail(model.AgentScanErrLimitExceeded, file)
				return nil, false
			}
			var entry map[string]json.RawMessage
			if json.Unmarshal(raw, &entry) != nil {
				a.fail(model.AgentScanErrParseFailed, file)
				continue
			}
			if declared := jsonString(entry["source"]); declared != "" && !strings.Contains(declared, ":") {
				target, safe := insideRoot(payloadRoot, declared)
				if !safe {
					a.fail(model.AgentScanErrUnsafePath, file)
					return nil, false
				}
				rel, _ := relSlash(root, target)
				entry["source"], _ = json.Marshal(rel)
				if target != root {
					a.s.evidence.suppress(target)
				}
			}
			if jsonString(entry["name"]) == name {
				if selected != nil {
					a.fail(model.AgentScanErrParseFailed, file)
					return nil, false
				}
				selected = entry
			}
		}
		if selected != nil {
			return selected, true
		}
		a.fail(model.AgentScanErrRootUnresolved, file)
		return nil, false
	}
	a.fail(model.AgentScanErrReadFailed, root)
	return nil, false
}

func copilotComponentError(p *model.PluginObservation, code, file string) {
	degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
	scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: file, InstanceID: p.InstanceID})
}

func (a *copilotAdapter) components(p *model.PluginObservation) {
	local := *a
	a = &local
	a.gd = a.gd.componentReader(p.InstallPath)
	rootDoc, absent, code := a.object(filepath.Join(p.InstallPath, "plugin.json"))
	if code != "" {
		copilotComponentError(p, code, filepath.Join(p.InstallPath, "plugin.json"))
		return
	}
	var doc map[string]json.RawMessage
	schema := jsonString(rootDoc["$schema"])
	if schema != "" {
		if schema != codexPortableSchema && schema != "https://agent-plugins.org/schemas/1.1.0/plugin.schema.json" {
			p.ComponentStatus = model.AgentScanStatusUnsupported
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsupportedSchema, SourcePath: filepath.Join(p.InstallPath, "plugin.json")})
			return
		}
		if _, ok := parsePortableManifest(rootDoc); !ok {
			copilotComponentError(p, model.AgentScanErrParseFailed, filepath.Join(p.InstallPath, "plugin.json"))
			return
		}
		doc = rootDoc
		p.ManifestFormat = model.PluginManifestPortable
		p.ManifestPath = filepath.Join(p.InstallPath, "plugin.json")
	} else {
		for _, rel := range copilotManifestPaths {
			file := filepath.Join(p.InstallPath, filepath.FromSlash(rel))
			var missing bool
			if rel == "plugin.json" {
				doc, missing = rootDoc, absent
			} else {
				doc, missing, code = a.object(file)
			}
			if missing {
				continue
			}
			if code != "" {
				copilotComponentError(p, code, file)
				return
			}
			p.ManifestFormat = model.PluginManifestCopilot
			if strings.HasPrefix(rel, ".claude-plugin/") {
				p.ManifestFormat = model.PluginManifestClaude
			}
			p.ManifestPath = file
			break
		}
	}
	if doc == nil {
		p.ManifestFormat = model.PluginManifestNone
		copilotComponentError(p, model.AgentScanErrReadFailed, p.InstallPath)
		return
	}
	p.ManifestName = jsonString(doc["name"])
	if p.ManifestName == "" {
		copilotComponentError(p, model.AgentScanErrParseFailed, p.ManifestPath)
		return
	}
	p.ManifestVersion = jsonString(doc["version"])
	p.Description = truncRunes(jsonString(doc["description"]), maxDescriptionRunes)
	p.Publisher = truncRunes(nameField(doc["author"]), maxNameBytes)
	p.Homepage = sanitizeHomepage(jsonString(doc["homepage"]))
	r := &pluginRootScan{s: a.s, gd: a.gd, p: p, root: p.InstallPath, attr: nestedAttr{agent: model.AgentCopilot, source: "copilot_plugin", vendor: "GitHub", scope: nestedScope(p.Scope), projectPath: p.ProjectPath}}
	portable := p.ManifestFormat == model.PluginManifestPortable
	skills, agents := []string{"skills"}, []string{"agents"}
	if portable {
		agents = []string{"com.github.copilot/agents"}
	} else {
		for key, dst := range map[string]*[]string{"skills": &skills, "agents": &agents} {
			if raw, ok := doc[key]; ok {
				*dst = stringList(raw)
				if *dst == nil {
					copilotComponentError(p, model.AgentScanErrUnsupportedSchema, p.ManifestPath)
				}
			}
		}
	}
	for _, rel := range skills {
		dir, safe := insideRoot(p.InstallPath, rel)
		if !safe {
			copilotComponentError(p, model.AgentScanErrUnsafePath, p.ManifestPath)
			continue
		}
		dirs := r.skillDirs(dir, !portable)
		if !portable {
			entries, code := a.s.listDir(a.gd, dir)
			if code != "" {
				copilotComponentError(p, code, dir)
			}
			if pluginSkillMD(entries) {
				dirs = []string{dir}
			}
		}
		for _, dir := range dirs {
			rel, _ := relSlash(p.InstallPath, dir)
			r.skillComponent(dir, rel, path.Base(rel), "")
		}
	}
	if !portable && doc["skills"] == nil {
		if st, _, _ := a.s.stat(a.gd, filepath.Join(p.InstallPath, "skills")); st == fileAbsent {
			entries, code := a.s.listDir(a.gd, p.InstallPath)
			if code != "" {
				copilotComponentError(p, code, p.InstallPath)
			} else if pluginSkillMD(entries) {
				r.skillComponent(p.InstallPath, ".", p.Name, "")
			}
		}
	}
	for _, rel := range agents {
		dir, safe := insideRoot(p.InstallPath, rel)
		if !safe {
			copilotComponentError(p, model.AgentScanErrUnsafePath, p.ManifestPath)
			continue
		}
		for _, file := range r.markdownFiles(dir) {
			a.agent(r, file)
		}
	}
	if portable {
		a.mcpFile(r, "mcp.json", strings.Replace(schema, "plugin.schema.json", "mcp.schema.json", 1))
	} else {
		for _, rel := range []string{".mcp.json", ".github/mcp.json"} {
			if a.mcpFile(r, rel, "") {
				return
			}
		}
		if raw, ok := doc["mcpServers"]; ok {
			if declared := jsonString(raw); declared != "" {
				file, safe := insideRoot(p.InstallPath, declared)
				if !safe {
					copilotComponentError(p, model.AgentScanErrUnsafePath, p.ManifestPath)
					return
				}
				rel, _ := relSlash(p.InstallPath, file)
				if !a.mcpFile(r, rel, "") {
					copilotComponentError(p, model.AgentScanErrReadFailed, file)
				}
				return
			}
			rel, _ := relSlash(p.InstallPath, p.ManifestPath)
			a.mcpComponents(r, raw, rel, "/mcpServers", p.ManifestPath)
		}
	}
}

func (a *copilotAdapter) mcpFile(r *pluginRootScan, rel, schema string) bool {
	file := filepath.Join(r.root, filepath.FromSlash(rel))
	doc, absent, code := a.object(file)
	if absent {
		return false
	}
	if code != "" {
		copilotComponentError(r.p, code, file)
		return true
	}
	if schema != "" && (jsonString(doc["$schema"]) != schema || len(doc) != 2 || doc["mcpServers"] == nil) {
		copilotComponentError(r.p, model.AgentScanErrUnsupportedSchema, file)
		return true
	}
	raw, pointer := doc["mcpServers"], "/mcpServers"
	if raw == nil {
		raw, _ = json.Marshal(doc)
		pointer = ""
	}
	a.mcpComponents(r, raw, rel, pointer, file)
	a.s.evidence.owned[file] = true
	return true
}

func (a *copilotAdapter) agent(r *pluginRootScan, file string) {
	if !r.takeDefinition() {
		return
	}
	if _, info, _ := a.s.stat(a.gd, file); info != nil && info.Size() > maxSkillMDReadBytes {
		copilotComponentError(r.p, model.AgentScanErrLimitExceeded, file)
		return
	}
	data, absent, code := a.s.readMetadata(a.gd, file)
	if absent || code != "" {
		copilotComponentError(r.p, model.AgentScanErrReadFailed, file)
		return
	}
	if len(data) > maxSkillMDReadBytes {
		copilotComponentError(r.p, model.AgentScanErrLimitExceeded, file)
		return
	}
	fm, _, ok := splitFrontmatter(string(data))
	fields, err := parseYAMLMap(fm)
	if !ok || err != nil {
		copilotComponentError(r.p, model.AgentScanErrParseFailed, file)
		return
	}
	description, _ := fields["description"].(string)
	if strings.TrimSpace(description) == "" {
		copilotComponentError(r.p, model.AgentScanErrParseFailed, file)
		return
	}
	rel, _ := relSlash(r.root, file)
	name := strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".md"), ".agent")
	r.declared(model.PluginComponentAgent, name, rel, "", file, model.AgentScanStatusComplete)
	if servers, ok := fields["mcp-servers"]; ok {
		raw, err := json.Marshal(servers)
		if err != nil {
			copilotComponentError(r.p, model.AgentScanErrParseFailed, file)
			return
		}
		a.mcpComponents(r, raw, rel, "/mcp-servers", file)
	}
}

func (a *copilotAdapter) mcpComponents(r *pluginRootScan, raw json.RawMessage, rel, pointer, file string) {
	var servers map[string]json.RawMessage
	if json.Unmarshal(raw, &servers) != nil || servers == nil {
		copilotComponentError(r.p, model.AgentScanErrParseFailed, file)
		return
	}
	for _, name := range sortedMapKeys(servers) {
		if !validCopilotMCP(servers[name]) {
			copilotComponentError(r.p, model.AgentScanErrParseFailed, file)
			delete(servers, name)
		}
	}
	raw, _ = json.Marshal(servers)
	r.mcpServerComponents(raw, rel, pointer, file)
}

func copilotManagedSettingsPath(exec executor.Executor) string {
	switch exec.GOOS() {
	case model.PlatformDarwin:
		return "/Library/Application Support/GitHubCopilot/managed-settings.json"
	case model.PlatformWindows:
		root := exec.Getenv("ProgramFiles")
		if root == "" {
			root = `C:\Program Files`
		}
		return filepath.Join(root, "GitHubCopilot", "managed-settings.json")
	default:
		return "/etc/github-copilot/managed-settings.json"
	}
}
