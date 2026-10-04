package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// This fixture is shared verbatim with Agent API internal/ddbmodels/testdata.
func TestCopilotGoldenContract(t *testing.T) {
	data, err := os.ReadFile("testdata/agent_plugins_v1_copilot_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	type wireFixture struct {
		Platform     string       `json:"platform"`
		AgentPlugins AgentPlugins `json:"agent_plugins"`
	}
	var envelope wireFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	scan := envelope.AgentPlugins
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip wireFixture
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(envelope, roundTrip) {
		t.Fatal("Copilot wire fixture changed on round trip")
	}
	id := func(prefix string, parts ...string) string {
		data, _ := json.Marshal(parts)
		sum := sha256.Sum256(data)
		return prefix + hex.EncodeToString(sum[:])
	}
	if scan.SchemaVersion != 1 || len(scan.Contexts) != 1 {
		t.Fatal("invalid fixture envelope")
	}
	c := scan.Contexts[0]
	if c.Agent != AgentCopilot || c.ContextID != id("ctx_", c.Agent, c.ConfigRoot, c.PluginRoot) {
		t.Fatal("context identity mismatch")
	}
	for _, m := range c.Marketplaces {
		if m.MarketplaceID != id("market_", c.ContextID, m.Name) {
			t.Fatal("marketplace identity mismatch")
		}
	}
	for _, p := range c.Plugins {
		if p.InstanceID != id("inst_", c.ContextID, p.NativeID, p.InstallationKind, p.Scope, p.ProjectPath, p.MarketplaceID) {
			t.Fatal("installation identity mismatch")
		}
		for _, component := range p.Components {
			if component.ComponentID != id("comp_", p.InstanceID, component.Kind, component.RelativePath, component.DeclarationPointer, component.Name) {
				t.Fatal("component identity mismatch")
			}
			if component.Skill != nil && (component.Skill.Usage != nil) {
				t.Fatal("skill attribution mismatch")
			}
		}
	}
}
