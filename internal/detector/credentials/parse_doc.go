package credentials

import (
	"encoding/base64"
	"encoding/json"

	"github.com/step-security/dev-machine-guard/internal/model"
	"gopkg.in/yaml.v3"
)

// gcpInlineSecretFields hold usable material in the file itself. The client secret
// belongs here despite its name: the loader accepts it on the external-account
// paths too, so a file naming an external source and carrying one holds material.
//
// Every field naming a credential the loader fetches at run time — an external
// source, an impersonation URL — is deliberately absent: none of them puts
// material in this file.
var gcpInlineSecretFields = []string{"private_key", "refresh_token", "client_secret"}

// parseGCPADC reports whether the application default credentials carry material.
// One file is one credential however many of its fields are filled in, so the
// nested credential adds to the count of nothing.
func parseGCPADC(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		top, ok := decodeJSONObject(data)
		if !ok {
			return false
		}
		material, malformed := gcpInlineMaterial(top)
		// The one field holding a whole credential of its own: an impersonation
		// configuration carries the credential it goes through inside itself. One
		// nested level, no deeper — recursing further would chase a structure the
		// loader does not define. It is read whether or not the outer object held
		// material of its own, because a nested shape this build cannot account
		// for is uncertainty the outer credential does not resolve: the file could
		// be carrying a second one nothing here can see.
		if raw, present := top["source_credentials"]; present && string(raw) != "null" {
			nested, ok := decodeJSONObject(raw)
			if !ok {
				malformed = true
			} else {
				nestedMaterial, nestedMalformed := gcpInlineMaterial(nested)
				material = material || nestedMaterial
				malformed = malformed || nestedMalformed
			}
		}
		f.unrecognized = malformed
		if material {
			f.add(model.CredentialProtectionPlaintext)
		}
		return true
	})
}

// gcpInlineMaterial reports whether one object fills a material field with a
// concrete value, and whether one of those fields held something that is not a
// string at all. The loader reads every one of them as a string, so another type
// there is a document this build cannot account for — while an unrecognised key
// elsewhere in the file is just a field this build does not need.
func gcpInlineMaterial(obj map[string]json.RawMessage) (material, malformed bool) {
	for _, field := range gcpInlineSecretFields {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			malformed = true
			continue
		}
		// A null decodes to the empty string, which is what a tool writes to mean
		// "no value here" — not material, and not a failure either.
		if concrete(value) {
			material = true
		}
	}
	return material, malformed
}

// decodeJSONObject parses a document as an object. A root that is not a mapping
// — a null, a list, a bare scalar — is rejected rather than read as an object
// with no fields in it, which would let a document this build cannot account for
// describe the file as holding nothing.
func decodeJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// decodeJSONDocument reads a document whose root must be an object into v, for
// the formats that decode straight into a shape of their own.
func decodeJSONDocument(data []byte, v any) bool {
	if _, ok := decodeJSONObject(data); !ok {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

// decodeYAMLDocument is the same guard for the formats written in YAML.
func decodeYAMLDocument(data []byte, v any) bool {
	var root map[string]yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || root == nil {
		return false
	}
	return yaml.Unmarshal(data, v) == nil
}

// dockerConfig is the subset of the container client's configuration that can
// hold a credential. The helper settings beside these are not decoded at all:
// they name a store this file does not contain. Registry names are read to
// iterate the entries and are not reported.
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
}

// parseDockerConfig counts the registry entries holding material. The inline
// field is base64 rather than encrypted — an encoding, not a protection — so an
// entry carrying it is plaintext, and its contents are never decoded.
func parseDockerConfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var cfg dockerConfig
		if !decodeJSONDocument(data, &cfg) {
			return false
		}
		for _, entry := range cfg.Auths {
			// One registry is one credential, whichever of the two fields holds it.
			if concrete(entry.Auth) || concrete(entry.IdentityToken) {
				f.add(model.CredentialProtectionPlaintext)
			}
		}
		return true
	})
}

// terraformCredentials is the credentials file's shape. Host keys are counted and
// never reported: a private infrastructure hostname is an internal detail of the
// customer's estate, not part of a credential inventory.
type terraformCredentials struct {
	Credentials map[string]struct {
		Token string `json:"token"`
	} `json:"credentials"`
}

// parseTerraformCredentials counts the host entries that carry a token. A valid
// document with no credentials block yields nothing: unrelated settings live here
// too, so the file's presence alone is not evidence a token was ever stored.
func parseTerraformCredentials(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc terraformCredentials
		if !decodeJSONDocument(data, &doc) {
			return false
		}
		for _, entry := range doc.Credentials {
			if concrete(entry.Token) {
				f.add(model.CredentialProtectionPlaintext)
			}
		}
		return true
	})
}

// ghHostEntry is the part of the GitHub CLI's configuration that can hold a
// token: the host itself in the older layout, and each account in the current
// one. Host and account names are read to iterate and are never reported.
type ghHostEntry struct {
	OAuthToken string `yaml:"oauth_token"`
	Users      map[string]struct {
		OAuthToken string `yaml:"oauth_token"`
	} `yaml:"users"`
}

// parseGitHubCLIHosts counts the hosts whose token is written into the file. The
// usual arrangement keeps it in an OS keystore instead, which this file cannot
// show and which is not material in any file this agent reads — so a configured
// host with no inline token is not a finding, and nothing here asks the CLI.
func parseGitHubCLIHosts(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var hosts map[string]ghHostEntry
		if !decodeYAMLDocument(data, &hosts) {
			return false
		}
		for _, entry := range hosts {
			// One host is one credential however many of its accounts carry a
			// token, since the tool authenticates to the host.
			if concrete(entry.OAuthToken) {
				f.add(model.CredentialProtectionPlaintext)
				continue
			}
			for _, account := range entry.Users {
				if concrete(account.OAuthToken) {
					f.add(model.CredentialProtectionPlaintext)
					break
				}
			}
		}
		return true
	})
}

// kubeconfigDoc is the subset of a cluster configuration that can hold material.
// The referencing fields beside these — a token path, a key path, a credential
// plugin, an identity provider, a client certificate — are not decoded: each
// names something fetched at run time, and none is a credential in this file.
// Entry names, cluster names and server URLs are not read.
type kubeconfigDoc struct {
	Users []struct {
		User struct {
			Token string `yaml:"token"`
			// The password is the credential in a basic-auth entry; the account
			// name it belongs to is not read, so there is no field for it here.
			Password      string `yaml:"password"`
			ClientKeyData string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// parseKubeconfig counts the user entries that carry material in the document
// itself. Embedded key data is decoded and structurally validated rather than
// counted on sight: this field is declared to hold a private key, so anything
// else in it is a document this build cannot account for.
func parseKubeconfig(data []byte) observation {
	return observed(data, func(data []byte, f *fold) bool {
		var doc kubeconfigDoc
		if !decodeYAMLDocument(data, &doc) {
			return false
		}
		for _, entry := range doc.Users {
			u := entry.User
			protection := ""
			if concrete(u.Token) || concrete(u.Password) {
				protection = model.CredentialProtectionPlaintext
			}
			if u.ClientKeyData != "" {
				// Read whatever else the entry carries: a token beside key data
				// that will not parse answers nothing about the key, and letting
				// it stand in would report the entry as fully understood.
				keyProtection, material, malformed := classifyEmbeddedKey(u.ClientKeyData)
				f.unrecognized = f.unrecognized || malformed
				if material && protectionRank[keyProtection] > protectionRank[protection] {
					protection = keyProtection
				}
			}
			// One user entry is one credential whichever of its fields holds it.
			if protection != "" {
				f.add(protection)
			}
		}
		return true
	})
}

// classifyEmbeddedKey reads the base64 a document embeds a private key in. The
// field is declared to hold one, so anything else in it — bytes that are not
// base64, a published half, a key that does not parse — is a document this build
// cannot account for rather than an entry holding nothing.
func classifyEmbeddedKey(field string) (protection string, material, malformed bool) {
	decoded, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return "", false, true
	}
	protection, material, malformed = classifySSHKey(decoded)
	return protection, material, malformed || !material
}
