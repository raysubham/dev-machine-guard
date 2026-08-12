package credentials

import (
	"encoding/base64"
	"testing"
)

// TestParseGCPADC covers the shapes this file takes. One file is one credential
// however many of its fields are filled in, so a nested inline credential is read
// for what it settles rather than added to a count — and a material field holding
// something that is not a string is a document this build cannot account for.
func TestParseGCPADC(t *testing.T) {
	runParseCases(t, parseGCPADC, []parseCase{
		{name: "interactive login holds material", body: `{"type":"authorized_user","client_id":"id.apps.googleusercontent.com","client_secret":"value","refresh_token":"value"}`, want: obsPlain(1)},
		{name: "service account key holds material", body: `{"type":"service_account","client_email":"svc@example.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----\n"}`, want: obsPlain(1)},
		// Impersonation carries the credential it goes through inside itself, so
		// the material can sit one level below the fields that describe it.
		{name: "impersonation counts the nested credential once", body: `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x","source_credentials":{"type":"authorized_user","client_secret":"value","refresh_token":"value"}}`, want: obsPlain(1)},
		{name: "material beside an external source is still one credential", body: `{"type":"external_account","credential_source":{"file":"/var/run/secrets/token"},"client_secret":"value"}`, want: obsPlain(1)},
		// An external account fetches its credential at run time, so nothing here
		// is material however completely the file is filled in.
		{name: "external account alone is not material", body: `{"type":"external_account","audience":"//iam.googleapis.com/x","credential_source":{"file":"/var/run/secrets/token"}}`, want: obsNone},
		{name: "impersonation with no inline source is not material", body: `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x"}`, want: obsNone},
		// The nested credential is read whether or not the outer object held one:
		// a nested shape this build cannot account for is uncertainty the outer
		// credential does not resolve, since the file could be carrying a second
		// credential nothing here can see.
		{name: "material beside a nested source of the wrong shape", body: `{"client_secret":"value","source_credentials":["a"]}`, want: alsoUnrec(obsPlain(1))},
		{name: "material beside a nested field of the wrong type", body: `{"client_secret":"value","source_credentials":{"refresh_token":42}}`, want: alsoUnrec(obsPlain(1))},
		{name: "a nested source that is not an object", body: `{"source_credentials":"a-name"}`, want: obsUnrec},
		{name: "a null nested source is not a failure", body: `{"source_credentials":null}`, want: obsNone},
		// A shape this build does not know is not a failure: the fields it reads
		// are simply absent, and an unrelated key proves nothing either way.
		{name: "an unfamiliar shape holds no material", body: `{"type":"some_future_credential_family","account":"a-name"}`, want: obsNone},
		{name: "null and empty fields are not material", body: `{"type":"authorized_user","client_secret":null,"refresh_token":""}`, want: obsNone},
		{name: "environment reference is not material", body: `{"type":"authorized_user","refresh_token":"${GOOGLE_REFRESH_TOKEN}"}`, want: obsNone},
		// The loader reads every one of these fields as a string, so another type
		// in one is a document this build cannot read.
		{name: "a material field of the wrong type", body: `{"refresh_token":{"nested":true}}`, want: obsUnrec},
		{name: "material beside a field of the wrong type", body: `{"client_secret":"value","refresh_token":["a"]}`, want: alsoUnrec(obsPlain(1))},
		{name: "malformed document", body: `{"type":"authorized_user",`, want: obsUnrec},
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseDockerConfig(t *testing.T) {
	runParseCases(t, parseDockerConfig, []parseCase{
		// The inline field is an encoding, not a protection, so an entry that
		// carries it is material in the clear.
		{name: "inline registry auth is plaintext", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}`, want: obsPlain(1)},
		{name: "identity token is material", body: `{"auths":{"registry.example.com":{"identitytoken":"value"}}}`, want: obsPlain(1)},
		{name: "one registry with both fields counts once", body: `{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz","identitytoken":"value"}}}`, want: obsPlain(1)},
		{name: "registries count separately", body: `{"auths":{"a.example.com":{"auth":"b25l"},"b.example.com":{"auth":"dHdv"}}}`, want: obsPlain(2)},
		// A helper holds the secret somewhere this file does not reach, so none of
		// these is a credential in it.
		{name: "entry with no inline material", body: `{"auths":{"registry.example.com":{}},"credsStore":"desktop"}`, want: obsNone},
		{name: "default helper alone", body: `{"credsStore":"desktop"}`, want: obsNone},
		{name: "per-registry helper alone", body: `{"credHelpers":{"registry.example.com":"ecr-login"}}`, want: obsNone},
		{name: "empty auth entry", body: `{"auths":{"registry.example.com":{"auth":""}}}`, want: obsNone},
		{name: "configuration with no credential statement", body: `{"currentContext":"desktop-linux"}`, want: obsNone},
		{name: "malformed document", body: `{"auths":`, want: obsUnrec},
		// A document with no mapping at its root is not this file's shape, and
		// reading it as an object with no fields would call the file clean.
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

func TestParseTerraformCredentials(t *testing.T) {
	runParseCases(t, parseTerraformCredentials, []parseCase{
		{name: "host token", body: `{"credentials":{"app.terraform.io":{"token":"value"}}}`, want: obsPlain(1)},
		{name: "hosts count separately", body: `{"credentials":{"app.terraform.io":{"token":"one"},"tfe.example.com":{"token":"two"}}}`, want: obsPlain(2)},
		{name: "empty token is not material", body: `{"credentials":{"app.terraform.io":{"token":""}}}`, want: obsNone},
		{name: "environment reference is not material", body: `{"credentials":{"app.terraform.io":{"token":"${TF_TOKEN}"}}}`, want: obsNone},
		// Unrelated settings live here too, so the file's presence alone is not
		// evidence that a token was ever stored.
		{name: "valid document with no credentials block", body: `{"unrelated":true}`, want: obsNone},
		{name: "malformed document", body: `{"credentials":`, want: obsUnrec},
		{name: "a root that is not an object", body: "null", want: obsUnrec},
		{name: "blank file", body: "\n", want: obsNone},
	})
}

// TestParseGitHubCLIHosts counts only tokens written into the file. The usual
// arrangement keeps the token in an OS keystore, which is not material in any
// file this agent reads — and nothing here asks the CLI what it holds.
func TestParseGitHubCLIHosts(t *testing.T) {
	runParseCases(t, parseGitHubCLIHosts, []parseCase{
		{name: "inline token on the host", body: "example.invalid:\n    oauth_token: value\n    user: a-user\n", want: obsPlain(1)},
		{name: "inline token on an account", body: "example.invalid:\n    users:\n        a-user:\n            oauth_token: value\n", want: obsPlain(1)},
		// One host is one credential however many of its accounts carry a token.
		{name: "several accounts on one host count once", body: "example.invalid:\n    users:\n        a-user:\n            oauth_token: one\n        b-user:\n            oauth_token: two\n", want: obsPlain(1)},
		{name: "hosts count separately", body: "a.invalid:\n    oauth_token: one\nb.invalid:\n    oauth_token: two\n", want: obsPlain(2)},
		{name: "keyring-backed host holds no material", body: "example.invalid:\n    user: a-user\n    git_protocol: ssh\n", want: obsNone},
		{name: "accounts without tokens hold no material", body: "example.invalid:\n    users:\n        a-user:\n            git_protocol: ssh\n", want: obsNone},
		{name: "empty token is not material", body: "example.invalid:\n    oauth_token: \"\"\n", want: obsNone},
		{name: "valid document with no hosts", body: "{}\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "malformed document", body: "example.invalid:\n  - this is a list where a map belongs\n", want: obsUnrec},
		{name: "a root that is not a mapping", body: "null\n", want: obsUnrec},
	})
}

func TestParseKubeconfig(t *testing.T) {
	runParseCases(t, parseKubeconfig, []parseCase{
		{name: "embedded token", body: "users:\n  - name: dev\n    user:\n      token: value\n", want: obsPlain(1)},
		{name: "basic password", body: "users:\n  - name: dev\n    user:\n      username: a-user\n      password: value\n", want: obsPlain(1)},
		{name: "embedded key material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testECPrivateKeyPEM()) + "\n", want: obsPlain(1)},
		// The embedded key is the one place this format can hold material that is
		// present without being usable, so the protection travels from the key.
		{name: "embedded encrypted key material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testEncryptedPKCS8PEM()) + "\n", want: obsProt(1)},
		{name: "entries count separately", body: "users:\n  - name: a\n    user:\n      token: one\n  - name: b\n    user:\n      token: two\n", want: obsPlain(2)},
		// Each of these names material fetched at run time, so none is a
		// credential in this document.
		{name: "token file is not material", body: "users:\n  - name: dev\n    user:\n      tokenFile: /var/run/secrets/token\n", want: obsNone},
		{name: "key path is not material", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/a-user/.kube/client.crt\n      client-key: /home/a-user/.kube/client.key\n", want: obsNone},
		{name: "credential plugin is not material", body: "users:\n  - name: dev\n    user:\n      exec:\n        command: aws\n        args: [eks, get-token]\n", want: obsNone},
		{name: "identity provider is not material", body: "users:\n  - name: dev\n    user:\n      auth-provider:\n        name: oidc\n", want: obsNone},
		// The public half authenticates nothing without its key.
		{name: "certificate alone is not material", body: "users:\n  - name: dev\n    user:\n      client-certificate: /home/a-user/.kube/client.crt\n", want: obsNone},
		{name: "environment reference is not material", body: "users:\n  - name: dev\n    user:\n      token: ${KUBE_TOKEN}\n", want: obsNone},
		{name: "clusters with no user entries", body: "clusters:\n  - name: dev\n    cluster:\n      server: https://cluster.example.com\n", want: obsNone},
		{name: "blank file", body: "\n", want: obsNone},
		{name: "malformed document", body: "users: [ unterminated\n", want: obsUnrec},
		{name: "a root that is not a mapping", body: "null\n", want: obsUnrec},
		// This field is declared to hold a private key, so anything else in it is
		// a document this build cannot account for — even bytes that would be
		// ignored harmlessly as a file in the key directory.
		{name: "embedded key data that is not base64", body: "users:\n  - name: dev\n    user:\n      client-key-data: not-base64!!\n", want: obsUnrec},
		{name: "embedded key data that is not a key", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64.StdEncoding.EncodeToString([]byte("not a key at all")) + "\n", want: obsUnrec},
		{name: "embedded public key is not material", body: "users:\n  - name: dev\n    user:\n      client-key-data: " + base64PEM(testCertificatePEM()) + "\n", want: obsUnrec},
		// Mixed users: the inline credential counts and the unreadable sibling
		// still costs the source its completeness.
		{name: "inline material beside unreadable key data", body: "users:\n  - name: a\n    user:\n      token: value\n  - name: b\n    user:\n      client-key-data: not-base64!!\n", want: alsoUnrec(obsPlain(1))},
		// Every field of an entry is read: a token beside key data that will not
		// parse answers nothing about the key, and letting it stand in would
		// report the entry as fully understood.
		{name: "one entry holding both a token and unreadable key data", body: "users:\n  - name: dev\n    user:\n      token: value\n      client-key-data: not-base64!!\n", want: alsoUnrec(obsPlain(1))},
		// The worst protection in an entry describes it, the same way the fold
		// over a whole source does.
		{name: "a token beside an encrypted key counts once as plaintext", body: "users:\n  - name: dev\n    user:\n      token: value\n      client-key-data: " + base64PEM(testEncryptedPKCS8PEM()) + "\n", want: obsPlain(1)},
	})
}

// base64PEM encodes a PEM document the way a kubeconfig embeds one.
func base64PEM(pem []byte) string {
	return base64.StdEncoding.EncodeToString(pem)
}
