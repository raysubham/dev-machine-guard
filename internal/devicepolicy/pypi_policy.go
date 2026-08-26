package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const pypiAuthScheme = "stepsecurity_device_token"

type PyPIClient string

const (
	PyPIClientPip PyPIClient = "pip"
	PyPIClientUV  PyPIClient = "uv"
)

type PyPIPolicy struct {
	Ecosystem   string       `json:"ecosystem"`
	Clients     []PyPIClient `json:"clients"`
	RegistryURL string       `json:"registry_url"`
	Auth        struct {
		Scheme string `json:"scheme"`
		APIKey string `json:"api_key"`
	} `json:"auth"`

	deviceID string
}

type PyPIClientObservation struct {
	RegistryURL     string `json:"registry_url"`
	ConfigStatus    string `json:"config_status"`
	EffectiveStatus string `json:"effective_status"`
	OverrideSource  string `json:"override_source"`
}

type PyPIObserved struct {
	Ecosystem       string                           `json:"ecosystem"`
	AuthTokenStatus string                           `json:"auth_token_status"`
	Clients         map[string]PyPIClientObservation `json:"clients"`
}

// ParsePyPIPolicy strictly validates one compiled package_config/pypi policy.
func ParsePyPIPolicy(raw json.RawMessage, deviceID string) (PyPIPolicy, error) {
	var policy PyPIPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return PyPIPolicy{}, errors.New("pypi: policy is not a well-formed policy object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PyPIPolicy{}, errors.New("pypi: policy has trailing data")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return PyPIPolicy{}, errors.New("pypi: policy contains duplicate JSON keys")
	}

	if policy.Ecosystem != "pypi" {
		return PyPIPolicy{}, errors.New("pypi: policy ecosystem is not pypi")
	}
	if !canonicalPyPIClients(policy.Clients) {
		return PyPIPolicy{}, errors.New("pypi: policy clients are not canonical")
	}
	if policy.Auth.Scheme != pypiAuthScheme {
		return PyPIPolicy{}, errors.New("pypi: unsupported auth scheme")
	}
	if err := validatePyPICredentialPart("api_key", policy.Auth.APIKey, npmrcMaxKeyBytes); err != nil {
		return PyPIPolicy{}, err
	}
	if strings.Contains(policy.Auth.APIKey, "::") {
		return PyPIPolicy{}, errors.New("pypi: policy api_key already contains a source suffix")
	}
	if err := validatePyPICredentialPart("device_id", deviceID, npmrcMaxSerialBytes); err != nil {
		return PyPIPolicy{}, err
	}

	u, err := parsePolicyRegistryURL(policy.RegistryURL)
	if err != nil {
		return PyPIPolicy{}, fmt.Errorf("pypi: policy %w", err)
	}
	switch u.EscapedPath() {
	case "/python/simple":
	case "/python/simple/":
		policy.RegistryURL = strings.TrimSuffix(policy.RegistryURL, "/")
	default:
		return PyPIPolicy{}, errors.New("pypi: policy registry_url path must be /python/simple")
	}

	policy.deviceID = deviceID
	return policy, nil
}

func canonicalPyPIClients(clients []PyPIClient) bool {
	switch len(clients) {
	case 1:
		return clients[0] == PyPIClientPip || clients[0] == PyPIClientUV
	case 2:
		return clients[0] == PyPIClientPip && clients[1] == PyPIClientUV
	default:
		return false
	}
}

func validatePyPICredentialPart(name, value string, maxBytes int) error {
	if value == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("pypi: policy %s is empty", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("pypi: policy %s too long", name)
	}
	if !isNPMSafe(value) {
		return fmt.Errorf("pypi: policy %s contains unsupported characters", name)
	}
	return nil
}

func (p PyPIPolicy) RegistryHost() string {
	u, err := url.Parse(p.RegistryURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (p PyPIPolicy) DeviceToken() string { return p.Auth.APIKey + "::dev:" + p.deviceID }

func (p PyPIPolicy) Selects(client PyPIClient) bool {
	for _, selected := range p.Clients {
		if selected == client {
			return true
		}
	}
	return false
}

// safeObservedRegistryURL returns only credential-free absolute HTTP(S) URLs.
func safeObservedRegistryURL(raw string) string {
	if err := transmittableRegistryURL(raw); err != nil {
		return ""
	}
	return raw
}

const maxLocalPolicyBytes = 1 << 20

type filePolicyEnvelope struct {
	Category    string          `json:"category"`
	Target      string          `json:"target"`
	Clear       bool            `json:"clear"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	Hash        string          `json:"hash,omitempty"`
	GeneratedAt string          `json:"generated_at,omitempty"`
	Enforcement string          `json:"enforcement,omitempty"`
}

// FileFetcher serves one validated offline PyPI policy without network access.
type FileFetcher struct {
	policy EffectivePolicy
}

// NewFileFetcher reads and validates one strict package_config/pypi envelope.
func NewFileFetcher(path string) (*FileFetcher, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: stat local policy: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("devicepolicy: local policy is not a regular file")
	}
	if pathInfo.Size() > maxLocalPolicyBytes {
		return nil, errors.New("devicepolicy: local policy exceeds size limit")
	}

	// #nosec G304 -- path is the operator-selected offline policy file, validated above as a bounded regular file.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: open local policy: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: stat open local policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("devicepolicy: open local policy is not a regular file")
	}
	if info.Size() > maxLocalPolicyBytes {
		return nil, errors.New("devicepolicy: local policy exceeds size limit")
	}

	body, err := io.ReadAll(io.LimitReader(file, maxLocalPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: read local policy: %w", err)
	}
	if len(body) > maxLocalPolicyBytes {
		return nil, errors.New("devicepolicy: local policy exceeds size limit")
	}

	var env filePolicyEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&env); err != nil {
		return nil, fmt.Errorf("devicepolicy: decode local policy: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("devicepolicy: local policy has trailing JSON")
		}
		return nil, fmt.Errorf("devicepolicy: decode trailing local policy data: %w", err)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}

	policy := EffectivePolicy{
		Category:    strings.TrimSpace(env.Category),
		Target:      strings.TrimSpace(env.Target),
		Clear:       env.Clear,
		Policy:      env.Policy,
		Hash:        strings.TrimSpace(env.Hash),
		GeneratedAt: env.GeneratedAt,
		Enforcement: strings.TrimSpace(env.Enforcement),
	}
	if policy.Category != CategoryPackageConfig || policy.Target != TargetPyPI {
		return nil, errors.New("devicepolicy: local policy must identify package_config/pypi")
	}
	if policy.Clear {
		if len(policy.Policy) != 0 {
			return nil, errors.New("devicepolicy: clear local policy must not include policy bytes")
		}
	} else {
		if len(policy.Policy) == 0 || policy.Hash == "" {
			return nil, errors.New("devicepolicy: local policy missing policy object or hash")
		}
		if !isJSONObject(policy.Policy) {
			return nil, errors.New("devicepolicy: local policy is not a JSON object")
		}
	}

	return &FileFetcher{policy: policy}, nil
}

// Fetch returns the offline policy only for its fixed public identity.
func (f *FileFetcher) Fetch(_ context.Context, _, _, category, target string) (EffectivePolicy, error) {
	if f == nil {
		return EffectivePolicy{}, errors.New("devicepolicy: nil file fetcher")
	}
	if category != f.policy.Category || target != f.policy.Target {
		return EffectivePolicy{}, errors.New("devicepolicy: file policy identity does not match request")
	}
	return f.policy, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var scanValue func() error
	scanValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}

		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := scanValue(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := scanValue(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected closing delimiter")
		}
		_, err = decoder.Token()
		return err
	}

	if err := scanValue(); err != nil {
		return fmt.Errorf("devicepolicy: invalid local policy JSON: %w", err)
	}
	return nil
}
