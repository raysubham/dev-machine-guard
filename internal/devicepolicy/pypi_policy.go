package devicepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
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
