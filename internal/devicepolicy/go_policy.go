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

const goAuthScheme = pypiAuthScheme

// GoPolicy is the compiled package_config/go policy delivered to this device.
type GoPolicy struct {
	Ecosystem   string `json:"ecosystem"`
	RegistryURL string `json:"registry_url"`
	Auth        struct {
		Scheme string `json:"scheme"`
		APIKey string `json:"api_key"`
	} `json:"auth"`

	deviceID string
}

// GoObserved is the strict, secret-free package_config/go report body.
type GoObserved struct {
	Ecosystem       string `json:"ecosystem"`
	RegistryURL     string `json:"registry_url"`
	AuthTokenStatus string `json:"auth_token_status"`
	ConfigStatus    string `json:"config_status"`
	EffectiveStatus string `json:"effective_status"`
	OverrideSource  string `json:"override_source"`
}

// ParseGoPolicy strictly validates one compiled package_config/go policy.
func ParseGoPolicy(raw json.RawMessage, deviceID string) (GoPolicy, error) {
	var policy GoPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return GoPolicy{}, errors.New("go: policy is not a well-formed policy object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return GoPolicy{}, errors.New("go: policy has trailing data")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return GoPolicy{}, errors.New("go: policy contains duplicate JSON keys")
	}
	if policy.Ecosystem != "go" {
		return GoPolicy{}, errors.New("go: policy ecosystem is not go")
	}
	if policy.Auth.Scheme != goAuthScheme {
		return GoPolicy{}, errors.New("go: unsupported auth scheme")
	}
	if err := validateGoCredentialPart("api_key", policy.Auth.APIKey, npmrcMaxKeyBytes); err != nil {
		return GoPolicy{}, err
	}
	if strings.Contains(policy.Auth.APIKey, "::") {
		return GoPolicy{}, errors.New("go: policy api_key already contains a source suffix")
	}
	if err := validateGoCredentialPart("device_id", deviceID, npmrcMaxSerialBytes); err != nil {
		return GoPolicy{}, err
	}
	if strings.ContainsAny(policy.RegistryURL, ",|") {
		return GoPolicy{}, errors.New("go: policy registry_url must not contain fallback delimiters")
	}
	u, err := parsePyPIRegistryURL(policy.RegistryURL)
	if err != nil {
		return GoPolicy{}, fmt.Errorf("go: policy %w", err)
	}
	switch u.EscapedPath() {
	case "/go":
	case "/go/":
		policy.RegistryURL = strings.TrimSuffix(policy.RegistryURL, "/")
	default:
		return GoPolicy{}, errors.New("go: policy registry_url path must be /go")
	}
	policy.deviceID = deviceID
	return policy, nil
}

func validateGoCredentialPart(name, value string, maxBytes int) error {
	if value == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("go: policy %s is empty", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("go: policy %s too long", name)
	}
	if !isNPMSafe(value) {
		return fmt.Errorf("go: policy %s contains unsupported characters", name)
	}
	return nil
}

func (p GoPolicy) RegistryHost() string {
	u, err := url.Parse(p.RegistryURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (p GoPolicy) DeviceToken() string { return p.Auth.APIKey + "::dev:" + p.deviceID }
