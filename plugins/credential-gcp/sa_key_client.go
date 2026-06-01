package credentialgcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// SAKeyClient abstracts the service-account KEY-MANAGEMENT operations minter
// self-rotation needs (keys.create / keys.delete on the SAME service account
// the minter authenticates as). This is SEPARATE from IAMCredentialsClient (the
// impersonation issuance client): IAMCredentialsClient mints short-lived access
// tokens via generateAccessToken, whereas these calls manage the minter SA's
// own long-lived JSON keys (the make-before-break rotation).
type SAKeyClient interface {
	// CreateKey provisions a new JSON key for the service account the minter
	// authenticates as, returning the new key's full SA JSON and its resource
	// name (used later to delete it).
	CreateKey(ctx context.Context) (newKeyJSON string, keyName string, err error)
	// DeleteKey deletes a key (by resource name) of that same service account.
	DeleteKey(ctx context.Context, keyName string) error
}

// SAKeyClientFactory builds a SAKeyClient from a minter's service-account JSON,
// mirroring IAMClientFactory. Tests inject a fake; when nil the real REST client
// is used.
type SAKeyClientFactory func(credentialsJSON string) SAKeyClient

const (
	// iamServiceEndpoint is the GCP IAM API base used for key management.
	iamServiceEndpoint = "https://iam.googleapis.com/v1"
	// orgPolicyKeyCreationDisabled is the org-policy constraint that, when
	// enforced, blocks all SA key creation. GCP returns it disabled by default;
	// when set it surfaces as an HTTP 400 FAILED_PRECONDITION on keys.create.
	orgPolicyKeyCreationDisabled = "iam.disableServiceAccountKeyCreation"
)

// errKeyCreationDisabled is the sentinel RotateMinter returns when keys.create
// is blocked by the iam.disableServiceAccountKeyCreation org policy, so the
// orchestration can map it to a clear operator-facing message distinct from a
// generic/auth failure.
var errKeyCreationDisabled = errors.New("service-account key creation disabled by GCP org policy " + orgPolicyKeyCreationDisabled)

// rotationSuffix returns a short, monotonic-ish suffix for a successor minter ID
// so successive rotations of the same minter never collide.
func rotationSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// minterRotator wraps a SAKeyClient to perform RotateMinter. It mirrors the
// other plugins' client.RotateMinter shape while keeping the SA key-management
// surface (SAKeyClient) separate from the impersonation issuance client.
type minterRotator struct {
	client SAKeyClient
}

// RotateMinter mints a successor for old by creating a NEW JSON key on the SAME
// service account old authenticates as (so the successor inherits old's IAM
// rights and impersonation permissions). The successor's Token is the new key's
// SA JSON; its OWN key resource name is recorded in RotationParams[key_name] so
// a later retired-sweep can DeleteKey it precisely.
//
// SA keys do not expire, so the successor inherits old.NeverExpires (minters
// here are typically never_expires); no ExpiresAt is set unless old had one.
//
// If keys.create is blocked by the iam.disableServiceAccountKeyCreation org
// policy, CreateKey returns errKeyCreationDisabled, which propagates unwrapped so
// the orchestration can map it to a clear operator-facing message.
func (m *minterRotator) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	newKeyJSON, keyName, err := m.client.CreateKey(ctx)
	if err != nil {
		if errors.Is(err, errKeyCreationDisabled) {
			return cloudconfig.Minter{}, err
		}
		return cloudconfig.Minter{}, fmt.Errorf("create service-account key failed: %w", err)
	}

	successor := cloudconfig.Minter{
		ID:           old.ID + "-rot-" + rotationSuffix(),
		Token:        newKeyJSON,
		CreatedAt:    time.Now(),
		NeverExpires: old.NeverExpires,
		RotationParams: map[string]string{
			fieldKeyName: keyName,
		},
	}
	if !old.NeverExpires {
		successor.ExpiresAt = old.ExpiresAt
	}
	return successor, nil
}

// realSAKeyClient is the production SAKeyClient. It reuses the same self-signed
// JWT -> OAuth2 access-token exchange the issuance client uses (signServiceAccountJWT
// / exchangeJWTForToken) to authenticate raw IAM REST calls, so it adds NO new
// module dependency. Because GCP is an injected-client plugin (fakes are injected
// in tests) this REST path is exercised only against real IAM and so is flagged
// for real-cloud validation (audit2 #9 / audit #7).
type realSAKeyClient struct {
	credentialsJSON string
}

func newRealSAKeyClient(credentialsJSON string) SAKeyClient {
	return &realSAKeyClient{credentialsJSON: credentialsJSON}
}

// authToken parses the SA JSON and exchanges a self-signed JWT for an OAuth2
// access token (the same flow the issuance client uses).
func (c *realSAKeyClient) authToken(ctx context.Context) (token, saEmail string, err error) {
	var key serviceAccountKey
	if err := json.Unmarshal([]byte(c.credentialsJSON), &key); err != nil {
		return "", "", fmt.Errorf("failed to parse credentials JSON: %w", err)
	}
	if key.ClientEmail == "" {
		return "", "", fmt.Errorf("credentials JSON missing client_email")
	}
	jwt, tokenURI, err := signServiceAccountJWT(&key)
	if err != nil {
		return "", "", err
	}
	tok, err := exchangeJWTForToken(ctx, tokenURI, jwt)
	if err != nil {
		return "", "", err
	}
	return tok, key.ClientEmail, nil
}

// createKeyResponse maps the keys.create REST response. privateKeyData is the
// base64-encoded full service-account JSON of the new key.
type createKeyResponse struct {
	Name           string `json:"name"`
	PrivateKeyData string `json:"privateKeyData"`
}

func (c *realSAKeyClient) CreateKey(ctx context.Context) (newKeyJSON, keyName string, err error) {
	authTok, saEmail, err := c.authToken(ctx)
	if err != nil {
		return "", "", err
	}

	apiURL := fmt.Sprintf("%s/projects/-/serviceAccounts/%s/keys", iamServiceEndpoint, saEmail)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", "", fmt.Errorf("failed to create keys.create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authTok)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("keys.create request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read keys.create response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if isOrgPolicyKeyCreationDisabled(resp.StatusCode, body) {
			return "", "", errKeyCreationDisabled
		}
		return "", "", fmt.Errorf("keys.create failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var out createKeyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("failed to parse keys.create response: %w", err)
	}
	if out.Name == "" || out.PrivateKeyData == "" {
		return "", "", fmt.Errorf("keys.create returned an incomplete key")
	}
	decoded, err := base64.StdEncoding.DecodeString(out.PrivateKeyData)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode privateKeyData: %w", err)
	}
	return string(decoded), out.Name, nil
}

func (c *realSAKeyClient) DeleteKey(ctx context.Context, keyName string) error {
	authTok, _, err := c.authToken(ctx)
	if err != nil {
		return err
	}
	apiURL := iamServiceEndpoint + "/" + keyName
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create keys.delete request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+authTok)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keys.delete request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return errSAKeyNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keys.delete failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// errSAKeyNotFound is returned by DeleteKey when the key is already gone (404).
// The retired-sweep treats it as success (idempotent).
var errSAKeyNotFound = errors.New("service-account key not found")

// isSAKeyNotFound reports whether err means the key was already gone.
func isSAKeyNotFound(err error) bool {
	return errors.Is(err, errSAKeyNotFound)
}

// isOrgPolicyKeyCreationDisabled reports whether a keys.create failure is the
// iam.disableServiceAccountKeyCreation org-policy block: an HTTP 400 whose body
// names the constraint or carries a FAILED_PRECONDITION / "key creation is not
// allowed" signal. Matching on the message/reason (not just the status) keeps it
// distinct from other 400s.
func isOrgPolicyKeyCreationDisabled(status int, body []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	s := strings.ToLower(string(body))
	if strings.Contains(s, strings.ToLower(orgPolicyKeyCreationDisabled)) {
		return true
	}
	return strings.Contains(s, "failed_precondition") &&
		strings.Contains(s, "key creation is not allowed")
}
