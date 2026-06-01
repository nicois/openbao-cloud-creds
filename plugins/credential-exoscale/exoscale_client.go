package credentialexoscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

type exoscaleClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type createAPIKeyRequest struct {
	Name   string `json:"name"`
	RoleID string `json:"role-id"`
}

type apiKeyResponse struct {
	Key    string `json:"key"`
	KeyID  string `json:"key-id"`
	Name   string `json:"name"`
	RoleID string `json:"role-id"`
}

type apiKeyInfo struct {
	KeyID  string `json:"key-id"`
	Name   string `json:"name"`
	RoleID string `json:"role-id"`
}

type listAPIKeysResponse struct {
	APIKeys []apiKeyInfo `json:"api-keys"`
}

func newExoscaleClient(baseURL, apiKey string) *exoscaleClient {
	return &exoscaleClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *exoscaleClient) CreateAPIKey(ctx context.Context, name, roleID string) (*apiKeyResponse, int, error) {
	body, _ := json.Marshal(createAPIKeyRequest{
		Name:   name,
		RoleID: roleID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v2/api-key", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("exoscale API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result apiKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *exoscaleClient) CheckHealth(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v2/zone", http.NoBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (c *exoscaleClient) ListAPIKeys(ctx context.Context) ([]apiKeyInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v2/api-key", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("exoscale API list keys returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result listAPIKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.APIKeys, nil
}

func (c *exoscaleClient) DeleteAPIKey(ctx context.Context, keyID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v2/api-key/"+keyID, http.NoBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("exoscale API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// rotationSuffix returns a short, monotonic-ish suffix for a successor minter
// ID so successive rotations of the same minter never collide.
func rotationSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// RotateMinter mints a successor Exoscale IAM API key bound to the SAME
// key-management IAM role as old (from old.RotationParams[role_id]), so the
// successor inherits old's key-creation rights and can itself mint and rotate.
// The successor records its OWN upstream key-id in RotationParams[key_id] so a
// later retired-sweep can DeleteAPIKey it, and carries role_id forward. It
// inherits old.NeverExpires; if the original expires, the successor is given a
// defaultMinterSecretLifetime-bounded local expiry. The minter's Token is the
// key secret (single Bearer value), matching newClientForMinter / path_creds.
func (c *exoscaleClient) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	roleID := old.RotationParams[fieldRoleID]
	if roleID == "" {
		return cloudconfig.Minter{}, fmt.Errorf("minter %s missing rotation_params.%s", old.ID, fieldRoleID)
	}

	name := successorKeyNamePrefix + old.ID
	keyResp, status, err := c.CreateAPIKey(ctx, name, roleID)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("create successor api-key failed (status %d): %w", status, err)
	}

	successor := cloudconfig.Minter{
		ID:           old.ID + "-rot-" + rotationSuffix(),
		Token:        keyResp.Key,
		CreatedAt:    time.Now(),
		NeverExpires: old.NeverExpires,
		RotationParams: map[string]string{
			fieldRoleID: roleID,
			fieldKeyID:  keyResp.KeyID,
		},
	}
	if !old.NeverExpires {
		successor.ExpiresAt = time.Now().Add(defaultMinterSecretLifetime)
	}
	return successor, nil
}
