package credentialexoscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
