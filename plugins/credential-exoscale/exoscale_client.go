package credentialexoscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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
			Timeout: 30 * time.Second,
		},
	}
}

func (c *exoscaleClient) CreateAPIKey(ctx context.Context, name string, roleID string) (*apiKeyResponse, int, error) {
	body, _ := json.Marshal(createAPIKeyRequest{
		Name:   name,
		RoleID: roleID,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v2/api-key", bytes.NewReader(body))
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

	if resp.StatusCode != 200 {
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
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v2/zone", nil)
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
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v2/api-key", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/v2/api-key/"+keyID, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return resp.StatusCode, fmt.Errorf("exoscale API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
