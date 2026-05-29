package credentialupcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type upcloudClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

type createTokenRequest struct {
	Name            string `json:"name"`
	ExpiresIn       string `json:"expires_in"`
	CanCreateTokens bool   `json:"can_create_tokens"`
}

type tokenResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type tokenInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listTokensResponse struct {
	Tokens []tokenInfo `json:"tokens"`
}

func newUpCloudClient(baseURL, username, password string) *upcloudClient {
	return &upcloudClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *upcloudClient) CreateToken(ctx context.Context, name string, expiresIn string) (*tokenResponse, int, error) {
	body, _ := json.Marshal(createTokenRequest{
		Name:            name,
		ExpiresIn:       expiresIn,
		CanCreateTokens: false,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/1.3/account/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("UpCloud API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *upcloudClient) CheckHealth(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/1.3/account", nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (c *upcloudClient) ListTokens(ctx context.Context) ([]tokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/1.3/account/tokens", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("UpCloud API list tokens returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result listTokensResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

func (c *upcloudClient) DeleteToken(ctx context.Context, tokenID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/1.3/account/tokens/"+tokenID, nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		return resp.StatusCode, fmt.Errorf("UpCloud API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
