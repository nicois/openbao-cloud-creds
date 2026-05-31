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

// httpTimeout bounds every UpCloud API call the minter client makes.
const httpTimeout = 30 * time.Second

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
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

func newUpCloudClient(baseURL, username, password string) *upcloudClient {
	return &upcloudClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *upcloudClient) CreateToken(ctx context.Context, name, expiresIn string) (*tokenResponse, int, error) {
	body, _ := json.Marshal(createTokenRequest{
		Name:            name,
		ExpiresIn:       expiresIn,
		CanCreateTokens: false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/1.3/account/tokens", bytes.NewReader(body))
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

	if resp.StatusCode != http.StatusCreated {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/1.3/account", http.NoBody)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/1.3/account/tokens", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("UpCloud API list tokens returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// UpCloud's GET /1.3/account/tokens returns a bare JSON array of tokens,
	// not an object with a "tokens" key, so decode directly into a slice.
	var result []tokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *upcloudClient) DeleteToken(ctx context.Context, tokenID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/1.3/account/tokens/"+tokenID, http.NoBody)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, fmt.Errorf("UpCloud API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
