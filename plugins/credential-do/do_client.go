package credentialdo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpTimeout bounds every DO API call the minter client makes.
const httpTimeout = 30 * time.Second

type doClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type createTokenRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type tokenResponse struct {
	Token struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		AccessToken string `json:"access_token"`
	} `json:"token"`
}

type tokenInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type listTokensResponse struct {
	Tokens []tokenInfo `json:"tokens"`
}

func newDOClient(baseURL, token string) *doClient {
	return &doClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *doClient) CreateToken(ctx context.Context, name string, scopes []string) (*tokenResponse, int, error) {
	body, _ := json.Marshal(createTokenRequest{Name: name, Scopes: scopes})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v2/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("DO API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *doClient) CheckHealth(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v2/account", http.NoBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (c *doClient) ListTokens(ctx context.Context) ([]tokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v2/tokens", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DO API list tokens returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result listTokensResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

func (c *doClient) DeleteToken(ctx context.Context, tokenID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v2/tokens/"+tokenID, http.NoBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, fmt.Errorf("DO API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
