package credentialakamai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type akamaiClient struct {
	baseURL    string
	credential *edgeGridCredential
	httpClient *http.Client
}

type createClientRequest struct {
	ClientName      string      `json:"clientName"`
	AuthorizedUsers []string    `json:"authorizedUsers"`
	APIAccess       interface{} `json:"apiAccess,omitempty"`
	GroupAccess     interface{} `json:"groupAccess,omitempty"`
}

type credentialEntry struct {
	CredentialID int    `json:"credentialId"`
	ClientToken  string `json:"clientToken"`
	ClientSecret string `json:"clientSecret"`
	AccessToken  string `json:"accessToken"`
	ExpiresOn    string `json:"expiresOn"`
}

type createClientResponse struct {
	ClientID    string            `json:"clientId"`
	ClientName  string            `json:"clientName"`
	Credentials []credentialEntry `json:"credentials"`
}

type clientInfo struct {
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`
}

func newAkamaiClient(baseURL string, cred *edgeGridCredential) *akamaiClient {
	return &akamaiClient{
		baseURL:    baseURL,
		credential: cred,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *akamaiClient) CreateClient(ctx context.Context, name string, apiAccess, groupAccess interface{}) (*createClientResponse, int, error) {
	body, _ := json.Marshal(createClientRequest{
		ClientName:      name,
		AuthorizedUsers: []string{},
		APIAccess:       apiAccess,
		GroupAccess:     groupAccess,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/identity-management/v3/api-clients?createCredential=true", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("akamai API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result createClientResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *akamaiClient) CheckHealth(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/identity-management/v3/api-clients/self", http.NoBody)
	if err != nil {
		return 0, err
	}

	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (c *akamaiClient) ListClients(ctx context.Context) ([]clientInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/identity-management/v3/api-clients", http.NoBody)
	if err != nil {
		return nil, err
	}

	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("akamai API list clients returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result []clientInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *akamaiClient) DeleteClient(ctx context.Context, clientID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/identity-management/v3/api-clients/"+clientID, http.NoBody)
	if err != nil {
		return 0, err
	}

	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, fmt.Errorf("akamai API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
