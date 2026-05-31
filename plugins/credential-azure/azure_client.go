package credentialazure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// httpTimeout bounds every Azure Graph/login API call the minter client makes.
	httpTimeout = 30 * time.Second

	// tokenRefreshBuffer refreshes the cached Graph token this long before it
	// actually expires, so an in-flight request never races the expiry.
	tokenRefreshBuffer = 5 * time.Minute
)

type azureClient struct {
	tenantID      string
	clientID      string
	clientSecret  string
	graphEndpoint string
	loginEndpoint string
	httpClient    *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

type addPasswordRequest struct {
	PasswordCredential passwordCredentialInput `json:"passwordCredential"`
}

type passwordCredentialInput struct {
	DisplayName string `json:"displayName"`
	EndDateTime string `json:"endDateTime"`
}

type addPasswordResponse struct {
	KeyID       string `json:"keyId"`
	SecretText  string `json:"secretText"`
	DisplayName string `json:"displayName"`
	EndDateTime string `json:"endDateTime"`
}

type removePasswordRequest struct {
	KeyID string `json:"keyId"`
}

type passwordCredentialInfo struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	EndDateTime string `json:"endDateTime"`
}

type applicationResponse struct {
	ID                  string                   `json:"id"`
	AppID               string                   `json:"appId"`
	PasswordCredentials []passwordCredentialInfo `json:"passwordCredentials"`
}

func newAzureClient(tenantID, clientID, clientSecret, graphEndpoint, loginEndpoint string) *azureClient {
	return &azureClient{
		tenantID:      tenantID,
		clientID:      clientID,
		clientSecret:  clientSecret,
		graphEndpoint: graphEndpoint,
		loginEndpoint: loginEndpoint,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *azureClient) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 5-minute buffer)
	if c.cachedToken != "" && time.Now().Add(tokenRefreshBuffer).Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginEndpoint, c.tenantID)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	c.cachedToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return c.cachedToken, nil
}

func (c *azureClient) AddPassword(ctx context.Context, appObjectID, displayName string, endDateTime time.Time) (*addPasswordResponse, int, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get access token: %w", err)
	}

	reqBody := addPasswordRequest{
		PasswordCredential: passwordCredentialInput{
			DisplayName: displayName,
			EndDateTime: endDateTime.UTC().Format(time.RFC3339),
		},
	}
	body, _ := json.Marshal(reqBody)

	apiURL := fmt.Sprintf("%s/v1.0/applications/%s/addPassword", c.graphEndpoint, appObjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("azure Graph API addPassword returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result addPasswordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *azureClient) RemovePassword(ctx context.Context, appObjectID, keyID string) (int, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get access token: %w", err)
	}

	reqBody := removePasswordRequest{KeyID: keyID}
	body, _ := json.Marshal(reqBody)

	apiURL := fmt.Sprintf("%s/v1.0/applications/%s/removePassword", c.graphEndpoint, appObjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("azure Graph API removePassword returned %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return resp.StatusCode, nil
}

func (c *azureClient) GetApplication(ctx context.Context, appObjectID string) (*applicationResponse, int, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get access token: %w", err)
	}

	apiURL := fmt.Sprintf("%s/v1.0/applications/%s", c.graphEndpoint, appObjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("azure Graph API get application returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result applicationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *azureClient) CheckHealth(ctx context.Context, appObjectID string) (int, error) {
	_, status, err := c.GetApplication(ctx, appObjectID)
	if err != nil {
		return status, err
	}
	return status, nil
}
