package credentialovh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultTokenLifetimeSeconds is the OVH OAuth2 access-token lifetime (1h) used
// when the token endpoint omits expires_in (and as the fake client's value).
const defaultTokenLifetimeSeconds = 3600

// TokenClient abstracts the OVH OAuth2 token endpoint operations used by this plugin.
type TokenClient interface {
	// MintToken requests a new access token using client_credentials grant.
	MintToken(ctx context.Context) (token string, expiresIn int, err error)
	// TestConnection validates the minter credentials by attempting to mint a token.
	TestConnection(ctx context.Context) error
}

// newRealTokenClient creates a real OVH OAuth2 token client.
func newRealTokenClient(clientID, clientSecret, tokenEndpoint string) TokenClient {
	return &realTokenClient{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenEndpoint: tokenEndpoint,
	}
}

type realTokenClient struct {
	clientID      string
	clientSecret  string
	tokenEndpoint string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

func (c *realTokenClient) MintToken(ctx context.Context) (token string, expiresIn int, err error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"all"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp tokenResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != "" {
			return "", 0, fmt.Errorf("OVH OAuth2 error (HTTP %d): %s: %s", resp.StatusCode, errResp.Error, errResp.ErrorDesc)
		}
		return "", 0, fmt.Errorf("OVH token endpoint error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("OVH token response missing access_token")
	}

	ttl := tokenResp.ExpiresIn
	if ttl <= 0 {
		ttl = defaultTokenLifetimeSeconds
	}

	return tokenResp.AccessToken, ttl, nil
}

func (c *realTokenClient) TestConnection(ctx context.Context) error {
	_, _, err := c.MintToken(ctx)
	return err
}

// fakeTokenClient is used in tests.
type fakeTokenClient struct {
	mintTokenFunc      func(ctx context.Context) (string, int, error)
	testConnectionFunc func(ctx context.Context) error
}

func (f *fakeTokenClient) MintToken(ctx context.Context) (token string, expiresIn int, err error) {
	if f.mintTokenFunc != nil {
		return f.mintTokenFunc(ctx)
	}
	// Default fake: return a predictable token
	return "ovh-fake-token-" + fmt.Sprintf("%d", time.Now().UnixNano()), defaultTokenLifetimeSeconds, nil
}

func (f *fakeTokenClient) TestConnection(ctx context.Context) error {
	if f.testConnectionFunc != nil {
		return f.testConnectionFunc(ctx)
	}
	return nil
}
