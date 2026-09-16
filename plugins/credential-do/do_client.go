package credentialdo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// httpTimeout bounds every DO API call the minter client makes.
const httpTimeout = 30 * time.Second

// The /v2/tokens endpoints used below (create/list/delete personal access
// tokens) are NOT part of DigitalOcean's public API: they are absent from the
// public OpenAPI spec, and DO documents PAT creation as a control-panel flow
// only. They are what the control panel itself calls, and they are the only way
// to mint headlessly — the documented OAuth flow needs interactive user
// authorization — so this is a deliberate, documented dependency with no
// stability contract. See docs/do-api-verification-2026-08-21.md (D1, D5); the
// exact request shape (notably whether an expiry field is accepted or required,
// which would give DO a native TTL) is unverified against real DO.

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

// httpTransport is the transport every DO client uses. Package-level so a test can replace it,
// matching jitterFraction's reason for being a var rather than a constant.
//
// It exists for testing/synctest. This type's lifecycle is measured in DAYS, and a bubble's clock
// only advances when every goroutine in it is durably blocked — which a pooled idle connection
// prevents, because its readLoop sits blocked on a real socket and a goroutine blocked on I/O is
// never durably blocked. A test that wants ninety days to pass in a millisecond substitutes a
// transport with keep-alives disabled, so those goroutines exit and the bubble can idle.
//
// The default stays pooled: these drivers make infrequent calls to one host, so a fresh handshake
// per call would be latency on a credential read for no gain.
var httpTransport http.RoundTripper = http.DefaultTransport

func newDOClient(baseURL, token string) *doClient {
	return &doClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout:   httpTimeout,
			Transport: httpTransport,
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
	var result listTokensResponse
	if err := c.listJSON(ctx, "/v2/tokens", "list tokens", &result); err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

// listJSON performs an authenticated GET and decodes the response into out. The plugin's
// two listing endpoints — tokens and Spaces keys, one per credential class — differ only
// in path, envelope and the noun in the error, so the transport handling lives here once:
// a listing is the reconciler's only view of what exists upstream, and two copies of it
// could drift into treating a failure differently on one class than the other.
func (c *doClient) listJSON(ctx context.Context, path, operation string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DO API %s returned %d: %s", operation, resp.StatusCode, string(bodyBytes))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *doClient) DeleteToken(ctx context.Context, tokenID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v2/tokens/"+cloudconfig.PathSegment(tokenID), http.NoBody)
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
