package credentialupcloud

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

// httpTimeout bounds every UpCloud API call the minter client makes.
const httpTimeout = 30 * time.Second

const (
	// defaultMinterSecretLifetime is how long a rotation successor token is valid
	// upstream when the original minter expires (NeverExpires=false). UpCloud
	// caps token expires_in at 8760h (365d), so a successor lasts the full year
	// before the next operator-driven rotation. Expressed as an UpCloud
	// expires_in duration string via minterExpiresIn.
	defaultMinterSecretLifetime = 365 * 24 * time.Hour

	// successorTokenNamePrefix is the token-name prefix for a rotation successor
	// (the owner-tag prefix the reconciler recognises, plus the successor minter
	// id).
	successorTokenNamePrefix = "cloud-creds-minter-"
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
	return c.postToken(ctx, name, expiresIn, false)
}

// postToken POSTs a new UpCloud API token. canCreateTokens marks the new token
// itself mint-capable (used for rotation successors, which must be able to mint
// further credentials).
func (c *upcloudClient) postToken(ctx context.Context, name, expiresIn string, canCreateTokens bool) (*tokenResponse, int, error) {
	body, _ := json.Marshal(createTokenRequest{
		Name:            name,
		ExpiresIn:       expiresIn,
		CanCreateTokens: canCreateTokens,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/1.3/account/tokens/"+cloudconfig.PathSegment(tokenID), http.NoBody)
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

// rotationSuffix returns a short, monotonic-ish suffix for a successor minter
// ID so successive rotations of the same minter never collide.
func rotationSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// minterExpiresIn formats a successor's upstream token lifetime as an UpCloud
// expires_in duration string (e.g. "8760h0m0s").
func minterExpiresIn(d time.Duration) string {
	return d.String()
}

// RotateMinter mints a successor UpCloud API token that is itself mint-capable
// (can_create_tokens=true), so the successor can mint further credentials like
// the original minter. The successor records its OWN upstream token id in
// RotationParams[token_id] so a later retired-sweep can DeleteToken it. It
// inherits old.NeverExpires; if the original expires, the successor is given a
// defaultMinterSecretLifetime-bounded expiry.
func (c *upcloudClient) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	name := successorTokenNamePrefix + old.ID
	expiresIn := ""
	endDate := time.Now().Add(defaultMinterSecretLifetime)
	if !old.NeverExpires {
		expiresIn = minterExpiresIn(defaultMinterSecretLifetime)
	}

	tok, status, err := c.postToken(ctx, name, expiresIn, true)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("create successor token failed (status %d): %w", status, err)
	}

	successor := cloudconfig.Minter{
		ID:           old.ID + "-rot-" + rotationSuffix(),
		Token:        tok.Token,
		CreatedAt:    time.Now(),
		NeverExpires: old.NeverExpires,
		RotationParams: map[string]string{
			fieldTokenID: tok.ID,
		},
	}
	if !old.NeverExpires {
		successor.ExpiresAt = endDate
	}
	return successor, nil
}
