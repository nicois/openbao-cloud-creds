package credentialakamai

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

const (
	// identityManagementAPIName is the human-readable Identity-Management API
	// label the allowed-apis lookup matches on; its numeric apiId is per-account,
	// so it is resolved at rotation time rather than hard-coded.
	identityManagementAPIName = "Identity Management: API Clients"
	// accessLevelReadWrite is the grant a rotation successor needs on the
	// Identity-Management API so it can itself create the next successor.
	accessLevelReadWrite = "READ-WRITE"
	// clientTypeClient is the Akamai api-client type for a service (non-user) API
	// client.
	clientTypeClient = "CLIENT"
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
	ClientID    string `json:"clientId"`
	ClientName  string `json:"clientName"`
	CreatedDate string `json:"createdDate"`
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

// allowedAPI is one entry of the per-user allowed-apis lookup. The numeric
// apiId of the Identity-Management API is per-account, so it is resolved here
// rather than hard-coded.
type allowedAPI struct {
	APIID        int      `json:"apiId"`
	APIName      string   `json:"apiName"`
	AccessLevels []string `json:"accessLevels"`
}

// resolveIdentityManagementAPIID looks up the per-account apiId of the
// Identity-Management API that the given user is allowed READ-WRITE on. The
// successor must be granted READ-WRITE on this api to stay self-rotatable.
func (c *akamaiClient) resolveIdentityManagementAPIID(ctx context.Context, username string) (int, error) {
	url := c.baseURL + "/identity-management/v3/users/" + username + "/allowed-apis"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, err
	}
	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("allowed-apis returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var apis []allowedAPI
	if err := json.NewDecoder(resp.Body).Decode(&apis); err != nil {
		return 0, err
	}
	for i := range apis {
		if apis[i].APIName != identityManagementAPIName {
			continue
		}
		for _, lvl := range apis[i].AccessLevels {
			if lvl == accessLevelReadWrite {
				return apis[i].APIID, nil
			}
		}
		return 0, fmt.Errorf("user %q is not granted %s on the Identity-Management API", username, accessLevelReadWrite)
	}
	return 0, fmt.Errorf("user %q has no allowed Identity-Management API entry", username)
}

// rotationSuffix returns a short, monotonic-ish suffix for a successor minter
// ID so successive rotations of the same minter never collide.
func rotationSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// RotateMinter mints a successor Akamai API client that is itself granted
// READ-WRITE on the (per-account) Identity-Management API, so the successor can
// later rotate again. The authorizing user comes from
// old.RotationParams["username"]; the per-account apiId is resolved from that
// user's allowed-apis at rotation time. The successor's EdgeGrid triple becomes
// its minter token, and it records its upstream clientId in
// RotationParams["client_id"] so the retired-sweep can delete the API client,
// carrying username (and any group_id) forward.
func (c *akamaiClient) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	username := old.RotationParams[fieldUsername]
	if username == "" {
		return cloudconfig.Minter{}, fmt.Errorf("minter %s missing rotation_params.%s", old.ID, fieldUsername)
	}

	apiID, err := c.resolveIdentityManagementAPIID(ctx, username)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("could not grant the successor Identity-Management access; %w", err)
	}

	apiAccess := map[string]interface{}{
		"allAccessibleApis": false,
		jsonKeyAPIs: []interface{}{
			map[string]interface{}{"apiId": apiID, "accessLevel": accessLevelReadWrite},
		},
	}
	groupAccess := map[string]interface{}{jsonKeyGroups: []interface{}{}}
	if gid := old.RotationParams[fieldGroupIDParam]; gid != "" {
		if n, perr := strconv.Atoi(gid); perr == nil {
			groupAccess = map[string]interface{}{
				jsonKeyGroups: []interface{}{map[string]interface{}{"groupId": n}},
			}
		}
	}

	clientName := "cloud-creds-minter-" + old.ID + "-rot-" + rotationSuffix()
	created, status, err := c.createRotationClient(ctx, clientName, username, apiAccess, groupAccess)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("create successor api client failed (status %d): %w", status, err)
	}
	if len(created.Credentials) == 0 {
		return cloudconfig.Minter{}, fmt.Errorf("successor api client returned no credentials")
	}
	cred := created.Credentials[0]

	successor := cloudconfig.Minter{
		ID:           old.ID + "-rot-" + rotationSuffix(),
		Token:        cred.ClientToken + ":" + cred.AccessToken + ":" + cred.ClientSecret,
		CreatedAt:    time.Now(),
		NeverExpires: old.NeverExpires,
		RotationParams: map[string]string{
			fieldUsername: username,
			fieldClientID: created.ClientID,
		},
	}
	// A non-never-expires successor gets a fresh full-lifetime expiry (the new
	// API-client credential is freshly minted, not inheriting old's residual
	// life). This matches the synthetic successor the rotate endpoint validates
	// against before minting.
	if !old.NeverExpires {
		successor.ExpiresAt = time.Now().Add(minterSecretLifetime)
	}
	if gid := old.RotationParams[fieldGroupIDParam]; gid != "" {
		successor.RotationParams[fieldGroupIDParam] = gid
	}
	return successor, nil
}

// createRotationClient POSTs a service (CLIENT-type) API client authorized for
// the given user, requesting credentials. It differs from CreateClient in that
// it sets clientType and authorizedUsers, as a rotation successor must.
func (c *akamaiClient) createRotationClient(ctx context.Context, name, username string, apiAccess, groupAccess interface{}) (*createClientResponse, int, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"clientName":      name,
		"clientType":      clientTypeClient,
		"authorizedUsers": []string{username},
		"apiAccess":       apiAccess,
		"groupAccess":     groupAccess,
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
