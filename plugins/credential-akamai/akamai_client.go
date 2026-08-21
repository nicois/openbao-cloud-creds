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

// selfClient is the subset of GET /api-clients/self a rotation needs: the
// incumbent minter's own grants. apiAccess is decoded (the Identity-Management
// entry has to be found and possibly upgraded), while groupAccess is kept as raw
// JSON and copied through verbatim — its shape (nested groups with
// subGroups/roles) is not something this plugin should reinterpret.
type selfClient struct {
	ClientID  string `json:"clientId"`
	APIAccess struct {
		AllAccessibleAPIs bool `json:"allAccessibleApis"`
		APIs              []struct {
			APIID       int    `json:"apiId"`
			APIName     string `json:"apiName"`
			AccessLevel string `json:"accessLevel"`
		} `json:"apis"`
	} `json:"apiAccess"`
	GroupAccess json.RawMessage `json:"groupAccess"`
}

// GetSelf reads the API client the signing credential belongs to, including its
// apiAccess and groupAccess grants. A rotation successor is built from these, so
// it inherits the incumbent's authority instead of being constructed with a
// guess at what it needs.
func (c *akamaiClient) GetSelf(ctx context.Context) (*selfClient, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/identity-management/v3/api-clients/self", http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	signRequest(req, c.credential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("akamai API self returned %d: %s", resp.StatusCode, string(bodyBytes))
	}
	var result selfClient
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

// successorGrants builds the successor's apiAccess and groupAccess from the
// incumbent's own grants (self) plus the per-account Identity-Management apiId.
//
// Every api the incumbent can reach is replicated at the same access level, and
// the Identity-Management entry is added (or upgraded to READ-WRITE) so the
// successor can rotate in turn. Constructing an Identity-Management-only grant
// instead — as this used to — produced a successor that could rotate but could
// not mint the credentials any role asks for, a difference no health check sees.
// allAccessibleApis is carried through: when the incumbent holds it, the apis
// list is irrelevant upstream and the successor gets the same blanket grant.
func successorGrants(self *selfClient, identityAPIID int) (apiAccess, groupAccess interface{}) {
	apis := make([]interface{}, 0, len(self.APIAccess.APIs)+1)
	haveIdentityRW := false
	for i := range self.APIAccess.APIs {
		api := self.APIAccess.APIs[i]
		level := api.AccessLevel
		if api.APIID == identityAPIID {
			// The successor must be able to create the NEXT successor, so this entry
			// is never copied at READ-ONLY.
			level = accessLevelReadWrite
			haveIdentityRW = true
		}
		apis = append(apis, map[string]interface{}{jsonKeyAPIID: api.APIID, jsonKeyAccessLevel: level})
	}
	if !haveIdentityRW {
		apis = append(apis, map[string]interface{}{jsonKeyAPIID: identityAPIID, jsonKeyAccessLevel: accessLevelReadWrite})
	}

	apiAccess = map[string]interface{}{
		"allAccessibleApis": self.APIAccess.AllAccessibleAPIs,
		jsonKeyAPIs:         apis,
	}
	return apiAccess, groupAccessFromSelf(self)
}

// groupAccessFromSelf returns the incumbent's groupAccess verbatim, or an empty
// grant when it reported none.
func groupAccessFromSelf(self *selfClient) interface{} {
	if len(self.GroupAccess) == 0 || string(self.GroupAccess) == "null" {
		return map[string]interface{}{jsonKeyGroups: []interface{}{}}
	}
	return self.GroupAccess
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

	// Read the incumbent's OWN grants and replicate them, rather than constructing
	// a grant from what rotation is known to need. A successor that holds only
	// Identity-Management access can rotate but cannot mint anything a role asks
	// for. Fail closed: without the incumbent's grants there is no safe grant to
	// give the successor, so a failed read aborts the rotation rather than
	// silently narrowing authority.
	self, status, err := c.GetSelf(ctx)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf(
			"could not read the incumbent minter's own grants to replicate onto the successor (status %d): %w", status, err)
	}
	apiAccess, groupAccess := successorGrants(self, apiID)
	// rotation_params.group_id remains an explicit override for the case where the
	// incumbent reports no group access of its own.
	if gid := old.RotationParams[fieldGroupIDParam]; gid != "" && len(self.GroupAccess) == 0 {
		if n, perr := strconv.Atoi(gid); perr == nil {
			groupAccess = map[string]interface{}{
				jsonKeyGroups: []interface{}{map[string]interface{}{jsonKeyGroupID: n}},
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
