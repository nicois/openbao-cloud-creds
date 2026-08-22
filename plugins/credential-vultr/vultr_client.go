package credentialvultr

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

// httpTimeout bounds every upstream Vultr API call.
const httpTimeout = 30 * time.Second

type vultrClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type createUserRequest struct {
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	APIEnabled bool     `json:"api_enabled"`
	ACLs       []string `json:"acls"`
}

type userResponse struct {
	User struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Email  string   `json:"email"`
		APIKey string   `json:"api_key"`
		ACLs   []string `json:"acls"`
	} `json:"user"`
}

type userInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listUsersResponse struct {
	Users []userInfo `json:"users"`
}

func newVultrClient(baseURL, token string) *vultrClient {
	return &vultrClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

func (c *vultrClient) CreateUser(ctx context.Context, name, email string, acls []string) (*userResponse, int, error) {
	body, _ := json.Marshal(createUserRequest{
		Email:      email,
		Name:       name,
		APIEnabled: true,
		ACLs:       acls,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v2/users", bytes.NewReader(body))
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
		return nil, resp.StatusCode, fmt.Errorf("vultr API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result userResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *vultrClient) CheckHealth(ctx context.Context) (int, error) {
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

func (c *vultrClient) ListUsers(ctx context.Context) ([]userInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v2/users", http.NoBody)
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
		return nil, fmt.Errorf("vultr API list users returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result listUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Users, nil
}

func (c *vultrClient) DeleteUser(ctx context.Context, userID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v2/users/"+cloudconfig.PathSegment(userID), http.NoBody)
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
		return resp.StatusCode, fmt.Errorf("vultr API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
