package credentialoci

import (
	"context"
	"fmt"
)

// AuthTokenInfo represents metadata about an existing OCI auth token.
type AuthTokenInfo struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	LifecycleState string `json:"lifecycle_state"`
}

// OCIIAMClient abstracts the OCI IAM operations needed by this plugin.
// Production implementations use OCI's RSA-SHA256 request signing;
// tests use an in-memory fake.
type OCIIAMClient interface {
	// CreateAuthToken creates a new auth token for the given user.
	// Returns the token value (only available at creation time), the token OCID, and any error.
	CreateAuthToken(ctx context.Context, userID, description string) (tokenValue, tokenID string, err error)

	// DeleteAuthToken deletes the specified auth token.
	DeleteAuthToken(ctx context.Context, userID, tokenID string) error

	// ListAuthTokens lists all auth tokens for the given user.
	ListAuthTokens(ctx context.Context, userID string) ([]AuthTokenInfo, error)

	// GetUser verifies the user exists (health check).
	GetUser(ctx context.Context, userID string) error
}

// fakeOCIClient is an in-memory implementation of OCIIAMClient for testing.
type fakeOCIClient struct {
	tokens   map[string]map[string]*fakeToken // userID -> tokenID -> token
	nextID   int
	failNext error
}

type fakeToken struct {
	id          string
	value       string
	description string
	userID      string
}

func newFakeOCIClient() *fakeOCIClient {
	return &fakeOCIClient{
		tokens: make(map[string]map[string]*fakeToken),
		nextID: 1000,
	}
}

func (f *fakeOCIClient) SetNextError(err error) {
	f.failNext = err
}

func (f *fakeOCIClient) CreateAuthToken(_ context.Context, userID, description string) (string, string, error) {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return "", "", err
	}

	f.nextID++
	tokenID := fmt.Sprintf("ocid1.credential.oc1..fake%d", f.nextID)
	tokenValue := fmt.Sprintf("faketoken_%d", f.nextID)

	if f.tokens[userID] == nil {
		f.tokens[userID] = make(map[string]*fakeToken)
	}
	f.tokens[userID][tokenID] = &fakeToken{
		id:          tokenID,
		value:       tokenValue,
		description: description,
		userID:      userID,
	}

	return tokenValue, tokenID, nil
}

func (f *fakeOCIClient) DeleteAuthToken(_ context.Context, userID, tokenID string) error {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}

	if userTokens, ok := f.tokens[userID]; ok {
		delete(userTokens, tokenID)
	}
	return nil
}

func (f *fakeOCIClient) ListAuthTokens(_ context.Context, userID string) ([]AuthTokenInfo, error) {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, err
	}

	var result []AuthTokenInfo
	if userTokens, ok := f.tokens[userID]; ok {
		for _, t := range userTokens {
			result = append(result, AuthTokenInfo{
				ID:             t.id,
				Description:    t.description,
				LifecycleState: "ACTIVE",
			})
		}
	}
	return result, nil
}

func (f *fakeOCIClient) GetUser(_ context.Context, _ string) error {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	return nil
}

// TokenCount returns the total number of tokens across all users (for testing).
func (f *fakeOCIClient) TokenCount() int {
	count := 0
	for _, userTokens := range f.tokens {
		count += len(userTokens)
	}
	return count
}

// TokenCountForUser returns the number of tokens for a specific user (for testing).
func (f *fakeOCIClient) TokenCountForUser(userID string) int {
	if userTokens, ok := f.tokens[userID]; ok {
		return len(userTokens)
	}
	return 0
}
