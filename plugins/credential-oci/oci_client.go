package credentialoci

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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

// signingOCIClient is the production OCIIAMClient. It parses a minter token of
// the form "tenancy_ocid:user_ocid:fingerprint:private_key_pem" and signs OCI
// IAM requests with RSA-SHA256. The signing transport is intentionally not yet
// implemented in this open-source extraction; real-cloud integration tests
// (build tag cloud_real) exercise it against a dedicated test tenancy.
type signingOCIClient struct {
	token  string
	region string
}

func newSigningOCIClient(token, region string) *signingOCIClient {
	return &signingOCIClient{token: token, region: region}
}

func (c *signingOCIClient) CreateAuthToken(_ context.Context, _, _ string) (tokenValue, tokenID string, err error) {
	return "", "", credenvelope.NewError(credenvelope.ErrUnsupported, http.StatusNotImplemented,
		"OCI request signing not implemented in this build")
}

func (c *signingOCIClient) DeleteAuthToken(_ context.Context, _, _ string) error {
	return credenvelope.NewError(credenvelope.ErrUnsupported, http.StatusNotImplemented,
		"OCI request signing not implemented in this build")
}

func (c *signingOCIClient) ListAuthTokens(_ context.Context, _ string) ([]AuthTokenInfo, error) {
	return nil, credenvelope.NewError(credenvelope.ErrUnsupported, http.StatusNotImplemented,
		"OCI request signing not implemented in this build")
}

func (c *signingOCIClient) GetUser(_ context.Context, _ string) error {
	return credenvelope.NewError(credenvelope.ErrUnsupported, http.StatusNotImplemented,
		"OCI request signing not implemented in this build")
}

// fakeOCIClient is an in-memory implementation of OCIIAMClient for testing.
//
// The fake is shared between the test goroutine and the background
// rotation/reconcile workers, which call its methods concurrently. mu guards
// every field; without it -race reports a data race / "concurrent map writes"
// (audit F3). All methods are leaves (none calls another fake method), so a
// plain Lock/defer-Unlock per method is re-entrancy-safe.
type fakeOCIClient struct {
	mu       sync.Mutex
	tokens   map[string]map[string]*fakeToken // userID -> tokenID -> token
	nextID   int
	failNext error
}

// fakeStartingTokenID is the starting counter for synthetic token OCIDs the
// in-memory fake hands out.
const fakeStartingTokenID = 1000

type fakeToken struct {
	id          string
	value       string
	description string
	userID      string
}

func newFakeOCIClient() *fakeOCIClient {
	return &fakeOCIClient{
		tokens: make(map[string]map[string]*fakeToken),
		nextID: fakeStartingTokenID,
	}
}

func (f *fakeOCIClient) SetNextError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = err
}

func (f *fakeOCIClient) CreateAuthToken(_ context.Context, userID, description string) (tokenValue, tokenID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err = f.failNext
		f.failNext = nil
		return "", "", err
	}

	f.nextID++
	tokenID = fmt.Sprintf("ocid1.credential.oc1..fake%d", f.nextID)
	tokenValue = fmt.Sprintf("faketoken_%d", f.nextID)

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
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	return nil
}

// TokenCount returns the total number of tokens across all users (for testing).
func (f *fakeOCIClient) TokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, userTokens := range f.tokens {
		count += len(userTokens)
	}
	return count
}

// TokenCountForUser returns the number of tokens for a specific user (for testing).
func (f *fakeOCIClient) TokenCountForUser(userID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if userTokens, ok := f.tokens[userID]; ok {
		return len(userTokens)
	}
	return 0
}
