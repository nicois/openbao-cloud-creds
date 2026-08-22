package credentialgcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// httpTimeout bounds every GCP API call the minter client makes.
const httpTimeout = 30 * time.Second

// defaultTokenURI is Google's OAuth2 token endpoint, used when the supplied
// service-account JSON omits token_uri.
const defaultTokenURI = "https://oauth2.googleapis.com/token"

var httpClient = &http.Client{
	Timeout: httpTimeout,
}

// IAMCredentialsClient abstracts the GCP IAM Credentials API operations used by this plugin.
type IAMCredentialsClient interface {
	GenerateAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (token string, expiry time.Time, err error)
	TestConnection(ctx context.Context) error
}

// serviceAccountKey represents the parsed JSON key file for a GCP service account.
type serviceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	TokenURI     string `json:"token_uri"`
}

// newRealIAMClient creates a real GCP IAM Credentials client using service account JSON.
func newRealIAMClient(credentialsJSON string) IAMCredentialsClient {
	return &realIAMClient{
		credentialsJSON: credentialsJSON,
	}
}

type realIAMClient struct {
	credentialsJSON string
}

type generateAccessTokenRequest struct {
	Scope    []string `json:"scope"`
	Lifetime string   `json:"lifetime"`
}

type generateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// getAccessToken generates a self-signed JWT and exchanges it for an access token.
func (c *realIAMClient) getAccessToken(ctx context.Context) (string, error) {
	var key serviceAccountKey
	if err := json.Unmarshal([]byte(c.credentialsJSON), &key); err != nil {
		return "", fmt.Errorf("failed to parse credentials JSON: %w", err)
	}

	jwt, tokenURI, err := signServiceAccountJWT(&key)
	if err != nil {
		return "", err
	}

	return exchangeJWTForToken(ctx, tokenURI, jwt)
}

// signServiceAccountJWT parses the service account's RSA private key and builds
// a signed JWT assertion. It returns the compact JWT and the token endpoint to
// POST it to.
func signServiceAccountJWT(key *serviceAccountKey) (jwt, tokenURI string, err error) {
	// Parse the private key
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", "", fmt.Errorf("failed to decode PEM block from private key")
	}

	rsaKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 as fallback
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	privateKey, ok := rsaKey.(*rsa.PrivateKey)
	if !ok {
		// If ParsePKCS1 returned directly
		if pk, ok2 := rsaKey.(rsa.PrivateKey); ok2 {
			privateKey = &pk
		} else {
			return "", "", fmt.Errorf("private key is not RSA")
		}
	}

	// Build JWT
	tokenURI = key.TokenURI
	if tokenURI == "" {
		tokenURI = defaultTokenURI
	}
	// token_uri arrives inside operator-supplied service-account JSON and was
	// used verbatim: a signed assertion for this service account would be POSTed
	// to whatever host it named, and the response body was returned in the error
	// as an oracle. Same exposure as the endpoint overrides on the other nine
	// plugins (A3 in docs/audit-2026-08-22.md), through a field nobody reads as
	// configuration.
	if err := cloudconfig.ValidateEndpoint("token_uri", tokenURI); err != nil {
		return "", "", err
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss": key.ClientEmail,
		// The MINTER's own assertion scope, which is a different question from a
		// role's scopes: this is the breadth of the minter service account's own
		// token, and it has to cover iamcredentials (to impersonate) and IAM (to
		// manage its own keys for rotation). A role's scopes, by contrast, bound
		// what the credential we hand a caller can do, and are required rather
		// than defaulted — see fullAccessScope in path_roles.go.
		"scope": fullAccessScope,
		"aud":   tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": key.PrivateKeyID,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), tokenURI, nil
}

// exchangeJWTForToken POSTs the signed JWT assertion to the token endpoint and
// returns the resulting OAuth2 access token.
func exchangeJWTForToken(ctx context.Context, tokenURI, jwt string) (string, error) {
	data := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

func (c *realIAMClient) GenerateAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
	authToken, err := c.getAccessToken(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	// Build request body
	lifetimeStr := fmt.Sprintf("%ds", int(lifetime.Seconds()))
	reqBody := generateAccessTokenRequest{
		Scope:    scopes,
		Lifetime: lifetimeStr,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	apiURL := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		cloudconfig.PathSegment(serviceAccount))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("GCP API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp generateAccessTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse response: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, tokenResp.ExpireTime)
	if err != nil {
		// Try RFC3339Nano as GCP sometimes returns nanosecond precision
		expiry, err = time.Parse(time.RFC3339Nano, tokenResp.ExpireTime)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("failed to parse expire_time %q: %w", tokenResp.ExpireTime, err)
		}
	}

	return tokenResp.AccessToken, expiry, nil
}

func (c *realIAMClient) TestConnection(ctx context.Context) error {
	_, err := c.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}

// fakeIAMClient is used in tests.
type fakeIAMClient struct {
	generateAccessTokenFunc func(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error)
	testConnectionFunc      func(ctx context.Context) error
}

func (f *fakeIAMClient) GenerateAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
	if f.generateAccessTokenFunc != nil {
		return f.generateAccessTokenFunc(ctx, serviceAccount, scopes, lifetime)
	}
	// Default fake: return a predictable token
	expiry := time.Now().Add(lifetime)
	return "ya29.fake-access-token-for-testing", expiry, nil
}

func (f *fakeIAMClient) TestConnection(ctx context.Context) error {
	if f.testConnectionFunc != nil {
		return f.testConnectionFunc(ctx)
	}
	return nil
}
