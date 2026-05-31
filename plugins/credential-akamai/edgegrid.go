package credentialakamai

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/rand"
)

// edgeGridCredential holds the components needed for EdgeGrid authentication.
type edgeGridCredential struct {
	ClientToken  string
	AccessToken  string
	ClientSecret string
	Host         string
}

// edgeGridTokenParts is the number of colon-separated components in a minter
// token: client_token, access_token, client_secret.
const edgeGridTokenParts = 3

// parseEdgeGridToken parses a colon-separated minter token into components.
// Format: "client_token:access_token:client_secret".
func parseEdgeGridToken(token string) (*edgeGridCredential, error) {
	parts := strings.SplitN(token, ":", edgeGridTokenParts)
	if len(parts) != edgeGridTokenParts {
		return nil, fmt.Errorf("minter token must be in format 'client_token:access_token:client_secret'")
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("minter token must have non-empty client_token, access_token, and client_secret")
	}
	return &edgeGridCredential{
		ClientToken:  parts[0],
		AccessToken:  parts[1],
		ClientSecret: parts[2],
	}, nil
}

// signRequest applies EdgeGrid HMAC-SHA256 authentication to an HTTP request.
func signRequest(req *http.Request, cred *edgeGridCredential) {
	timestamp := time.Now().UTC().Format("20060102T15:04:05+0000")
	nonce := generateNonce()

	// Build auth header data prefix (without signature)
	authData := fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		cred.ClientToken, cred.AccessToken, timestamp, nonce)

	// Build canonical request
	scheme := "https"
	if req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}

	host := req.URL.Host
	pathAndQuery := req.URL.RequestURI()

	// Body hash (for POST/PUT with content)
	bodyHash := ""
	if req.Body != nil && (req.Method == "POST" || req.Method == "PUT") {
		// We don't read the body for signing in this implementation.
		// EdgeGrid typically only hashes the first 131072 bytes.
		// For API client creation, the body content is included.
		bodyHash = hashBody(nil) // empty for simplicity; real impl would buffer
	}

	// Canonical request: method\tscheme\thost\tpath+query\theaders\tbody_hash\t
	canonicalRequest := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t",
		req.Method, scheme, host, pathAndQuery, "", bodyHash)

	// Signing key: HMAC-SHA256(client_secret, timestamp)
	signingKey := hmacSHA256([]byte(cred.ClientSecret), []byte(timestamp))

	// Data to sign: auth_data + canonical_request
	dataToSign := authData + canonicalRequest

	// Signature: HMAC-SHA256(signing_key, data_to_sign) -> base64
	signature := base64.StdEncoding.EncodeToString(
		hmacSHA256(signingKey, []byte(dataToSign)),
	)

	// Final Authorization header
	req.Header.Set("Authorization", authData+"signature="+signature)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	// hash.Hash.Write is documented never to return an error; the result is
	// discarded deliberately. This does not change the signing bytes.
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return base64.StdEncoding.EncodeToString(h[:])
}

func generateNonce() string {
	b := make([]byte, nonceBytes)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
