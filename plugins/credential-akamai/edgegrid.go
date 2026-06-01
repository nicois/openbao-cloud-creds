package credentialakamai

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"crypto/rand"
)

// maxBodyHashBytes is EdgeGrid's documented cap on the bytes hashed for the
// request-body portion of the signature.
const maxBodyHashBytes = 131072

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

// signRequest applies EdgeGrid HMAC-SHA256 authentication to an HTTP request,
// generating the timestamp and nonce.
func signRequest(req *http.Request, cred *edgeGridCredential) {
	timestamp := time.Now().UTC().Format("20060102T15:04:05+0000")
	signRequestAt(req, cred, timestamp, generateNonce())
}

// signRequestAt is the deterministic core of signRequest: the timestamp and
// nonce are supplied by the caller so the signature is reproducible (used by
// signRequest with generated values, and by tests with fixed values).
func signRequestAt(req *http.Request, cred *edgeGridCredential, timestamp, nonce string) {
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

	// Body hash (for POST/PUT with content). EdgeGrid hashes at most the first
	// maxBodyHashBytes of the body; the body is buffered and restored so the
	// real send is unaffected.
	bodyHash := ""
	if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut) {
		buf, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(buf)) // restore for the real send
			hashInput := buf
			if len(hashInput) > maxBodyHashBytes {
				hashInput = hashInput[:maxBodyHashBytes]
			}
			bodyHash = hashBody(hashInput)
		}
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
