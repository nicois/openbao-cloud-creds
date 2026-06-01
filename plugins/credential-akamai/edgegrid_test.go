package credentialakamai

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSignRequest_HashesBody proves the EdgeGrid signature covers the actual
// POST body — a non-empty body must change the signature, and the body must
// remain readable after signing (restored for the real send).
//
// signRequest generates the timestamp and nonce internally, which would make
// two signatures differ for reasons other than the body. We pin both via the
// signRequestAt core so the body is the ONLY varying input.
func TestSignRequest_HashesBody(t *testing.T) {
	cred := &edgeGridCredential{ClientToken: "ct", AccessToken: "at", ClientSecret: "cs"}
	const ts = "20260101T00:00:00+0000"
	const nonce = "fixednonce"
	body := []byte(`{"clientName":"cloud-creds-x"}`)

	req, _ := http.NewRequest(http.MethodPost, "https://h.example/x", bytes.NewReader(body))
	signRequestAt(req, cred, ts, nonce)
	sigWithBody := extractSignature(t, req)

	reqEmpty, _ := http.NewRequest(http.MethodPost, "https://h.example/x", http.NoBody)
	signRequestAt(reqEmpty, cred, ts, nonce)
	sigEmpty := extractSignature(t, reqEmpty)

	if sigWithBody == sigEmpty {
		t.Fatal("signature must differ when the body is non-empty (body hash not included)")
	}

	got, _ := io.ReadAll(req.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("body not restored after signing: got %q", got)
	}
}

func extractSignature(t *testing.T, req *http.Request) string {
	t.Helper()
	auth := req.Header.Get("Authorization")
	const marker = "signature="
	i := strings.Index(auth, marker)
	if i < 0 {
		t.Fatalf("no signature in %q", auth)
	}
	return auth[i+len(marker):]
}
