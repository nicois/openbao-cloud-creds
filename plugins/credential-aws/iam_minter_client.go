package credentialaws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

// IAMMinterClient abstracts the IAM access-key management operations minter
// self-rotation needs. This is SEPARATE from STSClient (the issuance client):
// STS mints short-lived role credentials, whereas these calls manage the minter
// IAM user's own long-lived access keys (the make-before-break rotation).
type IAMMinterClient interface {
	// CreateAccessKey provisions a new access key for the IAM user the minter
	// authenticates as, returning the new key id and secret.
	CreateAccessKey(ctx context.Context) (accessKeyID, secretAccessKey string, err error)
	// DeleteAccessKey deletes an access key (by id) of that same IAM user.
	DeleteAccessKey(ctx context.Context, accessKeyID string) error
	// ListAccessKeyIDs lists the access key ids of that same IAM user.
	ListAccessKeyIDs(ctx context.Context) ([]string, error)
}

// IAMMinterClientFactory builds an IAMMinterClient from a minter's
// access_key_id:secret_access_key pair (and region), mirroring STSClientFactory.
type IAMMinterClientFactory func(accessKeyID, secretAccessKey, region string) IAMMinterClient

const (
	// iamAPIVersion is the IAM query-API version. All actions use it.
	iamAPIVersion = "2010-05-08"
	// iamServiceName is the SigV4 service name for IAM. IAM is a global service
	// signed in iamSigningRegion regardless of the configured STS region.
	iamServiceName = "iam"
	// iamSigningRegion is the region IAM (a global service) is signed for.
	iamSigningRegion = "us-east-1"
	// iamEndpoint is the IAM global endpoint.
	iamEndpoint = "https://iam.amazonaws.com/"
	// iamHTTPTimeout bounds every IAM API call.
	iamHTTPTimeout = 30 * time.Second
	// errNoSuchEntity is the IAM error code returned when an access key to delete
	// is already gone — the retired-sweep treats it as success (idempotent).
	errNoSuchEntity = "NoSuchEntity"
)

// realIAMMinterClient is the production IAMMinterClient. It signs raw IAM
// query-API requests with SigV4 using the AWS SDK's signer (already a transitive
// dependency via the STS client), so it adds NO new module dependency. It is a
// minimal real implementation of the three access-key calls rotation needs;
// because AWS is an injected-client plugin (fakes are injected in tests) this
// signed path is exercised only against real IAM and so is flagged for
// real-cloud validation (audit2 #9 / audit #7).
type realIAMMinterClient struct {
	creds      aws.Credentials
	httpClient *http.Client
	signer     *v4.Signer
}

// newRealIAMMinterClient builds a realIAMMinterClient from a minter's static
// access key. region is accepted for signature parity with the STS factory; IAM
// is global so signing always uses iamSigningRegion.
func newRealIAMMinterClient(accessKeyID, secretAccessKey, _ string) IAMMinterClient {
	return &realIAMMinterClient{
		creds:      aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey},
		httpClient: &http.Client{Timeout: iamHTTPTimeout},
		signer:     v4.NewSigner(),
	}
}

// iamErrorResponse is the IAM query-API XML error envelope.
type iamErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// createAccessKeyResult maps the CreateAccessKey XML response.
type createAccessKeyResult struct {
	AccessKey struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
	} `xml:"CreateAccessKeyResult>AccessKey"`
}

// listAccessKeysResult maps the ListAccessKeys XML response.
type listAccessKeysResult struct {
	Members []struct {
		AccessKeyID string `xml:"AccessKeyId"`
	} `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
}

// do signs and sends a single IAM query-API POST and returns the body bytes. On
// a non-2xx it parses the XML error and returns an error whose message includes
// the IAM error Code (so callers can match errNoSuchEntity).
func (c *realIAMMinterClient) do(ctx context.Context, action string, extra url.Values) ([]byte, error) {
	form := url.Values{}
	form.Set("Action", action)
	form.Set("Version", iamAPIVersion)
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, iamEndpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	sum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(sum[:])
	if err := c.signer.SignHTTP(ctx, c.creds, req, payloadHash, iamServiceName, iamSigningRegion, time.Now()); err != nil {
		return nil, fmt.Errorf("sign IAM request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var e iamErrorResponse
		if xmlErr := xml.Unmarshal(raw, &e); xmlErr == nil && e.Error.Code != "" {
			return nil, fmt.Errorf("iam %s failed (%s): %s", action, e.Error.Code, e.Error.Message)
		}
		return nil, fmt.Errorf("iam %s failed (status %d)", action, resp.StatusCode)
	}
	return raw, nil
}

func (c *realIAMMinterClient) CreateAccessKey(ctx context.Context) (accessKeyID, secretAccessKey string, err error) {
	raw, err := c.do(ctx, "CreateAccessKey", nil)
	if err != nil {
		return "", "", err
	}
	var out createAccessKeyResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return "", "", fmt.Errorf("parse CreateAccessKey response: %w", err)
	}
	if out.AccessKey.AccessKeyID == "" {
		return "", "", fmt.Errorf("CreateAccessKey returned an empty access key id")
	}
	return out.AccessKey.AccessKeyID, out.AccessKey.SecretAccessKey, nil
}

func (c *realIAMMinterClient) DeleteAccessKey(ctx context.Context, accessKeyID string) error {
	_, err := c.do(ctx, "DeleteAccessKey", url.Values{"AccessKeyId": {accessKeyID}})
	return err
}

func (c *realIAMMinterClient) ListAccessKeyIDs(ctx context.Context) ([]string, error) {
	raw, err := c.do(ctx, "ListAccessKeys", nil)
	if err != nil {
		return nil, err
	}
	var out listAccessKeysResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse ListAccessKeys response: %w", err)
	}
	ids := make([]string, 0, len(out.Members))
	for i := range out.Members {
		ids = append(ids, out.Members[i].AccessKeyID)
	}
	return ids, nil
}

// isNoSuchEntity reports whether err is an IAM NoSuchEntity (the key is already
// gone). Used by the retired-sweep to treat an already-deleted key as success.
func isNoSuchEntity(err error) bool {
	return err != nil && strings.Contains(err.Error(), errNoSuchEntity)
}

// maxAccessKeysPerUser is the IAM hard limit on access keys per user. The
// make-before-break rotation needs one free slot to create the successor before
// the old key is retired, so a user already at this many keys cannot be rotated
// until the retired-sweep frees a slot.
const maxAccessKeysPerUser = 2

// rotationSuffix returns a short, monotonic-ish suffix for a successor minter ID
// so successive rotations of the same minter never collide.
func rotationSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// minterRotator wraps an IAMMinterClient to perform RotateMinter. It mirrors the
// other plugins' client.RotateMinter shape while keeping the IAM key-management
// surface (IAMMinterClient) separate from the STS issuance client.
type minterRotator struct {
	client IAMMinterClient
}

// RotateMinter mints a successor IAM access key for the SAME IAM user that old
// authenticates as (so the successor inherits old's IAM rights), implementing
// make-before-break:
//
//  1. 2-key guard: list the user's existing access keys; if it is already at
//     the IAM cap (maxAccessKeysPerUser) there is no free slot, so reject WITHOUT
//     creating anything. In the normal case the minter is the user's only key,
//     leaving one free slot for the successor.
//  2. CreateAccessKey on that user → the successor's access key id + secret. The
//     successor Token is "accessKeyId:secretAccessKey"; its OWN access key id is
//     recorded in RotationParams[access_key_id] so a later retired-sweep can
//     DeleteAccessKey it precisely.
//
// 2-key + grace interaction: during the retirement grace the user legitimately
// holds 2 keys (old retired + successor active). A SECOND rotation within that
// grace therefore hits the 2-key guard and is rejected until the retired-sweep
// deletes the old key. That is correct and bounded — never more than 2 keys.
//
// AWS access keys do not expire, so the successor inherits old.NeverExpires
// (minters here are typically never_expires); no ExpiresAt is set.
func (m *minterRotator) RotateMinter(ctx context.Context, old cloudconfig.Minter) (cloudconfig.Minter, error) {
	ids, err := m.client.ListAccessKeyIDs(ctx)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("list access keys failed: %w", err)
	}
	if len(ids) >= maxAccessKeysPerUser {
		return cloudconfig.Minter{}, fmt.Errorf(
			"minter user already has %d access keys; free a slot or wait for the retirement sweep", len(ids))
	}

	newID, newSecret, err := m.client.CreateAccessKey(ctx)
	if err != nil {
		return cloudconfig.Minter{}, fmt.Errorf("create access key failed: %w", err)
	}

	return cloudconfig.Minter{
		ID:           old.ID + "-rot-" + rotationSuffix(),
		Token:        newID + ":" + newSecret,
		CreatedAt:    time.Now(),
		NeverExpires: old.NeverExpires,
		RotationParams: map[string]string{
			fieldAccessKeyID: newID,
		},
	}, nil
}
