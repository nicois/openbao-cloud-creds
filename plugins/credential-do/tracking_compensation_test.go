package credentialdo_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// putFailStorage wraps a logical.Storage and forces Put to fail for any key
// with the configured prefix, delegating everything else to the embedded
// storage. Used to simulate a tracking-record write failure during issuance
// (audit finding F6).
type putFailStorage struct {
	logical.Storage
	failPrefix string
}

func (s *putFailStorage) Put(ctx context.Context, e *logical.StorageEntry) error {
	if strings.HasPrefix(e.Key, s.failPrefix) {
		return fmt.Errorf("injected put failure for key %q", e.Key)
	}
	return s.Storage.Put(ctx, e)
}

// TestCredsIssue_TrackingWriteFailureCompensates verifies that when the
// active-tokens/ tracking record cannot be persisted, the plugin does NOT
// leave a live-but-untracked upstream credential: it revokes the just-minted
// token and returns an error envelope (F6).
func TestCredsIssue_TrackingWriteFailureCompensates(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	before := srv.ProvisionedCount()

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   &putFailStorage{Storage: storage, failPrefix: "active-tokens/"},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected an error response when tracking write fails, got resp=%v", resp)
	}

	// The compensating revoke must have removed the just-minted token, leaving
	// the fake's token count unchanged from before the (failed) issue.
	if got := srv.ProvisionedCount(); got != before {
		t.Fatalf("orphaned upstream token: count went %d -> %d (live-but-untracked credential, F6)", before, got)
	}
}
