package credentialdo_test

import (
	"sync"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestConcurrent_IssueDuringWorkerActivity hammers the shared backend with many
// concurrent credential issues plus concurrent metrics reads against a single
// shared backend + storage. Its purpose is to be run under -race: the pass
// criterion is "no data race and no Go-level error/panic". A fake-returned
// logical error response would be acceptable to ignore, but here issuance is
// expected to succeed, so we assert no error and no error response.
func TestConcurrent_IssueDuringWorkerActivity(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	const issuers = 8
	const issuesPerGoroutine = 20
	const readers = 2

	var wg sync.WaitGroup

	// Issuers: each repeatedly issues creds/test-role with its own request.
	wg.Add(issuers)
	for i := 0; i < issuers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < issuesPerGoroutine; j++ {
				req := &logical.Request{
					Operation: logical.ReadOperation,
					Path:      "creds/test-role",
					Storage:   storage,
				}
				resp, err := b.HandleRequest(t.Context(), req)
				if err != nil {
					t.Errorf("issue failed: %v", err)
					return
				}
				if resp == nil || resp.IsError() {
					t.Errorf("issue error response: %v", resp)
					return
				}
			}
		}()
	}

	// Readers: concurrently read the minter set, which now carries per-minter health
	// (A27). This replaced a read of the deleted metrics/entity endpoint; the point of
	// the test is concurrent reads racing worker activity, and this is the read-side
	// surface that exists.
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < issuesPerGoroutine; j++ {
				req := &logical.Request{
					Operation: logical.ReadOperation,
					Path:      "minter-sets/default",
					Storage:   storage,
				}
				if _, err := b.HandleRequest(t.Context(), req); err != nil {
					t.Errorf("metrics read failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()
}
