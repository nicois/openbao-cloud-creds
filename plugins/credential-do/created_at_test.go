package credentialdo

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/ownertag"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

// TestReconcile_PopulatesCreatedAt proves the lister surfaces the upstream
// token's creation timestamp (DO's GET /v2/tokens "created_at" field) into
// UpstreamEntity.CreatedAt, which the fail-closed reconciler relies on to
// confirm an orphan is old enough to delete (audit F1 precision layer).
func TestReconcile_PopulatesCreatedAt(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	// Seed a cloud-creds-prefixed token via the create path so the fake emits
	// a created_at on the subsequent list.
	client := newDOClient(srv.URL, "fake-minter-token")
	if _, _, err := client.CreateToken(t.Context(), ownertag.Prefix(testOwnerInstance)+"role-abc", []string{"read"}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	lister := &doCloudLister{client: client, instanceID: testOwnerInstance}
	ents, err := lister.ListTaggedEntities(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	found := false
	for _, e := range ents {
		if !e.CreatedAt.IsZero() {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one entity with non-zero CreatedAt")
	}
}

// TestReconcile_CreatedAtDrivesDeleteVsSkip is the end-to-end Task3+Task4 proof:
// driving the real lister through reconciler.New(ConfirmationHold:1h).Run, an
// orphan whose upstream created_at is 2h old IS deleted, while one 5m old is
// SKIPPED (still inside the create-then-track window we cannot rule out).
func TestReconcile_CreatedAtDrivesDeleteVsSkip(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name       string
		createdAt  time.Time
		wantDelete bool
	}{
		{"two-hours-old", now.Add(-2 * time.Hour), true},
		{"five-minutes-old", now.Add(-5 * time.Minute), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakes.NewDOServer()
			defer srv.Close()

			client := newDOClient(srv.URL, "fake-minter-token")
			// Plant an orphan (cloud-creds- named, not in the lease registry)
			// with a controlled created_at.
			srv.AddRawTokenWithCreatedAt("orphan-1", ownertag.Prefix(testOwnerInstance)+"role-x", tc.createdAt.UTC().Format(time.RFC3339))

			lister := &doCloudLister{client: client, instanceID: testOwnerInstance}
			rec := reconciler.New(reconciler.Config{
				MaxDeletesPerPass: 10,
				ConfirmationHold:  time.Hour,
			}, lister, allOrphansRegistry{})

			res, err := rec.Run(t.Context(), now)
			if err != nil {
				t.Fatalf("run: %v", err)
			}

			deleted := !srv.HasToken("orphan-1")
			if deleted != tc.wantDelete {
				t.Fatalf("orphan deleted=%v, want %v (result=%+v)", deleted, tc.wantDelete, res)
			}
		})
	}
}

// TestDeleteEntity_404IsSuccess proves the lister treats an upstream 404 (the
// entity is already gone) as a successful delete rather than a hard error that
// would wedge the whole reconcile pass (audit F5). Asserted for EVERY credential
// class: the tolerance is per-endpoint code, so a new class starts without it.
func TestDeleteEntity_404IsSuccess(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()
	lister := &doCloudLister{client: newDOClient(srv.URL, "minter-token"), instanceID: testOwnerInstance}
	for _, class := range []string{credentialTypeToken, credentialTypeSpacesKey} {
		if err := lister.DeleteEntity(t.Context(), classedID(class, "nonexistent-id")); err != nil {
			t.Errorf("DeleteEntity(%s) should treat upstream 404 as success, got: %v", class, err)
		}
	}
}

// allOrphansRegistry knows nothing, so every upstream entity is an orphan.
type allOrphansRegistry struct{}

func (allOrphansRegistry) OwnedIDs(context.Context) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

// testOwnerInstance stands in for a mount's persisted owner instance id (A19).
const testOwnerInstance = "testinstance"
