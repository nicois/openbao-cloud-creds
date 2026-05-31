package credentialdo

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
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
	if _, _, err := client.CreateToken(context.Background(), tokenPrefix+"role-abc", []string{"read"}); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	lister := &doCloudLister{client: client}
	ents, err := lister.ListTaggedEntities(context.Background())
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
			srv.AddRawTokenWithCreatedAt("orphan-1", tokenPrefix+"role-x", tc.createdAt.UTC().Format(time.RFC3339))

			lister := &doCloudLister{client: client}
			rec := reconciler.New(reconciler.Config{
				MaxDeletesPerPass: 10,
				ConfirmationHold:  time.Hour,
			}, lister, allOrphansRegistry{})

			res, err := rec.Run(context.Background(), now)
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

// allOrphansRegistry knows nothing, so every upstream entity is an orphan.
type allOrphansRegistry struct{}

func (allOrphansRegistry) IsKnown(string) bool { return false }
