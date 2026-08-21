package credentialupcloud

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

// TestReconcile_PopulatesCreatedAt proves the lister surfaces the upstream
// token's creation timestamp (UpCloud's "created" field) into
// UpstreamEntity.CreatedAt (audit F1 precision layer).
func TestReconcile_PopulatesCreatedAt(t *testing.T) {
	srv := fakes.NewUpCloudServer()
	defer srv.Close()

	client := newUpCloudClient(srv.URL, "user", "pass")
	if _, _, err := client.CreateToken(t.Context(), tokenPrefix+"role-abc", "1h"); err != nil {
		t.Fatalf("seed create: %v", err)
	}

	lister := &upcloudCloudLister{client: client}
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

// TestReconcile_CreatedAtDrivesDeleteVsSkip drives the real lister through the
// fail-closed reconciler: a 2h-old orphan IS deleted, a 5m-old one is SKIPPED.
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
			srv := fakes.NewUpCloudServer()
			defer srv.Close()

			client := newUpCloudClient(srv.URL, "user", "pass")
			srv.AddRawTokenWithCreatedAt("orphan-1", tokenPrefix+"role-x", tc.createdAt.UTC().Format(time.RFC3339))

			lister := &upcloudCloudLister{client: client}
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

type allOrphansRegistry struct{}

func (allOrphansRegistry) OwnedIDs(context.Context) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}
