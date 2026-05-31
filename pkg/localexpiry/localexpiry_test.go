package localexpiry_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/nicois/openbao-cloud-creds/pkg/localexpiry"
)

func put(t *testing.T, s logical.Storage, key, expiresAt string) {
	t.Helper()
	e, err := logical.StorageEntryJSON("active-tokens/"+key, map[string]interface{}{"expires_at": expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func TestPruneExpired_DeletesPastEntries(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "old", now.Add(-time.Hour).Format(time.RFC3339))
	put(t, s, "fresh", now.Add(time.Hour).Format(time.RFC3339))

	res, err := localexpiry.PruneExpired(context.Background(), s, localexpiry.Options{Prefix: "active-tokens/", Now: now, DryRun: false, Logger: hclog.NewNullLogger()})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", res.Deleted)
	}
	if len(res.Expired) != 1 || res.Expired[0] != "old" {
		t.Fatalf("expected [old] expired, got %v", res.Expired)
	}
	if e, _ := s.Get(context.Background(), "active-tokens/fresh"); e == nil {
		t.Fatal("fresh entry was wrongly deleted")
	}
	if e, _ := s.Get(context.Background(), "active-tokens/old"); e != nil {
		t.Fatal("old entry was not deleted")
	}
}

func TestPruneExpired_DryRunDeletesNothing(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "old", now.Add(-time.Hour).Format(time.RFC3339))

	res, err := localexpiry.PruneExpired(context.Background(), s, localexpiry.Options{Prefix: "active-tokens/", Now: now, DryRun: true, Logger: hclog.NewNullLogger()})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("dry-run: expected 0 deleted, got %d", res.Deleted)
	}
	if len(res.Expired) != 1 {
		t.Fatalf("dry-run: expected 1 expired-found, got %d", len(res.Expired))
	}
	if e, _ := s.Get(context.Background(), "active-tokens/old"); e == nil {
		t.Fatal("dry-run must not delete")
	}
}

func TestPruneExpired_SkipsMalformedTimestamp(t *testing.T) {
	s := &logical.InmemStorage{}
	now := time.Now()
	put(t, s, "bad", "not-a-timestamp")
	put(t, s, "missing", "")

	res, err := localexpiry.PruneExpired(context.Background(), s, localexpiry.Options{Prefix: "active-tokens/", Now: now, DryRun: false, Logger: hclog.NewNullLogger()})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 0 || len(res.Expired) != 0 {
		t.Fatalf("malformed/empty must be skipped, got deleted=%d expired=%d", res.Deleted, len(res.Expired))
	}
}
