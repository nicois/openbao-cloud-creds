package reconciler_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

type fakeCloudLister struct {
	entities []reconciler.UpstreamEntity
}

func (f *fakeCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	return f.entities, nil
}

func (f *fakeCloudLister) DeleteEntity(ctx context.Context, id string) error {
	for i, e := range f.entities {
		if e.ID == id {
			f.entities = append(f.entities[:i], f.entities[i+1:]...)
			return nil
		}
	}
	return nil
}

type fakeRegistry struct {
	known map[string]bool
}

func (f *fakeRegistry) IsKnown(id string) bool {
	return f.known[id]
}

func TestDetectsOrphans(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "known-1", Name: "cloud-creds-role-a-lease1"},
			{ID: "orphan-1", Name: "cloud-creds-role-b-lease2"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{"known-1": true}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.OrphansFound) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(result.OrphansFound))
	}
	if result.OrphansFound[0] != "orphan-1" {
		t.Fatalf("unexpected orphan: %s", result.OrphansFound[0])
	}
}

func TestDryRunDoesNotDelete(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-role-a-lease1"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            true,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("expected 0 deletes in dry-run, got %d", result.Deleted)
	}
	if len(cloud.entities) != 1 {
		t.Fatal("entity should not have been deleted in dry-run")
	}
}

func TestRun_OnlyDeletesListedOrphans(t *testing.T) {
	cloud := &fakeCloudLister{entities: []reconciler.UpstreamEntity{
		{ID: "orphan-1", Name: "cloud-creds-role-a-1"},
		{ID: "known-1", Name: "cloud-creds-role-a-2"},
	}}
	reg := &fakeRegistry{known: map[string]bool{"known-1": true}}
	r := reconciler.New(reconciler.Config{MaxDeletesPerPass: 10}, cloud, reg)
	res, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(cloud.entities) != 1 || cloud.entities[0].ID != "known-1" {
		t.Fatalf("known entity deleted or orphan survived: %v", cloud.entities)
	}
	if res.Deleted != 1 {
		t.Fatalf("expected 1 delete, got %d", res.Deleted)
	}
}

func TestMaxDeletesPerPass(t *testing.T) {
	entities := make([]reconciler.UpstreamEntity, 15)
	for i := range entities {
		entities[i] = reconciler.UpstreamEntity{
			ID:   fmt.Sprintf("orphan-%d", i),
			Name: fmt.Sprintf("cloud-creds-role-x-lease%d", i),
		}
	}
	cloud := &fakeCloudLister{entities: entities}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 10 {
		t.Fatalf("expected max 10 deletes, got %d", result.Deleted)
	}
	if !result.HitLimit {
		t.Fatal("expected HitLimit=true")
	}
}
