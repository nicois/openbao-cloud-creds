package credentialoci

import (
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// An overdue slot is not served as TTL=0; with no other active slot the read
// returns pool_exhausted rather than serving a TTL=0 lease (audit2 #6).
func TestCredsRead_OverdueSlotNotServed(t *testing.T) {
	b, storage, _ := newInternalConfiguredBackend(t)

	role, ok := loadRole(t.Context(), storage, "test-role")
	if !ok {
		t.Fatal("test-role not found after setup")
	}

	// Force ALL slots overdue.
	for i := 0; i < role.SlotCount; i++ {
		s, err := loadSlot(t.Context(), storage, "test-role", i)
		if err != nil || s == nil {
			continue
		}
		s.NextRotationAt = time.Now().Add(-time.Hour)
		if err := saveSlot(t.Context(), storage, "test-role", s); err != nil {
			t.Fatalf("saveSlot(%d): %v", i, err)
		}
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected pool_exhausted error response, got %v", resp)
	}
}

// One overdue + one fresh slot → fresh slot served with positive TTL.
func TestCredsRead_FreshSlotServedWhenAnotherOverdue(t *testing.T) {
	b, storage, _ := newInternalConfiguredBackend(t)

	s0, err := loadSlot(t.Context(), storage, "test-role", 0)
	if err != nil || s0 == nil {
		t.Fatalf("loadSlot(0): err=%v slot=%v", err, s0)
	}
	s0.NextRotationAt = time.Now().Add(-time.Hour)
	if err := saveSlot(t.Context(), storage, "test-role", s0); err != nil {
		t.Fatalf("saveSlot(0): %v", err)
	}

	s1, err := loadSlot(t.Context(), storage, "test-role", 1)
	if err != nil || s1 == nil {
		t.Fatalf("loadSlot(1): err=%v slot=%v", err, s1)
	}
	s1.NextRotationAt = time.Now().Add(time.Hour)
	s1.RotatedAt = time.Now() // make slot 1 freshest
	if err := saveSlot(t.Context(), storage, "test-role", s1); err != nil {
		t.Fatalf("saveSlot(1): %v", err)
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/test-role", Storage: storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected served credential, got %v", resp)
	}
	if resp.Secret == nil || resp.Secret.TTL <= 0 {
		t.Fatalf("expected positive TTL, got %v", resp.Secret)
	}
}
