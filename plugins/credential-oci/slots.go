package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// slotState represents the lifecycle state of a credential slot.
type slotState string

const (
	slotActive   slotState = "active"
	slotRetiring slotState = "retiring"
	slotRetired  slotState = "retired"
	slotEmpty    slotState = "empty"
)

// slot represents a single credential slot in phased rotation.
type slot struct {
	TokenID        string    `json:"token_id"`
	TokenValue     string    `json:"token_value"`
	RotatedAt      time.Time `json:"rotated_at"`
	NextRotationAt time.Time `json:"next_rotation_at"`
	State          slotState `json:"state"`
	SlotIndex      int       `json:"slot_index"`
	Description    string    `json:"description"`
}

// storageKeyForSlot returns the storage key for a slot.
func storageKeyForSlot(roleName string, slotIndex int) string {
	return fmt.Sprintf("slots/%s/%d", roleName, slotIndex)
}

// loadSlot loads a slot from storage.
func loadSlot(ctx context.Context, storage logical.Storage, roleName string, slotIndex int) (*slot, error) {
	entry, err := storage.Get(ctx, storageKeyForSlot(roleName, slotIndex))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var s slot
	if err := json.Unmarshal(entry.Value, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// saveSlot persists a slot to storage.
func saveSlot(ctx context.Context, storage logical.Storage, roleName string, s *slot) error {
	entry, err := logical.StorageEntryJSON(storageKeyForSlot(roleName, s.SlotIndex), s)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// loadAllSlots loads all slots for a role.
func loadAllSlots(ctx context.Context, storage logical.Storage, roleName string, slotCount int) ([]*slot, error) {
	slots := make([]*slot, 0, slotCount)
	for i := 0; i < slotCount; i++ {
		s, err := loadSlot(ctx, storage, roleName, i)
		if err != nil {
			return nil, err
		}
		if s != nil {
			slots = append(slots, s)
		}
	}
	return slots, nil
}

// deleteSlots removes all slot data for a role from storage.
func deleteSlots(ctx context.Context, storage logical.Storage, roleName string, slotCount int) error {
	for i := 0; i < slotCount; i++ {
		if err := storage.Delete(ctx, storageKeyForSlot(roleName, i)); err != nil {
			return err
		}
	}
	return nil
}

// freshestSlot returns the slot with the most recent RotatedAt time.
// Returns nil if no active slots exist.
func freshestSlot(slots []*slot) *slot {
	var best *slot
	for _, s := range slots {
		if s.State != slotActive {
			continue
		}
		if best == nil || s.RotatedAt.After(best.RotatedAt) {
			best = s
		}
	}
	return best
}

// initializeSlots provisions the initial credential slots for a role.
// This is called on first role write when slots don't exist yet.
func (b *backend) initializeSlots(ctx context.Context, storage logical.Storage, role *ociRole) error {
	client := b.getClient()
	if client == nil {
		return fmt.Errorf("OCI client not configured")
	}

	now := time.Now()
	rotationInterval := role.RotationPeriod / time.Duration(role.SlotCount)

	for i := 0; i < role.SlotCount; i++ {
		description := fmt.Sprintf("cloud-creds-%s-slot-%d", role.Name, i)

		tokenValue, tokenID, err := client.CreateAuthToken(ctx, role.UserOCID, description)
		if err != nil {
			return fmt.Errorf("failed to create auth token for slot %d: %w", i, err)
		}

		// Stagger the initial rotation times so slots don't all rotate at once.
		// Slot 0 rotates at now + rotationInterval, slot 1 at now + 2*rotationInterval, etc.
		nextRotation := now.Add(rotationInterval * time.Duration(i+1))

		s := &slot{
			TokenID:        tokenID,
			TokenValue:     tokenValue,
			RotatedAt:      now,
			NextRotationAt: nextRotation,
			State:          slotActive,
			SlotIndex:      i,
			Description:    description,
		}

		if err := saveSlot(ctx, storage, role.Name, s); err != nil {
			return fmt.Errorf("failed to save slot %d: %w", i, err)
		}
	}

	return nil
}

// rotateSlot rotates a single slot: creates a new token, updates storage, deletes the old one.
func (b *backend) rotateSlot(ctx context.Context, storage logical.Storage, role *ociRole, slotIndex int) error {
	client := b.getClient()
	if client == nil {
		return fmt.Errorf("OCI client not configured")
	}

	existing, err := loadSlot(ctx, storage, role.Name, slotIndex)
	if err != nil {
		return fmt.Errorf("failed to load slot %d: %w", slotIndex, err)
	}
	if existing == nil {
		return fmt.Errorf("slot %d does not exist for role %s", slotIndex, role.Name)
	}

	// Create new token
	description := fmt.Sprintf("cloud-creds-%s-slot-%d", role.Name, slotIndex)
	tokenValue, tokenID, err := client.CreateAuthToken(ctx, role.UserOCID, description)
	if err != nil {
		return fmt.Errorf("failed to create replacement auth token for slot %d: %w", slotIndex, err)
	}

	now := time.Now()
	rotationInterval := role.RotationPeriod / time.Duration(role.SlotCount)

	// Update slot with new token
	updated := &slot{
		TokenID:        tokenID,
		TokenValue:     tokenValue,
		RotatedAt:      now,
		NextRotationAt: now.Add(rotationInterval),
		State:          slotActive,
		SlotIndex:      slotIndex,
		Description:    description,
	}

	if err := saveSlot(ctx, storage, role.Name, updated); err != nil {
		// Try to clean up the newly created token since we couldn't persist it
		_ = client.DeleteAuthToken(ctx, role.UserOCID, tokenID)
		return fmt.Errorf("failed to save rotated slot %d: %w", slotIndex, err)
	}

	// Delete old token (best effort — if this fails, the reconciler will clean it up)
	if existing.TokenID != "" {
		if err := client.DeleteAuthToken(ctx, role.UserOCID, existing.TokenID); err != nil {
			b.Logger().Warn("failed to delete old auth token during rotation",
				"role", role.Name,
				"slot", slotIndex,
				"old_token_id", existing.TokenID,
				"error", err,
			)
		}
	}

	emitSlotRotated(role.Name, slotIndex)
	return nil
}
