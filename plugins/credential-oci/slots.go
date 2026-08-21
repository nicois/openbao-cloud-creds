package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
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
//
// MinterSet and MinterID record which minter set + minter provisioned this
// slot, so rotation and cleanup of the slot use a minter from the same set.
type slot struct {
	TokenID        string    `json:"token_id"`
	TokenValue     string    `json:"token_value"`
	RotatedAt      time.Time `json:"rotated_at"`
	NextRotationAt time.Time `json:"next_rotation_at"`
	State          slotState `json:"state"`
	SlotIndex      int       `json:"slot_index"`
	Description    string    `json:"description"`
	MinterSet      string    `json:"minter_set"`
	MinterID       string    `json:"minter_id"`
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

// freshestSlot returns the active slot with the most recent RotatedAt time that
// is not yet overdue for rotation as of now. Slots whose NextRotationAt has
// already passed are skipped: serving one would yield a TTL <= 0, violating the
// "TTL is always honest" invariant. Returns nil if no eligible slot exists.
func freshestSlot(slots []*slot, now time.Time) *slot {
	var best *slot
	for _, s := range slots {
		if s.State != slotActive {
			continue
		}
		if !s.NextRotationAt.After(now) {
			continue // overdue: TTL would be <= 0; not eligible to serve
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
	minterID, client, err := b.selectMinterForSet(role.MinterSet)
	if err != nil {
		return err
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
			MinterSet:      role.MinterSet,
			MinterID:       minterID,
		}

		if err := saveSlot(ctx, storage, role.Name, s); err != nil {
			return fmt.Errorf("failed to save slot %d: %w", i, err)
		}
	}

	return nil
}

// rotateSlot rotates a single slot: creates a new token, updates storage, deletes the old one.
//
// It holds rotateReconcileMu for the whole create+persist+delete so a reconcile
// pass cannot list+delete the freshly-created token before it is recorded in
// slot storage (audit F4). rotateReconcileMu is the outermost lock; b.mu is only
// taken-and-released inside the helper calls below, never across this body.
func (b *backend) rotateSlot(ctx context.Context, storage logical.Storage, role *ociRole, slotIndex int) error {
	b.rotateReconcileMu.Lock()
	defer b.rotateReconcileMu.Unlock()

	existing, err := loadSlot(ctx, storage, role.Name, slotIndex)
	if err != nil {
		return fmt.Errorf("failed to load slot %d: %w", slotIndex, err)
	}
	if existing == nil {
		return fmt.Errorf("slot %d does not exist for role %s", slotIndex, role.Name)
	}

	// Provision the replacement using a healthy minter from the role's bound set.
	minterID, client, err := b.selectMinterForSet(role.MinterSet)
	if err != nil {
		return err
	}

	// Create new token
	description := fmt.Sprintf("cloud-creds-%s-slot-%d", role.Name, slotIndex)
	tokenValue, tokenID, err := client.CreateAuthToken(ctx, role.UserOCID, description)
	if err != nil {
		return fmt.Errorf("failed to create replacement auth token for slot %d: %w", slotIndex, err)
	}

	now := time.Now()
	rotationInterval := role.RotationPeriod / time.Duration(role.SlotCount)

	// Update slot with new token, recording the provisioning set + minter.
	updated := &slot{
		TokenID:        tokenID,
		TokenValue:     tokenValue,
		RotatedAt:      now,
		NextRotationAt: now.Add(rotationInterval),
		State:          slotActive,
		SlotIndex:      slotIndex,
		Description:    description,
		MinterSet:      role.MinterSet,
		MinterID:       minterID,
	}

	if err := saveSlot(ctx, storage, role.Name, updated); err != nil {
		// Try to clean up the newly created token since we couldn't persist it
		_ = client.DeleteAuthToken(ctx, role.UserOCID, tokenID)
		return fmt.Errorf("failed to save rotated slot %d: %w", slotIndex, err)
	}

	// Delete old token via the minter that provisioned it (best effort — if this
	// fails, the reconciler will clean it up).
	if existing.TokenID != "" {
		oldClient := b.clientForSlot(existing, role.MinterSet)
		if oldClient != nil {
			if err := oldClient.DeleteAuthToken(ctx, role.UserOCID, existing.TokenID); err != nil {
				b.Logger().Warn("failed to delete old auth token during rotation",
					"role", role.Name,
					"slot", slotIndex,
					"old_token_id", existing.TokenID,
					"error", err,
				)
			}
		}
	}

	emitSlotRotated(role.Name, slotIndex)
	return nil
}

// selectMinterForSet returns the ID and client of a healthy minter in the named
// set. Slots for a role are always provisioned and rotated using a minter from
// the role's bound set.
func (b *backend) selectMinterForSet(setName string) (minterID string, client OCIIAMClient, err error) {
	now := time.Now()
	b.mu.RLock()
	states, ok := b.minterSets[setName]
	if !ok {
		b.mu.RUnlock()
		return "", nil, credenvelope.NewError(credenvelope.ErrConfigInvalid,
			http.StatusBadRequest, fmt.Sprintf("minter set %q is not loaded", setName))
	}
	var token string
	for id, ms := range states {
		if !ms.minter.Retired && ms.sm.Selectable(now) {
			minterID = id
			token = ms.minter.Token
			break
		}
	}
	// Gathered under the lock: the diagnosis needs the same state machines the
	// loop just consulted, and the map must not be read after unlocking.
	machines := machinesOf(states)
	b.mu.RUnlock()
	if minterID == "" {
		return "", nil, recovery.UnavailableError(setName, machines, now)
	}
	return minterID, b.newOCIClient(token), nil
}

// getMinterClient returns a client for a specific minter in a set, regardless of
// health. Used to operate on a slot via the exact minter that provisioned it.
func (b *backend) getMinterClient(setName, minterID string) OCIIAMClient {
	b.mu.RLock()
	var token string
	found := false
	if states, ok := b.minterSets[setName]; ok {
		if ms, ok := states[minterID]; ok {
			token = ms.minter.Token
			found = true
		}
	}
	b.mu.RUnlock()
	if !found {
		return nil
	}
	return b.newOCIClient(token)
}

// anyHealthyMinter returns a client for any healthy minter across all sets.
// Used by the reconciler, which lists owner-tagged tokens regardless of set.
func (b *backend) anyHealthyMinter() OCIIAMClient {
	now := time.Now()
	b.mu.RLock()
	var token string
	found := false
	for _, states := range b.minterSets {
		for _, ms := range states {
			if !ms.minter.Retired && ms.sm.Selectable(now) {
				token = ms.minter.Token
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	b.mu.RUnlock()
	if !found {
		return nil
	}
	return b.newOCIClient(token)
}

// clientForSlot returns the client to operate on the given slot's upstream
// token: the exact minter that provisioned it if still present, otherwise any
// healthy minter in the role's bound set.
func (b *backend) clientForSlot(s *slot, roleSet string) OCIIAMClient {
	if s.MinterSet != "" && s.MinterID != "" {
		if c := b.getMinterClient(s.MinterSet, s.MinterID); c != nil {
			return c
		}
	}
	_, c, err := b.selectMinterForSet(roleSet)
	if err != nil {
		return nil
	}
	return c
}
