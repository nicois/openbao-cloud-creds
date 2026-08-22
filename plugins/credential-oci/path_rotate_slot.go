package credentialoci

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) rotateSlotPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-slot/" + framework.GenericNameRegex(fieldRole) + "/" + framework.GenericNameRegex(fieldSlotIndex),
			Fields: map[string]*framework.FieldSchema{
				fieldRole: {
					Type:        framework.TypeString,
					Description: descRoleName,
				},
				fieldSlotIndex: {
					Type:        framework.TypeString,
					Description: "Index of the slot to rotate (0 or 1)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateSlot},
			},
		},
	}
}

func (b *backend) pathRotateSlot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldRole).(string)
	slotIndexStr := d.Get(fieldSlotIndex).(string)

	slotIndex, err := strconv.Atoi(slotIndexStr)
	if err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "slot_index must be an integer"), nil
	}

	// Load role
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	if entry == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrRoleNotFound, "role_not_found: role %q does not exist", roleName), nil
	}

	var role ociRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	if slotIndex < 0 || slotIndex >= role.SlotCount {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "slot_index must be between 0 and %d", role.SlotCount-1), nil
	}

	if err := b.rotateSlot(ctx, req.Storage, &role, slotIndex); err != nil {
		return credenvelope.ErrorResponse(credenvelope.Classify(credenvelope.StatusNone, err),
			"rotation failed: %v", err), nil
	}

	// Load the updated slot to return its state
	updated, err := loadSlot(ctx, req.Storage, roleName, slotIndex)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
	}
	// loadSlot reports an absent slot as (nil, nil), which happens if the role — and
	// with it every slot — is deleted between the rotation and this read. Reading
	// updated.TokenID unchecked panicked the handler (A29). The rotation itself
	// succeeded, so this is not an error the operator can act on beyond knowing the
	// slot is gone.
	if updated == nil {
		return credenvelope.ErrorResponse(credenvelope.ErrEntityUnavailable,
			"slot %d of role %q rotated, but the slot no longer exists — the role was most likely "+
				"deleted concurrently", slotIndex, roleName), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			fieldRole:          roleName,
			fieldSlotIndex:     slotIndex,
			"rotated":          true,
			"new_token_id":     updated.TokenID,
			"next_rotation_at": updated.NextRotationAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}
