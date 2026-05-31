package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

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
		return logical.ErrorResponse("slot_index must be an integer"), nil
	}

	// Load role
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("role_not_found: role %q does not exist", roleName), nil
	}

	var role ociRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if slotIndex < 0 || slotIndex >= role.SlotCount {
		return logical.ErrorResponse("slot_index must be between 0 and %d", role.SlotCount-1), nil
	}

	if err := b.rotateSlot(ctx, req.Storage, &role, slotIndex); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("rotation failed: %v", err)), nil
	}

	// Load the updated slot to return its state
	updated, err := loadSlot(ctx, req.Storage, roleName, slotIndex)
	if err != nil {
		return nil, err
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
