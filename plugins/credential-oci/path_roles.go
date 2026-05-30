package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ociRole stores the configuration for a single OCI credential role.
type ociRole struct {
	Name           string        `json:"name"`
	UserOCID       string        `json:"user_ocid"`
	SlotCount      int           `json:"slot_count"`
	RotationPeriod time.Duration `json:"rotation_period"`
	DefaultTTL     time.Duration `json:"default_ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	MinterSet      string        `json:"minter_set"`
	Disabled       bool          `json:"disabled,omitempty"`
}

const (
	defaultSlotCount      = 2
	maxSlotCount          = 2
	defaultRotationPeriod = 7 * 24 * time.Hour // 7 days
)

func (b *backend) rolePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				"user_ocid": {
					Type:        framework.TypeString,
					Description: "OCI user OCID to manage auth tokens for",
				},
				"slot_count": {
					Type:        framework.TypeInt,
					Default:     defaultSlotCount,
					Description: "Number of credential slots (max 2 for OCI auth tokens)",
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Default:     int(defaultRotationPeriod.Seconds()),
					Description: "Total rotation period T (default 7d). Each slot rotates every T/slot_count.",
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     int((defaultRotationPeriod / 2).Seconds()),
					Description: "Default lease TTL returned to clients. Must be <= rotation_period/slot_count.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     int(defaultRotationPeriod.Seconds()),
					Description: "Maximum lease TTL",
				},
				"minter_set": {
					Type:        framework.TypeString,
					Description: "Name of the minter set used to provision and rotate this role's slots (required)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
		},
	}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	userOCID := d.Get("user_ocid").(string)
	slotCount := d.Get("slot_count").(int)
	rotationPeriod := time.Duration(d.Get("rotation_period").(int)) * time.Second
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second

	if userOCID == "" {
		return logical.ErrorResponse("user_ocid is required"), nil
	}

	minterSet := d.Get("minter_set").(string)
	if minterSet == "" {
		return logical.ErrorResponse("minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("minter_set %q does not exist", minterSet), nil
	}

	if slotCount < 1 || slotCount > maxSlotCount {
		return logical.ErrorResponse("slot_count must be between 1 and %d", maxSlotCount), nil
	}

	// Validate rotation period is reasonable
	if rotationPeriod < 1*time.Hour {
		return logical.ErrorResponse("rotation_period must be at least 1 hour"), nil
	}

	// Validate default_ttl <= rotation_period / slot_count
	rotationInterval := rotationPeriod / time.Duration(slotCount)
	if defaultTTL > rotationInterval {
		return logical.ErrorResponse(
			"default_ttl (%v) must be <= rotation_period/slot_count (%v)",
			defaultTTL, rotationInterval), nil
	}

	// Use the shared role validator for basic TTL checks
	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      "oci",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			"user_ocid":       userOCID,
			"slot_count":      slotCount,
			"rotation_period": rotationPeriod.String(),
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	ociR := &ociRole{
		Name:           name,
		UserOCID:       userOCID,
		SlotCount:      slotCount,
		RotationPeriod: rotationPeriod,
		DefaultTTL:     defaultTTL,
		MaxTTL:         maxTTL,
		MinterSet:      minterSet,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, ociR)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Initialize slots if they don't exist yet and the role's bound set has a
	// healthy minter to provision with.
	if _, _, selErr := b.selectMinterForSet(minterSet); selErr == nil {
		existingSlots, err := loadAllSlots(ctx, req.Storage, name, slotCount)
		if err != nil {
			return nil, fmt.Errorf("failed to check existing slots: %w", err)
		}
		if len(existingSlots) == 0 {
			if err := b.initializeSlots(ctx, req.Storage, ociR); err != nil {
				return logical.ErrorResponse("role saved but slot initialization failed: %v", err), nil
			}
		}
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role ociRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	// Load slot status
	slots, _ := loadAllSlots(ctx, req.Storage, name, role.SlotCount)
	slotStatus := make([]map[string]interface{}, 0, len(slots))
	for _, s := range slots {
		slotStatus = append(slotStatus, map[string]interface{}{
			"slot_index":       s.SlotIndex,
			"state":            string(s.State),
			"rotated_at":       s.RotatedAt.UTC().Format(time.RFC3339),
			"next_rotation_at": s.NextRotationAt.UTC().Format(time.RFC3339),
			"token_id":         s.TokenID,
		})
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":            role.Name,
			"user_ocid":       role.UserOCID,
			"slot_count":      role.SlotCount,
			"rotation_period": int(role.RotationPeriod.Seconds()),
			"default_ttl":     int(role.DefaultTTL.Seconds()),
			"max_ttl":         int(role.MaxTTL.Seconds()),
			"minter_set":      role.MinterSet,
			"disabled":        role.Disabled,
			"slots":           slotStatus,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Load role to get slot count for cleanup
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var role ociRole
		if err := json.Unmarshal(entry.Value, &role); err == nil {
			// Clean up slots — delete each upstream token via the minter that
			// provisioned it (recorded provenance), falling back to any healthy
			// minter in the role's bound set.
			slots, _ := loadAllSlots(ctx, req.Storage, name, role.SlotCount)
			for _, s := range slots {
				if s.TokenID == "" {
					continue
				}
				client := b.clientForSlot(s, role.MinterSet)
				if client != nil {
					_ = client.DeleteAuthToken(ctx, role.UserOCID, s.TokenID)
				}
			}
			// Remove slot storage
			_ = deleteSlots(ctx, req.Storage, name, role.SlotCount)
		}
	}

	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}
