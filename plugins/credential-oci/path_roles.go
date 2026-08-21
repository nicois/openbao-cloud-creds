package credentialoci

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
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
			Pattern: "roles/" + framework.GenericNameRegex(fieldName),
			Fields: map[string]*framework.FieldSchema{
				fieldName: {
					Type:        framework.TypeString,
					Description: descRoleName,
				},
				fieldUserOCID: {
					Type:        framework.TypeString,
					Description: "OCI user OCID to manage auth tokens for",
				},
				fieldSlotCount: {
					Type:        framework.TypeInt,
					Default:     defaultSlotCount,
					Description: "Number of credential slots (max 2 for OCI auth tokens)",
				},
				fieldRotation: {
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
				fieldMinterSet: {
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
	name := d.Get(fieldName).(string)
	userOCID := d.Get(fieldUserOCID).(string)
	slotCount := d.Get(fieldSlotCount).(int)
	rotationPeriod := time.Duration(d.Get(fieldRotation).(int)) * time.Second
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	minterSet := d.Get(fieldMinterSet).(string)

	if errResp, err := b.validateRoleWriteParams(ctx, req, roleWriteParams{
		userOCID:       userOCID,
		minterSet:      minterSet,
		slotCount:      slotCount,
		rotationPeriod: rotationPeriod,
		defaultTTL:     defaultTTL,
	}); errResp != nil || err != nil {
		return errResp, err
	}

	// Use the shared role validator for basic TTL checks
	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			fieldUserOCID:  userOCID,
			fieldSlotCount: slotCount,
			fieldRotation:  rotationPeriod.String(),
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
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

	// Prove the bound set's minters can actually mint what this role asks for,
	// so an unsuitable minting key is reported to whoever wrote the role rather
	// than to the first caller that reads credentials from it.
	if errResp := b.verifyRoleCapability(ctx, req.Storage, ociR); errResp != nil {
		return errResp, nil
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
	return b.maybeInitializeSlots(ctx, req, ociR)
}

// roleWriteParams bundles the role-write fields that need cross-field validation.
type roleWriteParams struct {
	userOCID       string
	minterSet      string
	slotCount      int
	rotationPeriod time.Duration
	defaultTTL     time.Duration
}

// validateRoleWriteParams performs the role-write input validation in the same
// order as the original inline checks. It returns a non-nil *logical.Response
// for a client-facing validation error, or a non-nil error for a storage
// failure; both nil means the parameters are valid.
func (b *backend) validateRoleWriteParams(ctx context.Context, req *logical.Request, p roleWriteParams) (*logical.Response, error) {
	if p.userOCID == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "user_ocid is required"), nil
	}

	if p.minterSet == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, p.minterSet)
	if err != nil {
		return nil, err
	}
	if !exists {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set %q does not exist", p.minterSet), nil
	}

	if p.slotCount < 1 || p.slotCount > maxSlotCount {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "slot_count must be between 1 and %d", maxSlotCount), nil
	}

	// Validate rotation period is reasonable
	if p.rotationPeriod < 1*time.Hour {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "rotation_period must be at least 1 hour"), nil
	}

	// Validate default_ttl <= rotation_period / slot_count
	rotationInterval := p.rotationPeriod / time.Duration(p.slotCount)
	if p.defaultTTL > rotationInterval {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"default_ttl (%v) must be <= rotation_period/slot_count (%v)",
			p.defaultTTL, rotationInterval), nil
	}

	return nil, nil
}

// maybeInitializeSlots provisions slots for a freshly written role when its
// bound set has a healthy minter and no slots exist yet.
func (b *backend) maybeInitializeSlots(ctx context.Context, req *logical.Request, ociR *ociRole) (*logical.Response, error) {
	if _, _, selErr := b.selectMinterForSet(ociR.MinterSet); selErr != nil {
		return nil, nil
	}
	existingSlots, err := loadAllSlots(ctx, req.Storage, ociR.Name, ociR.SlotCount)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing slots: %w", err)
	}
	if len(existingSlots) != 0 {
		return nil, nil
	}
	if err := b.initializeSlots(ctx, req.Storage, ociR); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrInternal, "role saved but slot initialization failed: %v", err), nil
	}
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
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
			fieldSlotIndex:     s.SlotIndex,
			"state":            string(s.State),
			"rotated_at":       s.RotatedAt.UTC().Format(time.RFC3339),
			"next_rotation_at": s.NextRotationAt.UTC().Format(time.RFC3339),
			"token_id":         s.TokenID,
		})
	}

	return &logical.Response{
		Data: map[string]interface{}{
			fieldName:      role.Name,
			fieldUserOCID:  role.UserOCID,
			fieldSlotCount: role.SlotCount,
			fieldRotation:  int(role.RotationPeriod.Seconds()),
			"default_ttl":  int(role.DefaultTTL.Seconds()),
			"max_ttl":      int(role.MaxTTL.Seconds()),
			fieldMinterSet: role.MinterSet,
			"disabled":     role.Disabled,
			"slots":        slotStatus,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)

	// Load role to get slot count for cleanup
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var role ociRole
		if err := json.Unmarshal(entry.Value, &role); err == nil {
			b.cleanupRoleSlots(ctx, req.Storage, name, &role)
		}
	}

	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

// cleanupRoleSlots deletes each slot's upstream token via the minter that
// provisioned it (recorded provenance), falling back to any healthy minter in
// the role's bound set, then removes the slot storage. Best-effort: upstream
// delete failures are ignored, matching the original inline behavior.
func (b *backend) cleanupRoleSlots(ctx context.Context, storage logical.Storage, name string, role *ociRole) {
	slots, _ := loadAllSlots(ctx, storage, name, role.SlotCount)
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
	_ = deleteSlots(ctx, storage, name, role.SlotCount)
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}
