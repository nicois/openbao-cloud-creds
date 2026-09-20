package credentialdo

import (
	"context"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Keys of the rotate report. The secret key is deliberately not among them: this is an
// operator lever, and the only place a Spaces secret is handed out is a credential read.
const (
	rotateKeyAccessKey         = "access_key"
	rotateKeyReplacedAccessKey = "replaced_access_key"
	rotateKeyReplacedDeletedAt = "replaced_deleted_at"
	rotateKeyRotateAt          = "rotate_at"
)

// rotationReasonOperator is what the rotation log says when this endpoint drove it, so the one
// rotation an operator caused is distinguishable from the schedule's.
const rotationReasonOperator = "an operator asked for it"

// sharedRotatePaths is roles/<name>/rotate: replace a rotated role's shared credential now,
// without waiting for its period.
//
// It exists because the schedule cannot be the only trigger. A suspected leak, a departing
// engineer, a compliance date — all of them are reasons to bring one rotation forward, and the
// alternative would be shortening the role's rotation_period (which changes every future
// rotation too) or revoke-upstream (which cuts every client off).
//
// The old key keeps its overlap on purpose: this is a rotation, not containment. An operator
// who needs the current credential dead now wants roles/<name>/revoke-upstream, and the help
// text says so, because a lever that half-does containment is worse than one that refuses.
func (b *backend) sharedRotatePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex(fieldName) + "/rotate",
			Fields: map[string]*framework.FieldSchema{
				fieldName: {
					Type:        framework.TypeString,
					Description: "Name of the role whose shared credential is to be replaced",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSharedSpacesRotate},
			},
			HelpSynopsis: "Replace a shared Spaces credential ahead of its schedule",
			HelpDescription: "Only for a role with credential_type=" + credentialTypeSpacesKeyRotated +
				", whose one credential is shared by every reader. A new key is minted and served " +
				"from now on; the key it replaces keeps working for the role's overlap_ttl, so " +
				"clients pick the new one up on their next read without being cut off. To end the " +
				"old credential immediately instead, use roles/<name>/revoke-upstream — it deletes " +
				"what the role has issued, which is a containment action rather than a rotation.",
		},
	}
}

func (b *backend) pathSharedSpacesRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(fieldName).(string)

	// loadRole rather than a bare storage read, unlike the purge path: rotating MINTS, so a
	// disabled role must be refused — the flag's whole job is to stop this mount acting on that
	// role's behalf upstream.
	role, errResp := b.loadRole(ctx, req, roleName)
	if errResp != nil {
		return errResp, nil
	}
	if !role.rotatesSharedKey() {
		return credenvelope.ErrorResponse(credenvelope.ErrUnsupported,
			"role %q issues %s credentials, which belong to the lease that read them: read "+
				"creds/%s for a fresh one, and let the lease end to dispose of the old",
			roleName, role.credentialType(), roleName), nil
	}

	release := b.lockSharedRole(roleName)
	defer release()

	now := time.Now()
	state, err := loadSharedSpacesState(ctx, req.Storage, roleName)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "loading the role's shared credential", err), nil
	}
	replaced := state.Current

	rotated, errResp := b.rotateSharedSpacesKey(ctx, req.Storage, rotationRequest{
		role: role, roleName: roleName, state: state, now: now, reason: rotationReasonOperator,
	})
	if errResp != nil {
		return errResp, nil
	}

	// One schema whether or not there was a key to replace: an operator scripting this reads the
	// same fields either way, and an absent key is reported as an empty name rather than by the
	// field going missing.
	data := map[string]any{
		fieldRole:                  roleName,
		rotateKeyAccessKey:         rotated.Current.AccessKey,
		rotateKeyReplacedAccessKey: "",
		rotateKeyReplacedDeletedAt: "",
		rotateKeyRotateAt:          rotated.Current.dueAt(role).UTC().Format(time.RFC3339),
	}
	if replaced != nil {
		data[rotateKeyReplacedAccessKey] = replaced.AccessKey
		// The date the clients still holding the old key have to be told, and the reason this
		// endpoint answers with a report rather than nothing at all.
		data[rotateKeyReplacedDeletedAt] = now.Add(role.OverlapTTL).UTC().Format(time.RFC3339)
	}
	return &logical.Response{Data: data}, nil
}
