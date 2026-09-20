package credentialdo

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/requester"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Role TTL schema defaults, in seconds (framework.TypeDurationSecond).
	defaultRoleTTLSeconds    = 900  // 15m
	defaultRoleMaxTTLSeconds = 3600 // 1h

	// minRotationPeriod is the shortest rotation a shared Spaces key may be given. The
	// floor exists because rotation is create-then-delete against a per-account cap of
	// 200 keys: a period near the sweep cadence would keep replacing a key nobody had
	// finished fetching. Matches OCI's floor, which is the same trade.
	minRotationPeriod = time.Hour
	// rotationJitterDivisor gives the default jitter as a fraction of the period (a
	// tenth). A default rather than zero because the failure it prevents — every role on
	// an account rotating in the same minute after a coordinated first read — is one an
	// operator would not think to ask for.
	rotationJitterDivisor = 10
)

type doRole struct {
	Name       string        `json:"name"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
	Scopes     []string      `json:"scopes"`
	MinterSet  string        `json:"minter_set"`
	Disabled   bool          `json:"disabled,omitempty"`

	// RequireCallerIdentity is how much of a caller's identity this role insists on before
	// it will hand over a credential. Empty is requester.RequireNone, so a role written
	// before the field existed keeps issuing exactly what it issued.
	RequireCallerIdentity string `json:"require_caller_identity,omitempty"`

	// CredentialType selects which of this cloud's two credential shapes the role
	// issues. Empty means credentialTypeToken: roles written before this field existed
	// must keep issuing what they issued before, so the zero value has to be the old
	// behaviour rather than an error.
	CredentialType string `json:"credential_type,omitempty"`
	// Grants, Region and Endpoint belong to credentialTypeSpacesKey and are empty
	// otherwise. Grants are stored in DigitalOcean's WIRE form (an empty bucket means
	// account-wide); renderGrants converts back for anything a human or client reads.
	Grants   []spacesGrant `json:"grants,omitempty"`
	Region   string        `json:"region,omitempty"`
	Endpoint string        `json:"endpoint,omitempty"`

	// RotationPeriod, RotationJitter and OverlapTTL belong to
	// credentialTypeSpacesKeyRotated and are zero otherwise. They describe ONE
	// credential's life rather than a lease's: the key is replaced once it reaches
	// RotationPeriod (less a jitter rolled at mint), and the key it replaces is deleted
	// OverlapTTL later, which is the grace a client that already holds it gets.
	RotationPeriod time.Duration `json:"rotation_period,omitempty"`
	RotationJitter time.Duration `json:"rotation_jitter,omitempty"`
	OverlapTTL     time.Duration `json:"overlap_ttl,omitempty"`
}

// credentialType returns the role's credential type, defaulting a role stored before the
// field existed to the token shape.
func (r *doRole) credentialType() string {
	if r.CredentialType == "" {
		return credentialTypeToken
	}
	return r.CredentialType
}

// issuesSpacesKey reports whether this role's credential is an S3-compatible Spaces access
// key rather than a personal access token.
//
// True for BOTH Spaces types, deliberately: they differ in lifecycle, not in the upstream
// call, the delete, the owner tag or the account's 200-key cap. Everything that follows
// from "this is a Spaces key" — the capability probe's mint shape, the tracking prefix, the
// reconciler class, the capacity count — must therefore see them as one, or a rotated key
// would be invisible to the counter that decides whether a minter is full.
func (r *doRole) issuesSpacesKey() bool {
	switch r.credentialType() {
	case credentialTypeSpacesKey, credentialTypeSpacesKeyRotated:
		return true
	default:
		return false
	}
}

// rotatesSharedKey reports whether the role serves ONE key to every reader and rotates it
// on a schedule, rather than minting a key per lease. This is the predicate for everything
// that differs: the secret type, the read path, the soft revoke and the sweeper.
func (r *doRole) rotatesSharedKey() bool {
	return r.credentialType() == credentialTypeSpacesKeyRotated
}

// roleFields is the role's schema. Lifted out of rolePaths because the descriptions ARE the
// documentation an operator reads at `bao path-help`, and three credential types' worth of them
// is most of the file otherwise.
func roleFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		fieldName: {
			Type:        framework.TypeString,
			Description: "Name of the role",
		},
		"default_ttl": {
			Type:        framework.TypeDurationSecond,
			Default:     defaultRoleTTLSeconds,
			Description: "Default lease TTL",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Default:     defaultRoleMaxTTLSeconds,
			Description: "Maximum lease TTL",
		},
		fieldCredentialType: {
			Type:    framework.TypeString,
			Default: credentialTypeToken,
			Description: "Which credential shape and lifecycle this role issues: " +
				credentialTypeToken + " (a personal access token; see KI-009 — this " +
				"cannot be minted against real DigitalOcean), " + credentialTypeSpacesKey +
				" (an S3-compatible Spaces access key per lease, deleted when the lease " +
				"ends) or " + credentialTypeSpacesKeyRotated + " (one Spaces access key " +
				"per role, served to every reader and rotated on a schedule). Defaults to " +
				credentialTypeToken,
		},
		fieldScopes: {
			Type: framework.TypeCommaStringSlice,
			Description: "DigitalOcean token scopes, e.g. droplet:create (required for a " +
				credentialTypeToken + " role; they are its privilege boundary, so there is " +
				"no default). Not accepted on a " + credentialTypeSpacesKey + " role",
		},
		fieldMinterSet: {
			Type:        framework.TypeString,
			Description: "Name of the minter set this role mints from (required)",
		},
		fieldDisabled: {
			Type: framework.TypeBool,
			Description: "When true the role issues nothing, answering role_disabled. This is " +
				"the lever for a suspected credential leak: deleting the role stops nothing, " +
				"because live leases stay renewable and issued credentials keep working. " +
				"Writing it alone is enough — a write to an existing role changes only the " +
				"fields it carries. Reversible; it destroys nothing already issued (see " +
				"roles/<name>/revoke-upstream for that)",
		},
		fieldRequireCallerIdentity: {
			Type:        framework.TypeString,
			Description: requester.RoleFieldDescription(),
		},
	}
	maps.Copy(fields, spacesRoleFields())
	maps.Copy(fields, rotationRoleFields())
	return fields
}

// spacesRoleFields describe the credential SHAPE both Spaces types share: which buckets the key
// may touch, and where an S3 client should send it.
func spacesRoleFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		fieldGrants: {
			Type: framework.TypeCommaStringSlice,
			Description: "Per-bucket Spaces grants as bucket:permission, e.g. " +
				"backups:read,archive:readwrite (required for a " + credentialTypeSpacesKey +
				" role). Permissions are " + permissionRead + ", " + permissionReadWrite +
				" and " + permissionFullAccess + "; " + permissionFullAccess + " is " +
				"account-wide and must be written as " + grantAllBuckets + grantSeparator +
				permissionFullAccess + " alone. Not accepted on a " + credentialTypeToken +
				" role",
		},
		fieldRegion: {
			Type: framework.TypeString,
			Description: "Spaces region, e.g. nyc3 (required for a " + credentialTypeSpacesKey +
				" role: it is what the endpoint is derived from, and an S3 client cannot be " +
				"constructed without it). Not accepted on a " + credentialTypeToken + " role",
		},
		fieldEndpoint: {
			Type: framework.TypeString,
			Description: "Optional: overrides the S3 endpoint otherwise derived from the " +
				"region. Not accepted on a " + credentialTypeToken + " role",
		},
	}
}

// rotationRoleFields describe the LIFECYCLE only the rotated type has: how long its one key is
// served, and how long the key it replaces keeps working.
func rotationRoleFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		fieldRotationPeriod: {
			Type: framework.TypeDurationSecond,
			Description: "How long a shared Spaces key is served before it is replaced, " +
				"e.g. 2160h for 90 days (required for a " + credentialTypeSpacesKeyRotated +
				" role, minimum 1h). A ceiling, not a target: the jitter is subtracted from " +
				"it, so the key is never served for longer than this. Not accepted on the " +
				"other credential types",
		},
		fieldRotationJitter: {
			Type: framework.TypeDurationSecond,
			Description: "How much earlier than " + fieldRotationPeriod + " a rotation may " +
				"fall. Rolled once when the key is minted and subtracted, so rotations across " +
				"roles and mounts spread out instead of landing together. Defaults to a tenth " +
				"of the period; 0 makes the rotation date predictable. Not accepted on the " +
				"other credential types",
		},
		fieldOverlapTTL: {
			Type: framework.TypeDurationSecond,
			Description: "How long a replaced Spaces key stays live after it is replaced, " +
				"e.g. 48h (required for a " + credentialTypeSpacesKeyRotated + " role). This " +
				"is the grace a client holding the old key gets before it stops working, and " +
				"it is the ceiling on this role's max_ttl, because no lease may outlive its " +
				"credential. Not accepted on the other credential types",
		},
	}
}

func (b *backend) rolePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields:  roleFields(),
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
	// A write to an existing role changes the fields it carries and leaves the rest as
	// they were, so `disabled=true` on its own is a complete request.
	if err := cloudconfig.PrefillRoleWrite(ctx, req.Storage, "roles/"+name, d, storedRoleData); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	scopes := d.Get(fieldScopes).([]string)

	typed, errResp := parseCredentialTypeFields(d, scopes, maxTTL)
	if errResp != nil {
		return errResp, nil
	}

	minterSet := d.Get(fieldMinterSet).(string)
	if minterSet == "" {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set is required"), nil
	}
	exists, err := b.minterSetExists(ctx, req.Storage, minterSet)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "a storage operation", err), nil
	}
	if !exists {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "minter_set %q does not exist", minterSet), nil
	}

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      cloudName,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]any{
			fieldScopes: scopes,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	// Refused HERE rather than at issuance: a value this binary cannot parse fails closed, so
	// storing it would turn every later read of the role into a refusal, far from the write
	// that got it wrong.
	requireCallerIdentity := d.Get(fieldRequireCallerIdentity).(string)
	if _, err := requester.ParseRequirement(requireCallerIdentity); err != nil {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error()), nil
	}

	doR := &doRole{
		Name:                  name,
		DefaultTTL:            defaultTTL,
		MaxTTL:                maxTTL,
		Scopes:                scopes,
		MinterSet:             minterSet,
		Disabled:              d.Get(fieldDisabled).(bool),
		RequireCallerIdentity: requireCallerIdentity,
		CredentialType:        typed.credentialType,
		Grants:                typed.grants,
		Region:                typed.region,
		Endpoint:              typed.endpoint,
		RotationPeriod:        typed.rotationPeriod,
		RotationJitter:        typed.rotationJitter,
		OverlapTTL:            typed.overlapTTL,
	}

	// Prove the bound set's minters can actually mint what this role asks for
	// before persisting it, so an unsuitable pairing is rejected here rather than
	// at the first credential read (see capability.go).
	if errResp := b.verifyRoleCapability(ctx, req.Storage, doR); errResp != nil {
		return errResp, nil
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, doR)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "encoding an entry for storage", err), nil
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "writing to storage", err), nil
	}

	return nil, nil
}

// parseCredentialTypeFields validates the fields that depend on which credential type a
// role issues, and returns them normalised. Exactly one of the two field groups may be
// present.
//
// A field belonging to the OTHER credential type is refused rather than ignored. Silently
// dropping `scopes` from a Spaces role would let an operator believe they had narrowed a
// credential they had not — and the ignored-field failure mode is the one that survives
// review, because the role reads correctly.
func parseCredentialTypeFields(d *framework.FieldData, scopes []string, maxTTL time.Duration) (credentialTypeFields, *logical.Response) {
	w := roleWriteFields{
		credentialType: d.Get(fieldCredentialType).(string),
		scopes:         scopes,
		maxTTL:         maxTTL,
		grantSpecs:     d.Get(fieldGrants).([]string),
		region:         d.Get(fieldRegion).(string),
		endpoint:       d.Get(fieldEndpoint).(string),
		life:           readLifecycleFields(d),
	}
	if w.credentialType == "" {
		w.credentialType = credentialTypeToken
	}

	switch w.credentialType {
	case credentialTypeToken:
		return w.parseToken()
	case credentialTypeSpacesKey, credentialTypeSpacesKeyRotated:
		return w.parseSpaces()
	default:
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s %q is not a credential shape this cloud issues; expected %s, %s or %s",
			fieldCredentialType, w.credentialType,
			credentialTypeToken, credentialTypeSpacesKey, credentialTypeSpacesKeyRotated)
	}
}

// roleWriteFields is one role write's type-dependent input, read off the request before
// anything has been decided about it, together with the max_ttl a lifecycle has to be checked
// against. Grouped so each type's parser takes no arguments at all and cannot be handed one
// field from this write and another from somewhere else.
type roleWriteFields struct {
	credentialType string
	scopes         []string
	maxTTL         time.Duration
	grantSpecs     []string
	region         string
	endpoint       string
	life           lifecycleFields
}

// spacesOwned names the fields that describe the Spaces credential's shape, for the refusal a
// token role carrying one gets. Derived from the same values the Spaces parser validates, so a
// field cannot be accepted in one place and reported as foreign in another.
func (w roleWriteFields) spacesOwned() []foreignField {
	return []foreignField{
		{fieldGrants, len(w.grantSpecs) > 0, credentialTypeSpacesKey},
		{fieldRegion, w.region != "", credentialTypeSpacesKey},
		{fieldEndpoint, w.endpoint != "", credentialTypeSpacesKey},
	}
}

// lifecycleOwned names the fields only the rotated type honours. Refused for BOTH other types:
// the token type has no Spaces key to rotate, and the per-lease Spaces type's credential lives
// exactly as long as its lease.
func (w roleWriteFields) lifecycleOwned() []foreignField {
	return []foreignField{
		{fieldRotationPeriod, w.life.periodSet, credentialTypeSpacesKeyRotated},
		{fieldRotationJitter, w.life.jitterSet, credentialTypeSpacesKeyRotated},
		{fieldOverlapTTL, w.life.overlapSet, credentialTypeSpacesKeyRotated},
	}
}

func (w roleWriteFields) parseToken() (credentialTypeFields, *logical.Response) {
	// DO scopes are the only privilege control this plugin has over a token, so a role
	// with none would issue a token that can do nothing — and "no opinion about
	// privilege" must not quietly mean that either (A28).
	if len(w.scopes) == 0 {
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s is required for a %s role", fieldScopes, credentialTypeToken)
	}
	if errResp := refuseForeignFields(credentialTypeToken,
		slices.Concat(w.spacesOwned(), w.lifecycleOwned())); errResp != nil {
		return credentialTypeFields{}, errResp
	}
	return credentialTypeFields{credentialType: credentialTypeToken}, nil
}

// parseSpaces validates both Spaces types together, because the credential they describe is the
// same one: the same grants, the same region, the same endpoint, the same account cap. The only
// difference is what happens to it after it is minted, which is the lifecycle block at the end.
func (w roleWriteFields) parseSpaces() (credentialTypeFields, *logical.Response) {
	if len(w.scopes) > 0 {
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s belongs to a %s role, not a %s one; a Spaces key's privilege is its %s",
			fieldScopes, credentialTypeToken, w.credentialType, fieldGrants)
	}
	// Accepting a lifecycle field on the per-lease type would describe a rotation that never
	// happens.
	if w.credentialType == credentialTypeSpacesKey {
		if errResp := refuseForeignFields(credentialTypeSpacesKey, w.lifecycleOwned()); errResp != nil {
			return credentialTypeFields{}, errResp
		}
	}
	parsed, err := parseGrants(w.grantSpecs)
	if err != nil {
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, "%s", err.Error())
	}
	// Without a region there is no endpoint, and without an endpoint the credential
	// cannot be used at all — so an unset region is a broken role, not a default. No
	// region is guessed, for the same reason no TTL floor is invented: a wrong one
	// yields a credential that authenticates and addresses the wrong datacentre.
	if w.region == "" {
		return credentialTypeFields{}, credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s is required for a %s role: it is what the S3 endpoint is derived from "+
				"(e.g. nyc3), and a client cannot construct an S3 session without it",
			fieldRegion, w.credentialType)
	}
	endpoint := w.endpoint
	if endpoint == "" {
		endpoint = spacesEndpointForRegion(w.region)
	}
	fields := credentialTypeFields{
		credentialType: w.credentialType,
		grants:         parsed,
		region:         w.region,
		endpoint:       endpoint,
	}
	if w.credentialType == credentialTypeSpacesKeyRotated {
		if errResp := w.life.apply(&fields, w.maxTTL); errResp != nil {
			return credentialTypeFields{}, errResp
		}
	}
	return fields, nil
}

// foreignField names a field, whether this write carried it, and which credential type owns
// it — everything the refusal has to say for an operator to fix the role in one attempt.
type foreignField struct {
	name  string
	set   bool
	owner string
}

// refuseForeignFields rejects a field belonging to a credential type other than the one
// being written, rather than ignoring it. Silently dropping `scopes` from a Spaces role
// would let an operator believe they had narrowed a credential they had not — and the
// ignored-field failure mode is the one that survives review, because the role reads
// correctly afterwards.
func refuseForeignFields(credentialType string, fields []foreignField) *logical.Response {
	for _, f := range fields {
		if !f.set {
			continue
		}
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s belongs to a %s role, not a %s one; set %s=%s or drop %s",
			f.name, f.owner, credentialType, fieldCredentialType, f.owner, f.name)
	}
	return nil
}

// lifecycleFields is the rotated type's three durations as the request stated them. Each
// carries whether it was stated at all, because zero and unstated differ: an explicit zero
// jitter is an operator asking for a predictable rotation date, while an unstated one takes
// the default.
type lifecycleFields struct {
	period, jitter, overlap          time.Duration
	periodSet, jitterSet, overlapSet bool
}

func readLifecycleFields(d *framework.FieldData) lifecycleFields {
	read := func(field string) (time.Duration, bool) {
		raw, ok := d.GetOk(field)
		if !ok {
			return 0, false
		}
		seconds, ok := raw.(int)
		if !ok {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	var l lifecycleFields
	l.period, l.periodSet = read(fieldRotationPeriod)
	l.jitter, l.jitterSet = read(fieldRotationJitter)
	l.overlap, l.overlapSet = read(fieldOverlapTTL)
	return l
}

// apply validates the lifecycle a rotated role asks for and writes it into fields.
//
// The rules are all one invariant seen from different sides: at any moment the served key's
// remaining life is at least overlap_ttl, because the worst case is the instant it rotates.
// So a max_ttl no greater than overlap_ttl means no lease can outlive the credential it
// names (techrfc OBC-002) — and every client gets its full TTL, which is what keeps the
// clamp in the read path defensive rather than load-bearing.
func (l lifecycleFields) apply(fields *credentialTypeFields, maxTTL time.Duration) *logical.Response {
	refuse := func(format string, args ...any) *logical.Response {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid, format, args...)
	}
	if !l.periodSet || l.period <= 0 {
		return refuse("%s is required for a %s role: it is how long one shared key is served "+
			"before it is replaced, and there is no safe default for a credential's lifetime",
			fieldRotationPeriod, credentialTypeSpacesKeyRotated)
	}
	if l.period < minRotationPeriod {
		return refuse("%s must be at least %s, and is %s: rotation is create-then-delete against "+
			"a per-account cap of %d keys, so a period near the sweep cadence replaces a key "+
			"before its readers have finished fetching it",
			fieldRotationPeriod, minRotationPeriod, l.period, spacesKeyAccountCap)
	}
	if !l.overlapSet || l.overlap <= 0 {
		return refuse("%s is required for a %s role: it is how long a replaced key keeps working, "+
			"which is the grace every client already holding it gets",
			fieldOverlapTTL, credentialTypeSpacesKeyRotated)
	}
	if l.overlap > l.period {
		return refuse("%s (%s) must not exceed %s (%s): a longer overlap keeps more than two keys "+
			"live at once, which reaches the per-account cap of %d without anybody adding a role",
			fieldOverlapTTL, l.overlap, fieldRotationPeriod, l.period, spacesKeyAccountCap)
	}
	jitter := l.jitter
	if !l.jitterSet {
		jitter = l.period / rotationJitterDivisor
	}
	if jitter < 0 || jitter >= l.period {
		return refuse("%s (%s) must be less than %s (%s): the jitter is SUBTRACTED from the "+
			"period, so a jitter that large could schedule a rotation at or before the mint itself",
			fieldRotationJitter, jitter, fieldRotationPeriod, l.period)
	}
	if maxTTL > l.overlap {
		return refuse("max_ttl (%s) must not exceed %s (%s): a replaced key is deleted %s after it "+
			"is replaced, so a longer lease would name a credential that no longer exists",
			maxTTL, fieldOverlapTTL, l.overlap, l.overlap)
	}
	fields.rotationPeriod = l.period
	fields.rotationJitter = jitter
	fields.overlapTTL = l.overlap
	return nil
}

// credentialTypeFields is what a role write keeps from the type-dependent fields once they are
// validated and normalised: the type itself plus, for a Spaces role, the parsed grants and the
// region/endpoint a client needs. Returned as one value rather than four so that a caller cannot
// pair a credential type with another type's fields.
type credentialTypeFields struct {
	credentialType string
	grants         []spacesGrant
	region         string
	endpoint       string
	rotationPeriod time.Duration
	rotationJitter time.Duration
	overlapTTL     time.Duration
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	if entry == nil {
		return nil, nil
	}

	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "parsing a stored entry", err), nil
	}

	return &logical.Response{Data: roleData(&role)}, nil
}

// roleData renders a role for its read endpoint, in the same field names and units the
// write schema accepts. That is what lets a write to an existing role prefill from it
// (cloudconfig.PrefillRoleWrite), so a field cannot be readable and unpatchable.
func roleData(role *doRole) map[string]any {
	data := map[string]any{
		fieldName:                  role.Name,
		"default_ttl":              int(role.DefaultTTL.Seconds()),
		"max_ttl":                  int(role.MaxTTL.Seconds()),
		fieldMinterSet:             role.MinterSet,
		fieldDisabled:              role.Disabled,
		fieldRequireCallerIdentity: role.RequireCallerIdentity,
		fieldCredentialType:        role.credentialType(),
	}
	// Only the fields belonging to this role's credential type are reported. Emitting the
	// other group as empty would suggest they could be set, which the write refuses.
	if role.issuesSpacesKey() {
		data[fieldGrants] = renderGrants(role.Grants)
		data[fieldRegion] = role.Region
		data[fieldEndpoint] = role.Endpoint
	} else {
		data[fieldScopes] = role.Scopes
	}
	if role.rotatesSharedKey() {
		data[fieldRotationPeriod] = int(role.RotationPeriod.Seconds())
		data[fieldRotationJitter] = int(role.RotationJitter.Seconds())
		data[fieldOverlapTTL] = int(role.OverlapTTL.Seconds())
	}
	return data
}

// storedRoleData renders a STORED role the same way, for a write that is patching one.
func storedRoleData(raw []byte) (map[string]any, error) {
	var role doRole
	if err := json.Unmarshal(raw, &role); err != nil {
		return nil, err
	}
	return roleData(&role), nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "deleting from storage", err), nil
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return credenvelope.InternalResponse(b.Logger().Warn, "reading from storage", err), nil
	}
	return logical.ListResponse(entries), nil
}
