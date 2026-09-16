package upstreampurge

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The two modes the write accepts. A dry run answers how big the incident is, having changed
// nothing; there is no third mode, and an unrecognised one is refused rather than defaulted —
// defaulting would turn a typo in a dry run into an irreversible purge.
const (
	ModeNormal = "normal"
	ModeDryRun = "dry_run"
)

// fieldName is the role name captured from the path. It matches every plugin's own spelling,
// because the endpoint hangs off the role path they already define.
const fieldName = "name"

// Target is what a purge needs to know about one role: where this credential type's tracking
// records live, and how to delete one of its credentials upstream.
//
// The prefix comes from the role rather than the plugin because a plugin serving two
// credential types has one prefix per type (DigitalOcean's tokens and Spaces keys), and the
// role is what says which type it issues.
type Target struct {
	Prefix string
	Delete Deleter
}

// Endpoint is the shared revoke-upstream path: the plugin supplies the cloud's identity and
// how to reach one role's credentials, and everything an operator sees — the schema, the two
// modes, the report, the pacing, the durable intent — is the same on every cloud.
type Endpoint struct {
	// Cloud names the cloud in log lines. Deleting a credential upstream is irreversible and
	// operator-initiated, so it is logged rather than only counted (metrics do not reach an
	// operator in the documented deployment).
	Cloud string
	// Logger may be nil, which silences the log lines and nothing else.
	Logger hclog.Logger
	// MaxDeletesPerPass bounds each pass, inline and in the worker. Zero takes
	// DefaultMaxDeletes.
	MaxDeletesPerPass int
	// Resolve returns the role's target, or the error response to answer with. A nil target
	// and a nil response is not a valid answer: a role that cannot be resolved must be said
	// so, because a clean report for a role nobody has reads as containment.
	Resolve func(ctx context.Context, storage logical.Storage, role string) (*Target, *logical.Response)
}

// Path is the role's revoke-upstream endpoint, on the clouds that can delete what they
// issued. It is taken as a function so the plugin can build it per request and give it a live
// logger.
func Path(endpoint func() Endpoint) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex(fieldName) + "/revoke-upstream",
		Fields: map[string]*framework.FieldSchema{
			fieldName: {
				Type:        framework.TypeString,
				Description: "Name of the role whose issued credentials are to be deleted upstream",
			},
			KeyMode: {
				Type:    framework.TypeString,
				Default: ModeNormal,
				Description: "Either " + ModeNormal + " (delete them) or " + ModeDryRun +
					" (report how many there are, change nothing and arm nothing). Start with " +
					ModeDryRun,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e := endpoint()
					return e.write(ctx, req, d)
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e := endpoint()
					return e.read(ctx, req, d)
				},
			},
		},
		HelpSynopsis: "Delete the credentials this role has already issued",
		HelpDescription: "Deleting a role stops nothing: live leases stay renewable and every " +
			"credential already issued keeps working. This deletes them upstream. Scope is what the " +
			"role had issued when the call was made, so credentials issued afterwards are untouched " +
			"and the role goes on issuing — set disabled=true on the role to stop that. Large " +
			"purges continue in the background; read this path for progress.",
	}
}

// RemedyExpiryOnly is the containment an operator has on a cloud whose credentials only ever
// expire: none, beyond having stopped the next one. Named once because it is the same sentence
// on every such cloud, and it is the sentence that has to be right — an operator reading it is
// deciding whether to keep looking for a lever.
const RemedyExpiryOnly = "a leaked credential is bounded only by its own expiry, so the role's " +
	"max_ttl is the blast radius; set disabled=true on the role to stop it issuing more"

// UnsupportedPath is the same endpoint on a cloud whose credentials cannot be deleted at all.
// It refuses both operations, naming the reason and the containment the operator does have.
//
// A success response listing zero deletions would be the harmful answer: it would tell an
// operator the incident was contained when in fact nothing was destroyed. The remedy is a
// parameter rather than a constant because it is not the same everywhere: where a credential
// merely expires it is the role's TTL ceiling, but where one occupies a rotation slot, rotating
// that slot invalidates it now — and an operator handed the expiry answer there would sit out a
// TTL they could have cut short.
func UnsupportedPath(reason, remedy string) *framework.Path {
	refuse := func(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
		return credenvelope.ErrorResponse(credenvelope.ErrUnsupported,
			"this cloud's credentials cannot be deleted once issued: %s. %s", reason, remedy), nil
	}
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex(fieldName) + "/revoke-upstream",
		Fields: map[string]*framework.FieldSchema{
			fieldName: {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			KeyMode: {
				Type:        framework.TypeString,
				Description: "Not accepted: this cloud cannot delete an issued credential",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: refuse},
			logical.ReadOperation:   &framework.PathOperation{Callback: refuse},
		},
		HelpSynopsis: "Refused on this cloud: an issued credential cannot be deleted",
		HelpDescription: "This cloud offers no way to delete a credential it has issued (" + reason +
			"). Instead: " + remedy,
	}
}

// write arms the purge and runs one bounded pass inline, so the operator's answer is progress
// rather than an acknowledgement.
func (e Endpoint) write(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get(fieldName).(string)
	mode := d.Get(KeyMode).(string)
	if mode != ModeNormal && mode != ModeDryRun {
		return credenvelope.ErrorResponse(credenvelope.ErrConfigInvalid,
			"%s %q is not a mode this endpoint accepts; expected %s or %s",
			KeyMode, mode, ModeNormal, ModeDryRun), nil
	}
	target, errResp := e.Resolve(ctx, req.Storage, role)
	if errResp != nil {
		return errResp, nil
	}

	if mode == ModeDryRun {
		cutoff := time.Now().UTC()
		records, err := Scan(ctx, req.Storage, target.Prefix, role, cutoff)
		if err != nil {
			return credenvelope.InternalResponse(e.warn, "reading the credentials this role has issued", err), nil
		}
		report := DryRunReport(role, cutoff, len(records))
		report[KeyMode] = mode
		return &logical.Response{Data: report}, nil
	}

	intent, err := Arm(ctx, req.Storage, target.Prefix, role, time.Now())
	if err != nil {
		return credenvelope.InternalResponse(e.warn, "arming the purge", err), nil
	}
	e.info("revoking upstream every credential a role has issued", "role", role,
		"tracked", intent.Tracked, "cutoff", intent.Cutoff)

	result, err := intent.Advance(ctx, req.Storage, target.Prefix, e.MaxDeletesPerPass, e.logged(role, target.Delete))
	if err != nil {
		return credenvelope.InternalResponse(e.warn, "deleting the credentials this role has issued", err), nil
	}
	report := intent.Report(result.Remaining)
	report[KeyMode] = mode
	return &logical.Response{Data: report}, nil
}

// read answers a purge's progress, including for a role that has never had one.
func (e Endpoint) read(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get(fieldName).(string)
	target, errResp := e.Resolve(ctx, req.Storage, role)
	if errResp != nil {
		return errResp, nil
	}
	report, err := Progress(ctx, req.Storage, target.Prefix, role)
	if err != nil {
		return credenvelope.InternalResponse(e.warn, "reading the purge's progress", err), nil
	}
	return &logical.Response{Data: report}, nil
}

// Sweep continues every armed purge by one bounded pass. This is the worker body: it runs on
// the active node only, on the same tick as the mount's other background work, and it is what
// makes the operator's single call enough for a purge too big for one request.
//
// A role it cannot resolve — deleted since the purge was armed, or unreadable — is skipped
// rather than fatal: the roles are unrelated, and one broken role must not strand every other
// operator's containment.
func (e Endpoint) Sweep(ctx context.Context, storage logical.Storage) error {
	roles, err := ArmedRoles(ctx, storage)
	if err != nil {
		return err
	}
	for _, role := range roles {
		intent, err := LoadIntent(ctx, storage, role)
		if err != nil {
			e.warn("skipping a purge whose intent cannot be read", "role", role, "error", err)
			continue
		}
		if intent == nil || intent.Complete {
			continue
		}
		target, errResp := e.Resolve(ctx, storage, role)
		if errResp != nil {
			e.warn("skipping a purge whose role cannot be resolved", "role", role,
				"reason", errResp.Error())
			continue
		}
		result, err := intent.Advance(ctx, storage, target.Prefix, e.MaxDeletesPerPass, e.logged(role, target.Delete))
		if err != nil {
			e.warn("a purge pass failed and will be retried", "role", role, "error", err)
			continue
		}
		if result.Complete() {
			e.info("finished revoking upstream what a role had issued", "role", role,
				"deleted", intent.Deleted)
		}
	}
	return nil
}

// logged wraps a plugin's deleter so every upstream deletion is a log line naming the role,
// the credential and the minter. Deleting a credential is irreversible, so what was destroyed
// has to be answerable afterwards from the log alone — plugin metrics reach nobody in the
// documented deployment.
func (e Endpoint) logged(role string, del Deleter) Deleter {
	return func(ctx context.Context, rec Record) error {
		err := del(ctx, rec)
		switch {
		case err == nil:
			e.info("deleted a credential upstream", "cloud", e.Cloud, "role", role,
				"credential", rec.ID, "minter", rec.Minter)
		case ctx.Err() == nil:
			e.warn("could not delete a credential upstream", "cloud", e.Cloud, "role", role,
				"credential", rec.ID, "minter", rec.Minter, "error", err)
		}
		return err
	}
}

func (e Endpoint) info(msg string, args ...interface{}) {
	if e.Logger != nil {
		e.Logger.Info(msg, args...)
	}
}

func (e Endpoint) warn(msg string, args ...interface{}) {
	if e.Logger != nil {
		e.Logger.Warn(msg, args...)
	}
}

// SweepInterval is how often an armed purge advances by one bounded pass.
//
// A minute: containment is urgent, so a purge too big for the operator's own request should
// not wait on the reconciler's cadence (hours), and a sweep with nothing armed costs one
// storage list. Deliberately NOT the reconciler's max_deletes_per_pass and cadence, either:
// those bound the RISK of a pass that infers what is an orphan, while this bounds the PACE of
// deleting exactly what an operator named. An operator who tightened the reconciler for safety
// must not thereby have slowed their own incident response.
const SweepInterval = time.Minute
