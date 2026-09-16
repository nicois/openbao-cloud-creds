package cloudconfig

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// PrefillRoleWrite makes a write to an EXISTING role a change to it rather than a
// replacement of it: every field of the write schema the request left out is filled
// in from the stored role before the handler validates anything.
//
// Without it, a role write is a full replacement, and a one-field write is refused —
// every plugin requires `minter_set`, and most require a privilege boundary too. That
// makes a field like `disabled` unusable as the thing it exists for. An operator
// containing a leak would have to restate the role's TTLs, minter set and scopes
// correctly from memory, and getting one of them wrong quietly changes what the role
// grants for everyone who reads it afterwards.
//
// stored is the role rendered in the shape its own READ endpoint reports, which is
// the shape the write schema accepts — the two are the same map builder in every
// plugin, so a field cannot be readable and unpatchable.
//
// A role that does not exist yet is left alone: nothing is prefilled, so a create
// still gets the schema's defaults and its required fields are still required.
func PrefillRoleWrite(
	ctx context.Context,
	storage logical.Storage,
	key string,
	d *framework.FieldData,
	render func(raw []byte) (map[string]interface{}, error),
) error {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}
	// An unparseable stored role prefills nothing and is not an error: it can neither
	// issue nor be read, and a full rewrite is how an operator repairs it. Refusing the
	// write would leave the entry unrepairable through the API.
	stored, err := render(entry.Value)
	if err != nil {
		return nil
	}
	prefill(d, stored)
	// The prefilled values bypass the framework's own conversion check, which ran
	// before this handler was called. Re-running it turns a field a plugin reports in
	// a form its schema cannot parse into an error here rather than a panic in d.Get.
	return d.Validate()
}

// prefill copies stored values into the request body for the schema fields the
// request did not carry.
func prefill(d *framework.FieldData, stored map[string]interface{}) {
	if d.Raw == nil {
		d.Raw = make(map[string]interface{}, len(stored))
	}
	for name, value := range stored {
		if _, supplied := d.Raw[name]; supplied {
			continue
		}
		// A read endpoint may report more than the write schema accepts. Copying such a
		// field in would make d.Get panic on a field the plugin never asked for.
		if _, known := d.Schema[name]; !known {
			continue
		}
		d.Raw[name] = value
	}
}
