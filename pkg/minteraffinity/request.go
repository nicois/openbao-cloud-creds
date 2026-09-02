package minteraffinity

import (
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The request binding lives with the hashing rather than in each plugin, because WHICH identity
// a key is derived from is this package's central decision — get it wrong and the feature
// silently does nothing (see Key). Nine plugins each deriving their own key is nine chances to
// pick the convenient field instead of the correct one.

// FieldShardKey is the optional request field a caller uses to name its own shard.
const FieldShardKey = "shard_key"

// ShardKeyField is the schema entry to add to a credential-issuing path, so every plugin
// describes it identically.
func ShardKeyField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type: framework.TypeString,
		Description: "Optional: an opaque key identifying the calling worker, used to pick which " +
			"minter of the role's set issues this credential. Callers sharing a key share a " +
			"minter; different keys are spread across the set. Omit it and the caller's token " +
			"accessor is used, which is per-token and therefore usually per-worker. Whether that " +
			"also spreads the ISSUED credential's own rate limit depends on the cloud: on some, a " +
			"credential belongs to the minter's account, and on others (AWS, GCP, Azure) it is a " +
			"target named on the role and is the same identity whichever minter issued it — see " +
			"docs/decisions.md",
	}
}

// KeyFromRequest derives the affinity key for a credential read.
//
// Safe on a path that does not declare FieldShardKey: FieldData.GetOk reports absence rather than
// failing, so a plugin that has not adopted the field yet keeps the token-accessor behaviour
// instead of breaking.
func KeyFromRequest(req *logical.Request, d *framework.FieldData) string {
	explicit := ""
	if d != nil {
		if raw, ok := d.GetOk(FieldShardKey); ok {
			explicit, _ = raw.(string)
		}
	}
	if req == nil {
		return explicit
	}
	return Key(explicit, req.ClientTokenAccessor, req.EntityID)
}
