//go:build e2e

package e2e

import (
	"github.com/nicois/openbao-cloud-creds/pkg/baotest"
)

// This file is what is left of the scenario after it moved to pkg/baotest: the vocabulary
// THIS repository's cases speak, and nothing else. The order of the writes, what the lease
// must say and what the envelope must carry are cloud-agnostic and now live in one importable
// place, so a second repository driving the same contract runs the same assertions rather than
// its own reading of them (pkg/baotest/scenario.go explains why that mattered).

// e2eCase is the shared scenario's per-cloud translation. Aliased rather than wrapped so a
// case file reads as it always did.
type e2eCase = baotest.Case

// Names the scenario asserts back out of a response, re-exported at the spelling the case
// files use.
const (
	defaultSet   = baotest.DefaultSetName
	liveMinterID = baotest.DefaultMinterID
)

// Field names shared by more than one cloud's API.
const (
	fieldID           = baotest.FieldID
	fieldNeverExpires = baotest.FieldNeverExpires
	fieldDefaultTTL   = baotest.FieldDefaultTTL
	fieldMaxTTL       = baotest.FieldMaxTTL
	fieldScopes       = baotest.FieldScopes
	fieldMinterSet    = baotest.FieldMinterSet
)

// TTLs the cases request. Each is inside its cloud's enforceable range
// (docs/ttl-semantics.md) and is asserted against the lease OpenBao creates, so a value core
// would clamp shows up as a failure rather than as a shorter lease nobody looked at.
const (
	shortTTL = 900
	hourTTL  = 3600
	dayTTL   = 86400
)

// minterSet and tokenMinter build the two shapes a minter-set write takes here.
var (
	minterSet   = baotest.MinterSet
	tokenMinter = baotest.TokenMinter
)

// pluginBinary is a cloud's plugin/binary name, fixed by convention in this repository.
func pluginBinary(cloud string) string { return "credential-" + cloud }

// modulePrefix is this module path's root, used to name the Go package each plugin binary is
// built from. It lives here rather than in pkg/baotest because the harness must not assume it
// is being used from this repository.
const modulePrefix = "github.com/nicois/openbao-cloud-creds"
