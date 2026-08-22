package cloudconfig

import "fmt"

// SchemaVersion is the version this binary writes into every versioned persisted
// entry. Bump it when a persisted shape changes in a way an older binary would
// mishandle, and add the corresponding migration note to docs/decisions.md.
const SchemaVersion = 1

// Versioned is embedded in a persisted struct to carry the schema version.
//
// # Why a version at all
//
// Nothing persisted here carried one, and every mutation is
// read-struct → change a field → write the WHOLE struct back. `encoding/json`
// drops fields it does not know, so a binary that predates a field silently
// ERASES it on any write. On a minter set that erasure is A13 all over again by a
// different route: dropping `retired`/`retired_at` un-retires a rotated-out minter,
// which cancels the sweep that was going to delete its upstream credential and puts
// a minter the operator has replaced back into the selection pool (A30 in
// docs/audit-2026-08-22.md).
//
// # What the check does, and what it deliberately does not
//
// The protection that matters is refusing to TOUCH an entry written by a newer
// binary, because that is the case where a rewrite loses information nobody can
// reconstruct. So a future version is a hard load failure for that entry, and an
// older or absent one is not: zero means "written before versioning existed", which
// during alpha is the ordinary case and is read as current.
//
// It is not field preservation. Round-tripping unknown fields through
// json.RawMessage would be strictly stronger and much more invasive; the version
// buys the important half — an older binary declines rather than damages — and
// leaves the operator with an intact entry and a message naming the mismatch.
type Versioned struct {
	// Schema is the version of the persisted shape. Omitted when zero so entries
	// written before versioning existed round-trip unchanged.
	Schema int `json:"schema_version,omitempty"`
}

// Stamp records this binary's schema version. Call it on every write path.
func (v *Versioned) Stamp() { v.Schema = SchemaVersion }

// CheckSchema reports whether this binary may safely load and rewrite the entry.
// kind names the entry in the error, because the operator's next action depends on
// which one it is.
func (v Versioned) CheckSchema(kind string) error {
	if v.Schema > SchemaVersion {
		return fmt.Errorf("%s was written with schema version %d but this binary understands %d: "+
			"refusing to load it, because rewriting it would erase the fields this binary does not "+
			"know about. Upgrade the plugin binary on this node", kind, v.Schema, SchemaVersion)
	}
	return nil
}
