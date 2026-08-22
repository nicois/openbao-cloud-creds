// Package ownertag names the upstream credentials a mount owns, so a reconciler can
// tell them from everything else — including from ANOTHER mount's.
//
// The owner tag used to be the bare prefix `cloud-creds-`, with no mount, cluster or
// instance component, while the "known" set was a per-mount storage view. Two mounts
// against one cloud account — or prod and staging, or two clusters — therefore each
// saw the other's LIVE credentials as orphans and deleted up to ten per pass,
// silently. docs/decisions.md actively recommended multiple mounts as an isolation
// strategy, with no warning (A19 in docs/audit-2026-08-22.md).
//
// The fix is an instance id in the name, minted once per mount and persisted. Nothing
// in the plugin API supplies a durable mount identity that a timer-driven worker can
// read — requests carry MountPoint, workers have no request — so the mount mints its
// own on first use.
//
// # No compatibility with the old scheme
//
// The project is alpha and has no users, so the previous bare-prefix scheme is simply
// gone rather than supported alongside this one. That was the right trade even had
// there been users: matching both shapes would have preserved exactly the cross-mount
// deletion this exists to stop. A name carrying the base prefix but no recognised
// instance id is treated as somebody else's and left alone, which is the safe
// direction if such a name is ever encountered.
package ownertag

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// storageKey holds this mount's instance id.
const storageKey = "owner-instance-id"

// Base is the scheme's leading segment, kept so a human can still recognise
// everything this project creates at a glance.
const Base = "cloud-creds-"

// instanceIDBytes is 8 bytes: long enough that two mounts colliding is not a practical
// concern, short enough to leave room in the naming limits some clouds impose (AWS
// caps a RoleSessionName at 64 characters, Akamai and Vultr have their own).
const instanceIDBytes = 8

// InstanceID returns this mount's instance id, minting and persisting one on first
// call. It is stable for the life of the mount, including across reloads and failover,
// because it lives in storage rather than in memory.
func InstanceID(ctx context.Context, storage logical.Storage) (string, error) {
	entry, err := storage.Get(ctx, storageKey)
	if err != nil {
		return "", fmt.Errorf("reading the owner instance id: %w", err)
	}
	if entry != nil && len(entry.Value) > 0 {
		return string(entry.Value), nil
	}

	buf := make([]byte, instanceIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating an owner instance id: %w", err)
	}
	id := hex.EncodeToString(buf)
	if err := storage.Put(ctx, &logical.StorageEntry{Key: storageKey, Value: []byte(id)}); err != nil {
		return "", fmt.Errorf("persisting the owner instance id: %w", err)
	}
	return id, nil
}

// Prefix is what this mount's upstream credentials are named with, and what its
// reconciler must match on.
func Prefix(instanceID string) string {
	return Base + instanceID + "-"
}

// CredentialName names one issued credential. The role and request id remain in the
// name because they are what makes a stray credential diagnosable upstream.
func CredentialName(instanceID, role, requestID string) string {
	return Prefix(instanceID) + role + "-" + requestID
}

// FitName assembles prefix + middle + "-" + suffix inside maxLen characters,
// shortening the MIDDLE rather than the tail. maxLen <= 0 means unbounded.
//
// Which end gets cut is the whole point. Several clouds cap a credential name
// (AWS: 64 for a RoleSessionName), and the natural `prefix + role + "-" + id`
// then overflows for perfectly ordinary role names. Truncating that from the
// right removes the discriminator — the request id — so every lease of a
// long-named role ends up sharing one upstream name, which destroys per-lease
// attribution in the cloud's own audit log exactly where it matters most. Cutting
// the middle instead keeps the mount prefix (ownership) and the discriminator
// (attribution), and loses only some characters of a role name that is also
// recorded in the lease, the envelope and this plugin's logs.
//
// Two long role names sharing a truncated form therefore produce names
// distinguished only by the suffix. That is intended: the suffix is the unique
// part, and role identity is carried elsewhere.
func FitName(prefix, middle, suffix string, maxLen int) string {
	assembled := prefix + middle + "-" + suffix
	if maxLen <= 0 || len(assembled) <= maxLen {
		return assembled
	}
	// One character of middle plus its separator has to fit for the middle to be
	// worth keeping at all.
	if budget := maxLen - len(prefix) - len(suffix) - 1; budget > 0 {
		return prefix + middle[:budget] + "-" + suffix
	}
	// No room for any of the middle: drop it and its separator. The prefix and the
	// suffix are the two parts with a job to do.
	if len(prefix)+len(suffix) <= maxLen {
		return prefix + suffix
	}
	// The caller's suffix cannot fit alongside the prefix, so it is the caller's
	// suffix that is too long for its own cloud — shorten it there rather than
	// here, where the choice of what to lose is not ours to make. The prefix is
	// never cut while any alternative exists: a name that loses it is a name this
	// mount's reconciler no longer recognises as its own.
	if maxLen > len(prefix) {
		return prefix + suffix[:maxLen-len(prefix)]
	}
	return prefix[:maxLen]
}

// Owns reports whether an upstream entity name belongs to THIS mount.
//
// Deliberately not "does it look like ours": a name carrying the base prefix but a
// different instance id belongs to another mount and must be left alone, which is the
// whole point.
func Owns(instanceID, name string) bool {
	return strings.HasPrefix(name, Prefix(instanceID))
}
