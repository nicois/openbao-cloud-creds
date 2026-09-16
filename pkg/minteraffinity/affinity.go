// Package minteraffinity spreads clients deterministically across the minters of a set, so a
// set can multiply an upstream rate limit instead of only surviving a failure.
//
// # The problem it solves
//
// A minter set already exists for redundancy: if one credential fails, others can serve. That
// says nothing about WHICH one serves, and today it is whichever Go's map iteration reaches
// first — effectively random per request.
//
// Random is the wrong answer when the upstream meters per credential. DigitalOcean meters
// **per token** — measured 2026-09-03: two credentials minted from ONE account, 25 requests spent
// on the first, and the second's counter fell by one, its own request — at 5000/hour each.
//
// Two consequences, and they point in opposite directions. A set does NOT multiply a CLIENT's
// throughput there, because every issued credential already carries its own budget whichever
// minter made it. What a set multiplies is ISSUANCE: each minter is itself a token with its own
// 5000/hour, so K minters give K times the budget for the mint, list and revoke calls this plugin
// makes — and that holds WITHIN one account, so it needs no multi-account estate. Affinity is what
// makes a worker's issuance land on one of those budgets consistently rather than spraying across
// all of them.
//
// Do not restate this as a per-account limit: that was the earlier inference, drawn from where a
// credential's OWNERSHIP comes from, and the measurement refuted it. See docs/decisions.md, "Why
// minter selection has affinity", for the table of which clouds this has actually been measured on.
//
// # Why affinity rather than round-robin
//
// Spreading load is the smaller half. The larger half is ISOLATION: with random selection every
// client draws on every budget, so one heavy client degrades all of them, and exhausting any one
// account affects everybody. With stable affinity a client draws on ONE budget, so a heavy or
// misbehaving client exhausts its own shard and leaves the others intact. It is a bulkhead, and
// that is worth more than the balancing.
//
// # Rendezvous hashing, and what "semi-stable" buys
//
// Selection is highest-random-weight (rendezvous) hashing rather than `hash % N`: modulo
// reshuffles nearly every client when the set changes size, while rendezvous moves only about
// 1/N of them. That matters because a set changes size for ordinary reasons — a minter is
// retired, rotated, or added — and a reshuffle would migrate every worker's budget at once.
//
// Rendezvous also yields a total ORDER rather than a single choice, which is what makes
// "best-effort" precise: a client prefers its own shard, and when that minter is unhealthy or in
// a rate-limit cooldown it falls to its second preference — deterministically, so the fallback
// is as stable as the primary. Affinity is therefore a preference, never a constraint, and
// redundancy is unaffected.
//
// # What it cannot do
//
// It cannot multiply anything if the set's minters share an account. Two credentials in one
// account draw on one budget, and no amount of hashing changes that. There is no portable way to
// verify separateness from here — an account is not a concept the cloud-agnostic layer has — so
// it is a property of how an operator populates the set, and a foot-gun worth stating plainly.
package minteraffinity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"
)

// Key picks the affinity key for one request, most specific first.
//
// The ordering is the whole design, because the obvious choice is wrong in a common deployment.
// An OpenBao identity entity is shared by every client authenticating through the same auth
// role — with AppRole the alias is the role id, so a fleet of a hundred workers using one role
// is ONE entity. Keying on that would hash the entire fleet to a single minter and the feature
// would silently achieve nothing, which is the worst kind of not working.
//
// So:
//
//   - explicit wins. A caller that knows its own identity (a task id, a worker name) can say so,
//     and gets a shard that is stable for exactly as long as it wants one. This is the only
//     option that is reliably per-worker.
//   - the client token accessor next. One token per worker is the ordinary shape, so this is
//     per-worker in practice — and it is the accessor rather than the token itself, which is a
//     secret. It is SEMI-stable: re-authenticating moves the worker to another shard, which
//     costs a budget migration and nothing else.
//   - the entity id last. Coarse, per the above, but better than nothing when it is all there is.
//   - otherwise empty, which Order treats as "no affinity" and randomises, because concentrating
//     every anonymous caller on one minter would be worse than the behaviour this replaces.
func Key(explicit, clientTokenAccessor, entityID string) string {
	switch {
	case explicit != "":
		return explicit
	case clientTokenAccessor != "":
		return clientTokenAccessor
	default:
		return entityID
	}
}

// Order returns ids in descending preference for key: the first is the client's shard, and the
// rest are its fallbacks in a deterministic order.
//
// An empty key means no affinity information, and the order is RANDOMISED rather than fixed.
// A fixed order would send every keyless caller to the same minter, which concentrates exactly
// the load this package exists to spread.
//
// ids is not modified. The result is a new slice.
func Order(key string, ids []string) []string {
	ordered := make([]string, len(ids))
	copy(ordered, ids)

	if key == "" {
		shuffle(ordered)
		return ordered
	}

	// Sort by descending weight, breaking ties on the id so the result is a total order and
	// cannot depend on the input's order. A tie needs a 256-bit collision, but a comparison
	// function that is not a total order is a sorting bug waiting for one.
	weights := make(map[string]uint64, len(ordered))
	for _, id := range ordered {
		weights[id] = weigh(key, id)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if weights[ordered[i]] != weights[ordered[j]] {
			return weights[ordered[i]] > weights[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

// weigh is the rendezvous weight of one (key, id) pair.
//
// SHA-256 rather than a fast non-cryptographic hash, for distribution rather than for secrecy:
// this runs once per credential issuance, alongside network calls, so its cost is invisible,
// while a hash with weak avalanche on short inputs would produce visibly lumpy shards — and
// lumpy shards are the one thing this package must not produce. The separator keeps
// ("ab", "c") from colliding with ("a", "bc").
func weigh(key, id string) uint64 {
	sum := sha256.Sum256([]byte(key + "\x00" + id))
	return binary.BigEndian.Uint64(sum[:8])
}

// shuffle randomises in place using crypto/rand, which cannot fail in a way worth handling here:
// on the impossible error the slice is simply left in its current order, which is still a valid
// (if unshuffled) preference list.
func shuffle(ids []string) {
	for i := len(ids) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := n.Int64()
		ids[i], ids[j] = ids[j], ids[i]
	}
}

// OrderKeys is Order over the keys of a map, which is how a plugin holds its minter states.
//
// It exists so that nine call sites do not each grow their own copy of "collect the keys, then
// order them" — the kind of four-line helper that drifts once it is written nine times.
func OrderKeys[V any](key string, states map[string]V) []string {
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	return Order(key, ids)
}
