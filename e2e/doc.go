// Package e2e drives the credential plugins the way production does: as plugin
// binaries running as child processes of a live OpenBao server, reached over
// HTTP, with leases managed by OpenBao's expiration manager.
//
// Why this module exists: every other test in this repo runs a backend
// in-process (logical.InmemStorage, b.HandleRequest called directly), which
// shares the test's address space with the plugin and stubs out OpenBao core
// entirely. That layer cannot see anything owned by the boundary itself — the
// JSON round-trip of resp.Data and a lease's internal_data, req.ID (which only
// core populates, and which seven plugins use to name the upstream credential),
// the lease OpenBao actually created and whether it says renewable, revocation
// driven by the expiration manager, or a `plugin reload` that rebuilds the
// backend from storage alone. `make smoke-test` starts a real server but stops
// at "the mount exists". See docs/openbao-integration-gaps.md for the full
// assessment of what each layer proves.
//
// The cloud fakes still stand in for the clouds, and they run in the *test*
// process while the plugin runs in its own — so upstream state can be asserted
// directly (the fake is a Go object here) while the plugin reaches it over real
// HTTP through a config field. That is the whole reason this layer covers seven
// clouds and not ten: AWS, GCP and OCI are wired with in-process client
// injection, so a plugin in another process has nothing to point at a fake.
// Those three are declared in the registry with their reasons, exactly as the
// conformance table declares category gaps.
//
// This module is test-only and build-tagged `e2e`: it needs an OpenBao binary
// on PATH, so it must not run in the default `go test ./...`. When the tag IS
// set, a missing binary is a failure and never a skip — an opt-in layer that
// silently does nothing is worse than no layer.
package e2e
