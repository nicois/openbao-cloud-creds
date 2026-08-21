// Package conformance holds the single table of every credential plugin and runs
// the shared, cloud-agnostic suites in pkg/plugintest against all of them.
//
// Why this module exists: the ten plugins are near-parallel implementations of one
// contract, and when their tests are written per plugin they drift. An invariant
// gets asserted on six clouds and silently absent on four; the same assertion
// acquires four different names; a new plugin arrives with a subset of the
// categories and nothing notices, because a missing test is an absence and
// absences are invisible.
//
// The table below turns those absences into failures:
//
//   - Every plugin appears in one list, so a new plugin that is not registered
//     fails TestEveryPluginIsRegistered.
//   - Every registered plugin runs every category in plugintest's registry, so a
//     new shared invariant applies to all ten the moment it is added.
//   - A plugin that cannot exercise a category must DECLARE it in Harness.Skips
//     with a reason. A category that is neither wired nor declared fails
//     validation, and TestConformanceMatrix prints the declared gaps as a table.
//
// What belongs here versus in a plugin's own tests: an assertion phrased in the
// contract's vocabulary (a rejected write must not persist, the reconciler must
// not touch a foreign entity, a probe must leave nothing upstream) belongs in
// pkg/plugintest and is driven from here. An assertion phrased in one cloud's
// vocabulary — the exact mint request shape, DurationSeconds=900, an EdgeGrid
// grant model, an org-policy error string — stays in that plugin's package, where
// it can use the cloud's own words and the package's unexported internals.
//
// This module is test-only: nothing in pkg/ or plugins/ imports it, so the rule
// that plugin modules stay isolated from each other still holds.
package conformance
