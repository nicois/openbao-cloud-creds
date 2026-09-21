package plugintest

import (
	"fmt"
	"sort"
	"testing"
)

// Plugin is one entry in the conformance table: a cloud name and a constructor
// that builds a FRESH harness (fresh fake, fresh counters, fresh deny knobs).
// The constructor is called once per category so no category inherits another's
// upstream state.
type Plugin struct {
	// Cloud is the plugin DIRECTORY's cloud name (plugins/credential-<Cloud>). Several
	// entries may share it — see Variant.
	Cloud string
	// Variant distinguishes two conformance SUBJECTS drawn from one plugin, and is empty
	// for the nine plugins that have only one.
	//
	// It exists because a Harness declares exactly one CredentialKind, ScopeKind,
	// SecretType and TrackingPrefix, which is right — those are the contract a client
	// and the lease core see — but a plugin may serve more than one credential type,
	// chosen per role. `credential-do` does: a personal access token and an
	// S3-compatible Spaces key. Without variants the shared suites covered whichever
	// type the harness happened to name and NOTHING covered the other, which on that
	// cloud meant covering the type real DigitalOcean refuses to mint (KI-009) instead
	// of the type it serves.
	//
	// Keying registration on Cloud while naming subtests by Subject is deliberate: a
	// variant must not be able to satisfy "every plugin directory is registered", or
	// adding one to a cloud could hide the absence of another cloud entirely.
	Variant string
	New     func(t *testing.T) Harness
}

// Subject names this entry for subtest names and coverage tables: the cloud, plus the
// variant where there is one.
func (p Plugin) Subject() string {
	if p.Variant == "" {
		return p.Cloud
	}
	return p.Cloud + "-" + p.Variant
}

// suite binds a category to its runner and to the harness fields it needs. The
// requires function is what turns a missing wiring into a loud failure: a plugin
// either supplies the fields or declares the skip.
type suite struct {
	name     Category
	run      func(t *testing.T, h Harness)
	requires func(h Harness) []string
}

// suites is the conformance registry. Adding a category here immediately applies
// it to every plugin in the table — which is the point: a new shared invariant
// cannot be added to one cloud and forgotten on the other nine.
var suites = []suite{
	{
		name: CategoryReload,
		run:  RunReloadSuite,
		requires: func(h Harness) []string {
			return missing(
				field{fieldRolePath, h.RolePath != ""},
				field{"WorkersRunning", h.WorkersRunning != nil},
			)
		},
	},
	{
		name: CategoryPerturbation,
		run:  RunPerturbationSuite,
		requires: func(h Harness) []string {
			return missing(field{"RewriteDefaultSetWithout", h.RewriteDefaultSetWithout != nil})
		},
	},
	{
		name: CategoryLease,
		run:  RunLeaseContractSuite,
		// No extra wiring: every assertion is drawn from the issuance response
		// itself, so no cloud can opt out by lacking a field.
		requires: func(_ Harness) []string { return nil },
	},
	{
		name:     CategoryRevoke,
		run:      RunRevokeResilienceSuite,
		requires: func(_ Harness) []string { return nil },
	},
	{
		name: CategoryCapability,
		run:  RunCapabilitySuite,
		requires: func(h Harness) []string {
			return missing(
				field{"ConfigureProbe", h.ConfigureProbe != nil},
				field{"ProbeRolePath", h.ProbeRolePath != ""},
				field{"WriteProbeRole", h.WriteProbeRole != nil},
				field{"RewriteSet", h.RewriteSet != nil},
				field{"DenyMint", h.DenyMint != nil},
				field{"AllowMint", h.AllowMint != nil},
				field{"LiveMinterID", h.LiveMinterID != ""},
				field{"ReplacementMinterID", h.ReplacementMinterID != ""},
			)
		},
	},
	{
		name: CategoryMinterVisibility,
		run:  RunMinterVisibilitySuite,
		// No extra wiring: SetPath is already required of every harness, so no cloud
		// can opt out of being observable.
		requires: func(_ Harness) []string { return nil },
	},
	{
		name: CategoryErrorTaxonomy,
		run:  RunErrorTaxonomySuite,
		// No extra wiring, so NO cloud can opt out of the contract that its
		// errors carry codes — the same reasoning as the lease category. The
		// individual cases that need a knob (a mint refusal, a forced status)
		// skip themselves with a printed reason, so a cloud missing a knob still
		// gets the cases that do not need one.
		requires: func(_ Harness) []string { return nil },
	},
	{
		name: CategoryContainment,
		run:  RunContainmentSuite,
		requires: func(h Harness) []string {
			return missing(field{fieldRolePath, h.RolePath != ""})
		},
	},
	{
		name: CategoryRotation,
		run:  RunRotationSuite,
		requires: func(h Harness) []string {
			return missing(
				field{"ForceRotationDue", h.ForceRotationDue != nil},
				field{"ForceOverlapExpired", h.ForceOverlapExpired != nil},
				field{"SweepRetiredCredentials", h.SweepRetiredCredentials != nil},
				field{"RotationOverlapTTL", h.RotationOverlapTTL > 0},
			)
		},
	},
	{
		name: CategoryReconcilerSafety,
		run:  RunReconcilerSafetySuite,
		requires: func(h Harness) []string {
			return missing(
				field{"SeedForeignEntity", h.SeedForeignEntity != nil},
				field{"HasEntity", h.HasEntity != nil},
			)
		},
	},
	{
		name: CategoryProvenance,
		run:  RunProvenanceSuite,
		// Only the role path: the two cases that read a tracking record gate on
		// TrackingPrefix themselves and print why, while the cases about refusing an
		// unidentifiable caller need nothing cloud-specific — so no cloud can opt out of
		// the contract that a credential is attributable, the same reasoning as `lease`.
		requires: func(h Harness) []string {
			return missing(field{fieldRolePath, h.RolePath != ""})
		},
	},
	{
		name: CategoryInventory,
		run:  RunInventorySuite,
		// Nothing cloud-specific: the `issued/` path exists on every plugin, answering where
		// credentials are tracked one-per-credential and REFUSING where they are not. A cloud
		// that could opt out would be one whose inventory nobody ever asked for.
		requires: func(_ Harness) []string { return nil },
	},
	{
		name: CategoryLineage,
		run:  RunLineageSuite,
		// Nothing cloud-specific and nothing to wire per subject: each case supplies its own
		// identity by copying the harness, so no cloud can opt out by omitting a field. The one
		// case needing a per-read tracking record gates itself and prints why.
		requires: func(_ Harness) []string { return nil },
	},
}

// fieldRolePath names the harness field three categories need. A const because more than two
// categories now require it, which is lint's threshold and a fair one: a typo'd field name in a
// requires() list reads as "this harness is wired" and silently disables the check.
const fieldRolePath = "RolePath"

type field struct {
	name string
	set  bool
}

func missing(fields ...field) []string {
	var out []string
	for _, f := range fields {
		if !f.set {
			out = append(out, f.name)
		}
	}
	return out
}

// AllCategories returns every conformance category, in registry order. Used by
// the conformance table's coverage-matrix test.
func AllCategories() []Category {
	out := make([]Category, 0, len(suites))
	for _, s := range suites {
		out = append(out, s.name)
	}
	return out
}

// alwaysRequired lists the harness fields no category can do without.
func alwaysRequired(h Harness) []string {
	return missing(
		field{"Cloud", h.Cloud != ""},
		field{"Factory", h.Factory != nil},
		field{"Configure", h.Configure != nil},
		field{"IssuePath", h.IssuePath != ""},
		field{"SetPath", h.SetPath != ""},
		field{"ProvisionedCount", h.ProvisionedCount != nil},
	)
}

// ValidateHarness reports why a harness is unusable, or nil. Exported so the
// conformance table can check every plugin up front rather than one category at a
// time.
func ValidateHarness(h Harness) error {
	if gaps := alwaysRequired(h); len(gaps) > 0 {
		return fmt.Errorf("harness is missing required field(s): %v", gaps)
	}
	known := make(map[Category]bool, len(suites))
	for _, s := range suites {
		known[s.name] = true
	}
	names := make([]string, 0, len(h.Skips))
	for c := range h.Skips {
		names = append(names, string(c))
	}
	sort.Strings(names)
	for _, n := range names {
		c := Category(n)
		if !known[c] {
			return fmt.Errorf("harness Skips declares unknown category %q (known: %v)", n, AllCategories())
		}
		if h.Skips[c] == "" {
			return fmt.Errorf("harness Skips[%q] has an empty reason; a skipped category must say why", n)
		}
	}
	for _, s := range suites {
		if _, skipped := h.Skips[s.name]; skipped {
			continue
		}
		if gaps := s.requires(h); len(gaps) > 0 {
			return fmt.Errorf("category %q needs harness field(s) %v; wire them, or declare Skips[%q] with a reason",
				s.name, gaps, s.name)
		}
	}
	return nil
}

// RunConformance runs every registered category against one plugin, as subtests
// named "<cloud>/<category>". A category the harness declares in Skips is
// skipped with its reason (visible in `go test -v` output); a category that is
// neither wired nor declared fails, so an absent invariant can never be silent.
func RunConformance(t *testing.T, p Plugin) {
	t.Helper()
	t.Run(p.Subject(), func(t *testing.T) {
		h0 := p.New(t)
		if err := ValidateHarness(h0); err != nil {
			t.Fatalf("%s conformance harness is invalid: %v", p.Subject(), err)
		}
		for _, s := range suites {
			t.Run(string(s.name), func(t *testing.T) {
				// A fresh harness per category: the fake, its counters and its
				// deny knobs must not leak between categories.
				h := p.New(t)
				if reason, skipped := h.Skips[s.name]; skipped {
					t.Skipf("%s: category %q not exercised: %s", p.Subject(), s.name, reason)
				}
				s.run(t, h)
			})
		}
	})
}
