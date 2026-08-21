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
	Cloud string
	New   func(t *testing.T) Harness
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
				field{"RolePath", h.RolePath != ""},
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
				field{"PlantDisabledProbeRole", h.PlantDisabledProbeRole != nil},
				field{"DenyMint", h.DenyMint != nil},
				field{"AllowMint", h.AllowMint != nil},
				field{"LiveMinterID", h.LiveMinterID != ""},
				field{"ReplacementMinterID", h.ReplacementMinterID != ""},
			)
		},
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
		name: CategoryReconcilerSafety,
		run:  RunReconcilerSafetySuite,
		requires: func(h Harness) []string {
			return missing(
				field{"SeedForeignEntity", h.SeedForeignEntity != nil},
				field{"HasEntity", h.HasEntity != nil},
			)
		},
	},
}

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
	t.Run(p.Cloud, func(t *testing.T) {
		h0 := p.New(t)
		if err := ValidateHarness(h0); err != nil {
			t.Fatalf("%s conformance harness is invalid: %v", p.Cloud, err)
		}
		for _, s := range suites {
			t.Run(string(s.name), func(t *testing.T) {
				// A fresh harness per category: the fake, its counters and its
				// deny knobs must not leak between categories.
				h := p.New(t)
				if reason, skipped := h.Skips[s.name]; skipped {
					t.Skipf("%s: category %q not exercised: %s", p.Cloud, s.name, reason)
				}
				s.run(t, h)
			})
		}
	})
}
