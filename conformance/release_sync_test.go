package conformance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot is this module's parent: the workspace every module lives under.
const repoRoot = ".."

// modulePrefix is the module path every module in this repository shares.
const modulePrefix = "github.com/nicois/openbao-cloud-creds/"

// TestEveryModuleAgreesOnOneVersion fails when the inter-module requires name more
// than one version of this repository's own modules.
//
// This repository releases its modules in LOCKSTEP: each release so far tagged every
// module path at one commit, and a consumer pins each module it uses directly rather
// than relying on one to pull the others. Nothing in the toolchain enforces that.
//
// It is unenforced in the worst possible way, because every module reaches its siblings
// through a `replace ../<sibling>` directive. So `go build`, `go test` and even
// `make build-standalone` resolve locally and never consult a require version — while a
// consumer OUTSIDE this checkout gets exactly what the requires name, since Go ignores a
// dependency's replace directives. A stale require is therefore invisible here and
// authoritative there.
//
// That is not hypothetical: the v0.3.0 release moved every require it found except the ten
// `plugins/credential-*` pins in this module's own go.mod, which stayed at v0.2.1. Nothing
// failed, because nothing looks.
func TestEveryModuleAgreesOnOneVersion(t *testing.T) {
	byVersion := map[string][]string{}
	for _, gomod := range findModules(t) {
		for path, version := range internalRequires(t, gomod) {
			byVersion[version] = append(byVersion[version],
				gomod+" -> "+strings.TrimPrefix(path, modulePrefix))
		}
	}
	if len(byVersion) <= 1 {
		return
	}
	t.Errorf("inter-module requires name %d different versions; this repository releases "+
		"its modules in lockstep, so a consumer resolving through the module proxy would "+
		"get a mixture of releases:", len(byVersion))
	for _, version := range sortedKeys(byVersion) {
		sort.Strings(byVersion[version])
		t.Errorf("  %s:", version)
		for _, where := range byVersion[version] {
			t.Errorf("    %s", where)
		}
	}
}

// TestEveryReleasedModuleDeclaresItsPath fails when a module's declared path does not
// match its directory. A release tag is derived from the directory while the proxy
// resolves the declared path, so a mismatch is a module that cannot be consumed under
// the tag the release creates for it.
func TestEveryReleasedModuleDeclaresItsPath(t *testing.T) {
	for _, gomod := range findModules(t) {
		dir := filepath.Dir(gomod)
		if dir != "pkg" && !strings.HasPrefix(dir, "pkg/") &&
			!strings.HasPrefix(dir, "plugins/") {
			continue // conformance and e2e are test-only and never tagged.
		}
		if got, want := declaredPath(t, gomod), modulePrefix+dir; got != want {
			t.Errorf("%s declares module %q, want %q: the release tags %s/, and the proxy "+
				"resolves the declared path, so these must agree", gomod, got, want, dir)
		}
	}
}

// modEdit is the subset of `go mod edit -json` this file reads. Shelling out to the
// toolchain rather than parsing go.mod by hand: it is authoritative about every syntax
// form (single-line require, block, retract) and costs no new dependency, where
// golang.org/x/mod/modfile would add one to a module that has none.
type modEdit struct {
	Module  struct{ Path string }
	Require []struct {
		Path    string
		Version string
	}
}

func readModEdit(t *testing.T, gomod string) modEdit {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "mod", "edit", "-json",
		filepath.Join(repoRoot, gomod)).Output()
	if err != nil {
		t.Fatalf("go mod edit -json %s: %v", gomod, err)
	}
	var parsed modEdit
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("decoding go mod edit -json %s: %v", gomod, err)
	}
	return parsed
}

// internalRequires maps this repository's own required module paths to their versions.
func internalRequires(t *testing.T, gomod string) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, req := range readModEdit(t, gomod).Require {
		if strings.HasPrefix(req.Path, modulePrefix) {
			found[req.Path] = req.Version
		}
	}
	return found
}

func declaredPath(t *testing.T, gomod string) string {
	t.Helper()
	return readModEdit(t, gomod).Module.Path
}

// findModules returns every go.mod in the repository, as a path relative to the root.
func findModules(t *testing.T) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Name() == "go.mod" {
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", repoRoot, err)
	}
	if len(found) == 0 {
		t.Fatal("found no go.mod files at all, so this test is looking in the wrong place")
	}
	sort.Strings(found)
	return found
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
