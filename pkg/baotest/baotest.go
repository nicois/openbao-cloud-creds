// Package baotest runs a live OpenBao dev server with plugin binaries in its
// plugin directory, for tests that need the real thing rather than an in-process
// backend.
//
// # Why this is a package and not test files
//
// Everything here used to live in `e2e/`'s `_test.go` files, which made it
// unreachable from any other module — including a separate repository exploring a
// new plugin against the same contract. A harness that cannot be imported gets
// copied, and a copied harness diverges: the reason `pkg/plugintest` is an ordinary
// package is exactly this, and this is the same decision applied to the layer above
// it.
//
// # What this layer is for
//
// In-process tests share an address space with the plugin and stub OpenBao out
// entirely, so they cannot see anything owned by the boundary itself: the JSON
// round-trip of a response and of a lease's internal_data, `req.ID` (which only core
// populates), the lease OpenBao actually created and whether it says renewable,
// revocation driven by the expiration manager, a query parameter surviving the HTTP
// layer, or a `plugin reload` that rebuilds a backend from storage alone. Every one
// of those has produced a real defect in this project. See
// docs/openbao-integration-gaps.md.
//
// The caller supplies the cloud fakes; they run in the TEST process while the plugin
// runs in its own, so upstream state stays directly assertable (the fake is a Go
// object) while the plugin reaches it over real HTTP through a config field.
package baotest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
)

const (
	// RootToken is the dev server's root token. A fixed value is safe because the
	// server listens on a loopback port for the life of one test and stores no token
	// on disk.
	RootToken = "root"

	// The readiness gate and the post-enable check both poll: neither the seal state
	// nor a successful `enable` guarantees the mount table serves a subsequent read
	// coherently (scripts/registration-smoke-test.sh learned this the hard way in CI,
	// on a different plugin each run).
	pollInterval = 250 * time.Millisecond
	pollAttempts = 120

	readinessMount = "baotest-readiness-probe"
	logTailBytes   = 16384

	pluginDirPerm = 0o755
)

// Plugin is a plugin binary to build, place in the server's plugin directory, and
// register. Package is the Go package to build, so a caller in another repository
// names its own module path rather than inheriting this one's.
type Plugin struct {
	// Name is both the binary's filename and the name it registers under, which is
	// what `bao plugin register` requires.
	Name string
	// Package is the Go package path of the plugin's main, e.g.
	// "github.com/you/your-repo/plugin/cmd".
	Package string
	// Dir is where to run `go build`, and it exists because the default is a trap. The
	// build otherwise runs in the TEST's module — the e2e module — so that module's
	// go.sum has to cover the plugin main's whole dependency graph. It does not, and
	// `go mod tidy` will not add it: nothing in an e2e module imports the plugin's
	// main package, so tidy prunes those sums on every run. The failure is a
	// "missing go.sum entry" for a package the caller never mentions.
	//
	// A workspace hides it, which is why this went unnoticed: with go.work present the
	// build resolves anyway. Point Dir at the plugin's own module (e.g. "../plugin")
	// and the build uses the go.sum that actually describes what is being built.
	//
	// Empty keeps the old behaviour, so this is additive for the callers that are
	// already green.
	Dir string
}

// Cluster is a running dev server plus a root-token client for driving it.
type Cluster struct {
	t         *testing.T
	client    *api.Client
	pluginDir string
	logPath   string
}

// Start builds each plugin, starts a dev server over that plugin directory, and
// returns once the mount subsystem verifiably serves write-then-read. The server is
// killed and its log tail printed on failure by a t.Cleanup.
func Start(t *testing.T, plugins ...Plugin) *Cluster {
	t.Helper()

	bao := baoBinary(t)
	work := t.TempDir()
	// Only plugin binaries may live in the plugin dir: bao tries to exec every file
	// it finds there.
	pluginDir := filepath.Join(work, "plugins")
	if err := os.Mkdir(pluginDir, pluginDirPerm); err != nil {
		t.Fatalf("creating the plugin dir failed: %v", err)
	}
	for _, p := range plugins {
		buildPlugin(t, pluginDir, p)
	}

	addr := freeAddr(t)
	logPath := filepath.Join(work, "bao.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("creating the server log failed: %v", err)
	}

	cmd := exec.Command(bao, "server", "-dev",
		"-dev-root-token-id="+RootToken,
		"-dev-listen-address="+addr,
		"-dev-plugin-dir="+pluginDir,
		// Never write the operator's ~/.bao-token: this is a throwaway server in
		// someone's real shell session.
		"-dev-no-store-token",
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the dev server failed: %v", err)
	}

	c := &Cluster{t: t, pluginDir: pluginDir, logPath: logPath}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
		if t.Failed() {
			t.Logf("dev server log (tail):\n%s", c.LogTail())
		}
	})

	cfg := api.DefaultConfig()
	cfg.Address = "http://" + addr
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("building the API client failed: %v", err)
	}
	client.SetToken(RootToken)
	c.client = client

	c.awaitReady()
	return c
}

// Client is the escape hatch: the lease APIs (Sys().Lookup/Renew/Revoke) are the
// point of this layer, and wrapping each of them here would add nothing.
func (c *Cluster) Client() *api.Client { return c.client }

// baoBinary locates the OpenBao binary. Absence is a failure, not a skip: reaching
// this code already means the caller opted into the layer that needs it.
func baoBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bao")
	if err != nil {
		t.Fatalf("this layer needs an OpenBao binary on PATH (`bao`): %v", err)
	}
	return path
}

func buildPlugin(t *testing.T, pluginDir string, p Plugin) {
	t.Helper()
	if p.Name == "" || p.Package == "" {
		t.Fatalf("plugin %+v needs both a Name and a Package", p)
	}
	out := filepath.Join(pluginDir, p.Name)
	cmd := exec.Command("go", "build", "-o", out, p.Package)
	// Dir empty leaves the build in the test's module, which is the historical behaviour.
	cmd.Dir = p.Dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building plugin %s (%s) in %q failed: %v\n%s",
			p.Name, p.Package, cmd.Dir, err, combined)
	}
}

// freeAddr reserves a loopback port by binding and releasing it. The dev server
// takes the port moments later; a fixed 8200 would collide with whatever the
// developer running the tests already has listening.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port failed: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing the reserved port failed: %v", err)
	}
	return addr
}

func (c *Cluster) awaitReady() {
	c.t.Helper()
	for range pollAttempts {
		if c.mountRoundTrips() {
			return
		}
		time.Sleep(pollInterval)
	}
	c.t.Fatalf("the dev server never round-tripped a mount within %s; log:\n%s",
		time.Duration(pollAttempts)*pollInterval, c.LogTail())
}

// mountRoundTrips gates on the operation this layer depends on rather than on
// sys/health alone: enable a throwaway mount, confirm it lists, remove it.
func (c *Cluster) mountRoundTrips() bool {
	health, err := c.client.Sys().Health()
	if err != nil || !health.Initialized || health.Sealed {
		return false
	}
	if err := c.client.Sys().Mount(readinessMount, &api.MountInput{Type: "kv"}); err != nil {
		return false
	}
	mounts, err := c.client.Sys().ListMounts()
	if err != nil {
		return false
	}
	_, listed := mounts[readinessMount+"/"]
	if err := c.client.Sys().Unmount(readinessMount); err != nil {
		c.t.Logf("removing the readiness probe mount failed: %v", err)
	}
	return listed
}

// Enable registers the plugin binary in the catalog under its own name and mounts
// it at mountPath.
func (c *Cluster) Enable(plugin, mountPath string) {
	c.t.Helper()
	if err := c.client.Sys().RegisterPlugin(&api.RegisterPluginInput{
		Name:    plugin,
		Type:    api.PluginTypeSecrets,
		Command: plugin,
		SHA256:  fileSHA256(c.t, filepath.Join(c.pluginDir, plugin)),
	}); err != nil {
		c.t.Fatalf("registering plugin %s failed: %v\nlog:\n%s", plugin, err, c.LogTail())
	}
	if err := c.client.Sys().Mount(mountPath, &api.MountInput{Type: plugin}); err != nil {
		c.t.Fatalf("mounting plugin %s at %s failed: %v\nlog:\n%s", plugin, mountPath, err, c.LogTail())
	}
	for range pollAttempts {
		mounts, err := c.client.Sys().ListMounts()
		if err == nil {
			if _, ok := mounts[mountPath+"/"]; ok {
				return
			}
		}
		time.Sleep(pollInterval)
	}
	c.t.Fatalf("mount %s reported success but never listed\nlog:\n%s", mountPath, c.LogTail())
}

func (c *Cluster) Unmount(mountPath string) {
	c.t.Helper()
	if err := c.client.Sys().Unmount(mountPath); err != nil {
		c.t.Errorf("unmounting %s failed: %v", mountPath, err)
	}
}

// Reload rebuilds every backend instance of the plugin from storage alone — the
// production path a plugin reload or a raft failover takes.
func (c *Cluster) Reload(plugin string) {
	c.t.Helper()
	if _, err := c.client.Sys().ReloadPlugin(&api.ReloadPluginInput{Plugin: plugin}); err != nil {
		c.t.Fatalf("reloading plugin %s failed: %v\nlog:\n%s", plugin, err, c.LogTail())
	}
}

// Write performs a write and returns whatever the endpoint answered, which for most of them
// is nothing — a caller ignoring the result is the common case. The endpoints that DO answer
// need it read back here rather than inferred: a report assembled by the plugin has crossed
// the RPC boundary and OpenBao's JSON layer by the time a client sees it, and its numbers
// arrive as json.Number.
func (c *Cluster) Write(path string, data map[string]interface{}) *api.Secret {
	c.t.Helper()
	secret, err := c.client.Logical().Write(path, data)
	if err != nil {
		c.t.Fatalf("write %s failed: %v\nlog:\n%s", path, err, c.LogTail())
	}
	return secret
}

// WriteExpectingError is for the writes that MUST be refused. It returns the error so the
// caller can assert on the code the client actually receives.
func (c *Cluster) WriteExpectingError(path string, data map[string]interface{}) error {
	c.t.Helper()
	secret, err := c.client.Logical().Write(path, data)
	if err == nil {
		c.t.Fatalf("write %s was expected to fail; it returned %v", path, secret)
	}
	return err
}

func (c *Cluster) Read(path string) *api.Secret {
	c.t.Helper()
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		c.t.Fatalf("read %s failed: %v\nlog:\n%s", path, err, c.LogTail())
	}
	if secret == nil {
		c.t.Fatalf("read %s returned no secret", path)
	}
	return secret
}

// ReadWithData is a read carrying query parameters. It exists for credential_kind: a
// shape pin is passed on a READ, so it travels as a query parameter through
// OpenBao's HTTP layer and the plugin RPC boundary before reaching
// framework.FieldData — a path no in-process test exercises, because those call the
// handler with a Data map directly.
func (c *Cluster) ReadWithData(path string, data map[string][]string) *api.Secret {
	c.t.Helper()
	secret, err := c.client.Logical().ReadWithData(path, data)
	if err != nil {
		c.t.Fatalf("read %s with %v failed: %v\nlog:\n%s", path, data, err, c.LogTail())
	}
	if secret == nil {
		c.t.Fatalf("read %s with %v returned no secret", path, data)
	}
	return secret
}

// ReadExpectingError is for the requests that MUST be refused. It returns the error
// so the caller can assert on the code the client actually receives.
func (c *Cluster) ReadExpectingError(path string, data map[string][]string) error {
	c.t.Helper()
	secret, err := c.client.Logical().ReadWithData(path, data)
	if err == nil {
		c.t.Fatalf("read %s with %v was expected to fail; it returned %v", path, data, secret)
	}
	return err
}

// LogTail returns the end of the dev server's log, which is where a plugin's own
// output goes. It is included in every failure message from this package, because a
// plugin running as a child process reports its problems nowhere else.
func (c *Cluster) LogTail() string {
	info, err := os.Stat(c.logPath)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	f, err := os.Open(c.logPath)
	if err != nil {
		return fmt.Sprintf("(no log: %v)", err)
	}
	defer func() { _ = f.Close() }()

	offset := int64(0)
	if info.Size() > logTailBytes {
		offset = info.Size() - logTailBytes
	}
	buf := make([]byte, info.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Sprintf("(unreadable log: %v)", err)
	}
	return string(buf)
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s to hash it failed: %v", path, err)
	}
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
