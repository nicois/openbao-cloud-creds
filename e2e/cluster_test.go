//go:build e2e

package e2e

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
	modulePrefix = "github.com/nicois/openbao-cloud-creds"
	rootToken    = "root"

	// The readiness gate and the post-enable check both poll: neither the seal
	// state nor a successful `enable` guarantees the mount table serves a
	// subsequent read coherently (scripts/registration-smoke-test.sh learned
	// this the hard way in CI, on a different plugin each run).
	pollInterval = 250 * time.Millisecond
	pollAttempts = 120

	readinessMount = "e2e-readiness-probe"
	logTailBytes   = 16384
)

// cluster is a live OpenBao dev server with this repo's plugin binaries in its
// plugin directory, plus a root-token API client for driving it.
type cluster struct {
	t         *testing.T
	client    *api.Client
	pluginDir string
	logPath   string
}

// startCluster builds each named plugin as a binary, starts a dev server over
// that plugin directory, and returns once the mount subsystem verifiably serves
// write-then-read.
func startCluster(t *testing.T, plugins ...string) *cluster {
	t.Helper()

	bao := baoBinary(t)
	work := t.TempDir()
	// Only plugin binaries may live in the plugin dir: bao tries to exec every
	// file it finds there.
	pluginDir := filepath.Join(work, "plugins")
	if err := os.Mkdir(pluginDir, 0o755); err != nil {
		t.Fatalf("creating the plugin dir failed: %v", err)
	}
	for _, name := range plugins {
		buildPlugin(t, pluginDir, name)
	}

	addr := freeAddr(t)
	logPath := filepath.Join(work, "bao.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("creating the server log failed: %v", err)
	}

	cmd := exec.Command(bao, "server", "-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address="+addr,
		"-dev-plugin-dir="+pluginDir,
		// Never write the operator's ~/.bao-token: this is a throwaway server
		// in someone's real shell session.
		"-dev-no-store-token",
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the dev server failed: %v", err)
	}

	c := &cluster{t: t, pluginDir: pluginDir, logPath: logPath}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
		if t.Failed() {
			t.Logf("dev server log (tail):\n%s", c.logTail())
		}
	})

	cfg := api.DefaultConfig()
	cfg.Address = "http://" + addr
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("building the API client failed: %v", err)
	}
	client.SetToken(rootToken)
	c.client = client

	c.awaitReady()
	return c
}

// baoBinary locates the OpenBao binary. Absence is a failure, not a skip: this
// package only compiles under `-tags=e2e`, which is already the opt-in.
func baoBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bao")
	if err != nil {
		t.Fatalf("the e2e layer needs an OpenBao binary on PATH (`bao`): %v", err)
	}
	return path
}

func buildPlugin(t *testing.T, pluginDir, name string) {
	t.Helper()
	out := filepath.Join(pluginDir, name)
	cmd := exec.Command("go", "build", "-o", out, modulePrefix+"/plugins/"+name+"/cmd")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building plugin %s failed: %v\n%s", name, err, combined)
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

func (c *cluster) awaitReady() {
	c.t.Helper()
	for range pollAttempts {
		if c.mountRoundTrips() {
			return
		}
		time.Sleep(pollInterval)
	}
	c.t.Fatalf("the dev server never round-tripped a mount within %s; log:\n%s",
		time.Duration(pollAttempts)*pollInterval, c.logTail())
}

// mountRoundTrips gates on the operation this package depends on rather than on
// sys/health alone: enable a throwaway mount, confirm it lists, remove it.
func (c *cluster) mountRoundTrips() bool {
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

// enable registers the plugin binary in the catalog under its own name and
// mounts it at mountPath.
func (c *cluster) enable(plugin, mountPath string) {
	c.t.Helper()
	if err := c.client.Sys().RegisterPlugin(&api.RegisterPluginInput{
		Name:    plugin,
		Type:    api.PluginTypeSecrets,
		Command: plugin,
		SHA256:  fileSHA256(c.t, filepath.Join(c.pluginDir, plugin)),
	}); err != nil {
		c.t.Fatalf("registering plugin %s failed: %v\nlog:\n%s", plugin, err, c.logTail())
	}
	if err := c.client.Sys().Mount(mountPath, &api.MountInput{Type: plugin}); err != nil {
		c.t.Fatalf("mounting plugin %s at %s failed: %v\nlog:\n%s", plugin, mountPath, err, c.logTail())
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
	c.t.Fatalf("mount %s reported success but never listed\nlog:\n%s", mountPath, c.logTail())
}

func (c *cluster) unmount(mountPath string) {
	c.t.Helper()
	if err := c.client.Sys().Unmount(mountPath); err != nil {
		c.t.Errorf("unmounting %s failed: %v", mountPath, err)
	}
}

// reload rebuilds every backend instance of the plugin from storage alone — the
// production path a plugin reload or a raft failover takes.
func (c *cluster) reload(plugin string) {
	c.t.Helper()
	if _, err := c.client.Sys().ReloadPlugin(&api.ReloadPluginInput{Plugin: plugin}); err != nil {
		c.t.Fatalf("reloading plugin %s failed: %v\nlog:\n%s", plugin, err, c.logTail())
	}
}

func (c *cluster) write(path string, data map[string]interface{}) {
	c.t.Helper()
	if _, err := c.client.Logical().Write(path, data); err != nil {
		c.t.Fatalf("write %s failed: %v\nlog:\n%s", path, err, c.logTail())
	}
}

func (c *cluster) read(path string) *api.Secret {
	c.t.Helper()
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		c.t.Fatalf("read %s failed: %v\nlog:\n%s", path, err, c.logTail())
	}
	if secret == nil {
		c.t.Fatalf("read %s returned no secret", path)
	}
	return secret
}

func (c *cluster) logTail() string {
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
