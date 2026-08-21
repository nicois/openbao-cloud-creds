package credentialgcp

import (
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/worker"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestBackend_CleanStopsWorkers verifies that after framework.Backend.Clean is
// invoked (backend unmount/reload), the worker manager is drained — goroutines
// stopped, not leaked.
func TestBackend_CleanStopsWorkers(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	lb, err := Factory(t.Context(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	bk := lb.(*backend)
	storage := config.StorageView

	// Populate b.config directly (startWorkers returns early if config==nil).
	// We avoid the HandleRequest("config") path on purpose: pathConfigWrite
	// launches its own async `go startWorkers`, which would race this test's
	// synchronous startWorkers and direct field reads.
	bk.mu.Lock()
	bk.config = cloudconfig.DefaultConfig("gcp")
	bk.mu.Unlock()

	// Start workers synchronously to guarantee a running manager.
	bk.startWorkers(t.Context(), storage)
	if mgr := bk.runningManager(); mgr == nil || !mgr.Running() {
		t.Fatal("expected workers running after startWorkers")
	}

	bk.Clean(t.Context())

	if mgr := bk.runningManager(); mgr != nil && mgr.Running() {
		t.Fatal("workers still running after Clean")
	}
}

// runningManager reads workerMgr under b.mu (matching the production locking).
func (b *backend) runningManager() *worker.Manager {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.workerMgr
}
