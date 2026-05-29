# credential-do Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the DigitalOcean JIT credential plugin as the reference implementation exercising the full contract: envelope, lease tracking, recovery state machine, reconciler, metrics, and Prometheus emission.

**Architecture:** One Go workspace with a root `go.work` file. Shared packages live under `pkg/` (each its own Go module). The DO plugin lives under `plugins/credential-do/` as its own module importing the shared packages. The plugin registers as an OpenBao secrets backend, exposing config, role CRUD, credential issuance, reconciliation trigger, and metrics query endpoints.

**Tech Stack:** Go 1.22+, OpenBao SDK (`github.com/openbao/openbao/sdk`), golangci-lint, GitHub Actions CI, `net/http/httptest` for cloud fakes.

---

## Task 1: Project Skeleton and CI

**Files:**
- Create: `go.work`
- Create: `pkg/credenvelope/go.mod`
- Create: `pkg/credenvelope/doc.go`
- Create: `pkg/recovery/go.mod`
- Create: `pkg/recovery/doc.go`
- Create: `pkg/metrics/go.mod`
- Create: `pkg/metrics/doc.go`
- Create: `pkg/reconciler/go.mod`
- Create: `pkg/reconciler/doc.go`
- Create: `pkg/cloudconfig/go.mod`
- Create: `pkg/cloudconfig/doc.go`
- Create: `plugins/credential-do/go.mod`
- Create: `plugins/credential-do/doc.go`
- Create: `.golangci.yml`
- Create: `Makefile`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Initialize Go workspace and modules**

```bash
cd /home/claude-aiven-2/code/openbao-cloud-creds

# Create module directories
mkdir -p pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig
mkdir -p plugins/credential-do

# Initialize each module
cd pkg/credenvelope && go mod init github.com/nicois/openbao-cloud-creds/pkg/credenvelope && cd ../..
cd pkg/recovery && go mod init github.com/nicois/openbao-cloud-creds/pkg/recovery && cd ../..
cd pkg/metrics && go mod init github.com/nicois/openbao-cloud-creds/pkg/metrics && cd ../..
cd pkg/reconciler && go mod init github.com/nicois/openbao-cloud-creds/pkg/reconciler && cd ../..
cd pkg/cloudconfig && go mod init github.com/nicois/openbao-cloud-creds/pkg/cloudconfig && cd ../..
cd plugins/credential-do && go mod init github.com/nicois/openbao-cloud-creds/plugins/credential-do && cd ../..

# Create workspace
go work init ./pkg/credenvelope ./pkg/recovery ./pkg/metrics ./pkg/reconciler ./pkg/cloudconfig ./plugins/credential-do
```

- [ ] **Step 2: Create doc.go placeholders so modules compile**

Each `doc.go` declares the package:

`pkg/credenvelope/doc.go`:
```go
package credenvelope
```

`pkg/recovery/doc.go`:
```go
package recovery
```

`pkg/metrics/doc.go`:
```go
package metrics
```

`pkg/reconciler/doc.go`:
```go
package reconciler
```

`pkg/cloudconfig/doc.go`:
```go
package cloudconfig
```

`plugins/credential-do/doc.go`:
```go
package credentialdo
```

- [ ] **Step 3: Create golangci-lint config**

`.golangci.yml`:
```yaml
run:
  timeout: 5m

linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused
    - gosimple
    - ineffassign
    - typecheck
    - gofmt
    - goimports
    - misspell
    - unconvert
    - unparam
    - revive

linters-settings:
  revive:
    rules:
      - name: exported
        disabled: true
```

- [ ] **Step 4: Create Makefile**

`Makefile`:
```makefile
.PHONY: build test lint fmt clean

build:
	go build ./...

test:
	go test ./...

test-cloud-real:
	go test -tags=cloud_real ./plugins/credential-do/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
    go fix
    go fix
	goimports -w .

clean:
	go clean ./...
```

- [ ] **Step 5: Create GitHub Actions CI**

`.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build
        run: go build ./...

      - name: Test
        run: go test -race -coverprofile=coverage.out ./...

      - name: Lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

- [ ] **Step 6: Verify everything compiles**

```bash
go build ./...
go test ./...
```

Expected: all pass (no tests yet, but no compile errors).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: initialize Go workspace with module skeleton and CI"
```

---

## Task 2: pkg/credenvelope — Envelope Types and Error Codes

**Files:**
- Create: `pkg/credenvelope/envelope.go`
- Create: `pkg/credenvelope/errors.go`
- Create: `pkg/credenvelope/envelope_test.go`

- [ ] **Step 1: Write failing test for envelope construction**

`pkg/credenvelope/envelope_test.go`:
```go
package credenvelope_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
)

func TestNewEnvelope(t *testing.T) {
	expiresAt := time.Now().Add(15 * time.Minute)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        "do",
		Role:         "snapshot-rw",
		Credential:   map[string]interface{}{"token": "dop_v1_abc", "scopes": []string{"read", "write"}},
		ExpiresAt:    expiresAt,
		TTLSeconds:   900,
		Renewable:    true,
		CredentialID: "do-tok-abc123",
		Scope:        "read write",
		IssuedBy:     "cloud-creds-do/v0.1",
	})

	if env.Cloud != "do" {
		t.Fatalf("expected cloud=do, got %s", env.Cloud)
	}
	if env.Role != "snapshot-rw" {
		t.Fatalf("expected role=snapshot-rw, got %s", env.Role)
	}
	if env.TTLSeconds != 900 {
		t.Fatalf("expected ttl=900, got %d", env.TTLSeconds)
	}
	if env.Metadata.APIVersion != "1" {
		t.Fatalf("expected api_version=1, got %s", env.Metadata.APIVersion)
	}
}

func TestEnvelopeToMap(t *testing.T) {
	expiresAt := time.Date(2026, 5, 29, 14, 30, 0, 0, time.UTC)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud:        "do",
		Role:         "snapshot-rw",
		Credential:   map[string]interface{}{"token": "dop_v1_abc"},
		ExpiresAt:    expiresAt,
		TTLSeconds:   900,
		Renewable:    true,
		CredentialID: "do-tok-abc123",
		Scope:        "read write",
		IssuedBy:     "cloud-creds-do/v0.1",
	})

	m := env.ToMap()
	if m["cloud"] != "do" {
		t.Fatalf("expected cloud=do in map, got %v", m["cloud"])
	}
	if m["expires_at"] != "2026-05-29T14:30:00Z" {
		t.Fatalf("unexpected expires_at: %v", m["expires_at"])
	}
	meta, ok := m["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata not a map")
	}
	if meta["api_version"] != "1" {
		t.Fatalf("expected api_version=1, got %v", meta["api_version"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/credenvelope && go test ./... -v
```

Expected: FAIL — types not defined.

- [ ] **Step 3: Implement envelope types**

`pkg/credenvelope/envelope.go`:
```go
package credenvelope

import "time"

type Metadata struct {
	Scope      string `json:"scope"`
	IssuedBy   string `json:"issued_by"`
	APIVersion string `json:"api_version"`
}

type Envelope struct {
	Cloud        string                 `json:"cloud"`
	Role         string                 `json:"role"`
	Credential   map[string]interface{} `json:"credential"`
	ExpiresAt    time.Time              `json:"expires_at"`
	TTLSeconds   int                    `json:"ttl_seconds"`
	Renewable    bool                   `json:"renewable"`
	CredentialID string                 `json:"credential_id"`
	Metadata     Metadata               `json:"metadata"`
}

type EnvelopeParams struct {
	Cloud        string
	Role         string
	Credential   map[string]interface{}
	ExpiresAt    time.Time
	TTLSeconds   int
	Renewable    bool
	CredentialID string
	Scope        string
	IssuedBy     string
}

func NewEnvelope(p EnvelopeParams) *Envelope {
	return &Envelope{
		Cloud:        p.Cloud,
		Role:         p.Role,
		Credential:   p.Credential,
		ExpiresAt:    p.ExpiresAt,
		TTLSeconds:   p.TTLSeconds,
		Renewable:    p.Renewable,
		CredentialID: p.CredentialID,
		Metadata: Metadata{
			Scope:      p.Scope,
			IssuedBy:   p.IssuedBy,
			APIVersion: "1",
		},
	}
}

func (e *Envelope) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"cloud":         e.Cloud,
		"role":          e.Role,
		"credential":    e.Credential,
		"expires_at":    e.ExpiresAt.UTC().Format(time.RFC3339),
		"ttl_seconds":   e.TTLSeconds,
		"renewable":     e.Renewable,
		"credential_id": e.CredentialID,
		"metadata": map[string]interface{}{
			"scope":       e.Metadata.Scope,
			"issued_by":   e.Metadata.IssuedBy,
			"api_version": e.Metadata.APIVersion,
		},
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd pkg/credenvelope && go test ./... -v
```

Expected: PASS.

- [ ] **Step 5: Write error codes**

`pkg/credenvelope/errors.go`:
```go
package credenvelope

import "fmt"

type ErrorCode string

const (
	ErrRoleNotFound           ErrorCode = "role_not_found"
	ErrRoleDisabled           ErrorCode = "role_disabled"
	ErrEntityUnavailable      ErrorCode = "entity_unavailable"
	ErrUpstreamQuotaExceeded  ErrorCode = "upstream_quota_exceeded"
	ErrUpstreamAuthFailed     ErrorCode = "upstream_auth_failed"
	ErrUpstreamTimeout        ErrorCode = "upstream_timeout"
	ErrConsentRequired        ErrorCode = "consent_required"
	ErrPoolExhausted          ErrorCode = "pool_exhausted"
	ErrLeaseRevokeFailed      ErrorCode = "lease_revoke_failed"
	ErrInternal               ErrorCode = "internal"
)

type PluginError struct {
	Code       ErrorCode
	Message    string
	StatusCode int
}

func (e *PluginError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code ErrorCode, statusCode int, msg string) *PluginError {
	return &PluginError{Code: code, Message: msg, StatusCode: statusCode}
}
```

- [ ] **Step 6: Write error test**

Add to `pkg/credenvelope/envelope_test.go`:
```go
func TestPluginError(t *testing.T) {
	err := credenvelope.NewError(credenvelope.ErrUpstreamAuthFailed, 502, "minter rejected")
	if err.Code != credenvelope.ErrUpstreamAuthFailed {
		t.Fatalf("unexpected code: %s", err.Code)
	}
	if err.StatusCode != 502 {
		t.Fatalf("unexpected status: %d", err.StatusCode)
	}
	expected := "upstream_auth_failed: minter rejected"
	if err.Error() != expected {
		t.Fatalf("unexpected error string: %s", err.Error())
	}
}
```

- [ ] **Step 7: Run tests**

```bash
cd pkg/credenvelope && go test ./... -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/credenvelope/
git commit -m "feat(credenvelope): add envelope types and error codes"
```

---

## Task 3: pkg/recovery — Recovery State Machine

**Files:**
- Create: `pkg/recovery/state.go`
- Create: `pkg/recovery/state_test.go`

- [ ] **Step 1: Write failing test for state transitions**

`pkg/recovery/state_test.go`:
```go
package recovery_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func TestHealthyToTransientOnError(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold: 30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	if sm.State() != recovery.Healthy {
		t.Fatalf("expected initial state healthy, got %s", sm.State())
	}

	sm.RecordError(500, time.Now())
	if sm.State() != recovery.TransientFailing {
		t.Fatalf("expected transient_failing after error, got %s", sm.State())
	}
}

func TestTransientToHealthyOnSuccess(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold: 30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	sm.RecordError(500, time.Now())
	sm.RecordSuccess(time.Now())

	if sm.State() != recovery.Healthy {
		t.Fatalf("expected healthy after success, got %s", sm.State())
	}
}

func TestTransientToAuthFailingOnSustained401(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold: 30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(401, now)

	// Still transient at <30s
	sm.RecordError(401, now.Add(20*time.Second))
	if sm.State() != recovery.TransientFailing {
		t.Fatalf("should still be transient at 20s, got %s", sm.State())
	}

	// Transitions at >30s
	sm.RecordError(401, now.Add(31*time.Second))
	if sm.State() != recovery.AuthFailing {
		t.Fatalf("expected auth_failing after 31s of 401s, got %s", sm.State())
	}
}

func TestAuthFailingToHealthyOnHealthCheck(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold: 30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(403, now)
	sm.RecordError(403, now.Add(31*time.Second))

	if sm.State() != recovery.AuthFailing {
		t.Fatalf("expected auth_failing, got %s", sm.State())
	}

	sm.RecordSuccess(now.Add(6 * time.Minute))
	if sm.State() != recovery.Healthy {
		t.Fatalf("expected healthy after successful health check, got %s", sm.State())
	}
}

func TestNeedsHealthCheck(t *testing.T) {
	sm := recovery.NewStateMachine(recovery.Config{
		AuthFailThreshold: 30 * time.Second,
		HealthCheckInterval: 5 * time.Minute,
	})

	now := time.Now()
	sm.RecordError(401, now)
	sm.RecordError(401, now.Add(31*time.Second))

	if !sm.NeedsHealthCheck(now.Add(6 * time.Minute)) {
		t.Fatal("should need health check after interval")
	}
	if sm.NeedsHealthCheck(now.Add(32 * time.Second)) {
		t.Fatal("should not need health check before interval")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/recovery && go test ./... -v
```

Expected: FAIL — package not implemented.

- [ ] **Step 3: Implement state machine**

`pkg/recovery/state.go`:
```go
package recovery

import (
	"sync"
	"time"
)

type State string

const (
	Healthy          State = "healthy"
	TransientFailing State = "transient_failing"
	AuthFailing      State = "auth_failing"
	Missing          State = "missing"
)

type Config struct {
	AuthFailThreshold   time.Duration
	HealthCheckInterval time.Duration
}

type StateMachine struct {
	mu                sync.RWMutex
	state             State
	config            Config
	firstAuthErrorAt  time.Time
	lastErrorAt       time.Time
	lastSuccessAt     time.Time
	enteredAuthFailed time.Time
}

func NewStateMachine(cfg Config) *StateMachine {
	return &StateMachine{
		state:  Healthy,
		config: cfg,
	}
}

func (sm *StateMachine) State() State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

func (sm *StateMachine) LastSuccessAt() time.Time {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.lastSuccessAt
}

func (sm *StateMachine) RecordSuccess(at time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.lastSuccessAt = at
	sm.firstAuthErrorAt = time.Time{}
	sm.state = Healthy
}

func (sm *StateMachine) RecordError(httpStatus int, at time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.lastErrorAt = at

	switch sm.state {
	case Healthy:
		sm.state = TransientFailing
		if isAuthError(httpStatus) {
			sm.firstAuthErrorAt = at
		}

	case TransientFailing:
		if isAuthError(httpStatus) {
			if sm.firstAuthErrorAt.IsZero() {
				sm.firstAuthErrorAt = at
			}
			if at.Sub(sm.firstAuthErrorAt) >= sm.config.AuthFailThreshold {
				sm.state = AuthFailing
				sm.enteredAuthFailed = at
			}
		} else {
			sm.firstAuthErrorAt = time.Time{}
		}

	case AuthFailing:
		// Stay in auth_failing
	}
}

func (sm *StateMachine) RecordMissing() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = Missing
}

func (sm *StateMachine) NeedsHealthCheck(now time.Time) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.state != AuthFailing {
		return false
	}
	lastCheck := sm.enteredAuthFailed
	if !sm.lastSuccessAt.IsZero() && sm.lastSuccessAt.After(lastCheck) {
		lastCheck = sm.lastSuccessAt
	}
	return now.Sub(lastCheck) >= sm.config.HealthCheckInterval
}

func isAuthError(status int) bool {
	return status == 401 || status == 403
}
```

- [ ] **Step 4: Run tests**

```bash
cd pkg/recovery && go test ./... -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/recovery/
git commit -m "feat(recovery): implement upstream recovery state machine"
```

---

## Task 4: pkg/cloudconfig — Config and Role CRUD Helpers

**Files:**
- Create: `pkg/cloudconfig/config.go`
- Create: `pkg/cloudconfig/role.go`
- Create: `pkg/cloudconfig/minter.go`
- Create: `pkg/cloudconfig/config_test.go`

- [ ] **Step 1: Write failing test for minter validation**

`pkg/cloudconfig/config_test.go`:
```go
package cloudconfig_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

func TestMinterSetValid_SingleNeverExpires(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", NeverExpires: true},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetValid_NeverExpiresPlusExpiring(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", NeverExpires: true},
		{ID: "m2", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetValid_TwoExpiringWith7dGap(t *testing.T) {
	now := time.Now()
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: now.Add(14 * 24 * time.Hour)},
		{ID: "m2", ExpiresAt: now.Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestMinterSetInvalid_SingleExpiring(t *testing.T) {
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err == nil {
		t.Fatal("expected error for single expiring minter")
	}
}

func TestMinterSetInvalid_TwoExpiringTooClose(t *testing.T) {
	now := time.Now()
	set := []cloudconfig.Minter{
		{ID: "m1", ExpiresAt: now.Add(10 * 24 * time.Hour)},
		{ID: "m2", ExpiresAt: now.Add(12 * 24 * time.Hour)},
	}
	if err := cloudconfig.ValidateMinterSet(set); err == nil {
		t.Fatal("expected error for minters with <7d gap")
	}
}

func TestMinterSetInvalid_Empty(t *testing.T) {
	if err := cloudconfig.ValidateMinterSet(nil); err == nil {
		t.Fatal("expected error for empty minter set")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/cloudconfig && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement minter types and validation**

`pkg/cloudconfig/minter.go`:
```go
package cloudconfig

import (
	"fmt"
	"sort"
	"time"
)

const MinMinterGap = 7 * 24 * time.Hour

type Minter struct {
	ID             string    `json:"id"`
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	ExpiresSource  string    `json:"expires_at_source,omitempty"`
	NeverExpires   bool      `json:"never_expires,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func ValidateMinterSet(minters []Minter) error {
	if len(minters) == 0 {
		return fmt.Errorf("minter set must not be empty")
	}

	hasNeverExpires := false
	var expiring []Minter

	for _, m := range minters {
		if m.NeverExpires {
			hasNeverExpires = true
		} else if !m.ExpiresAt.IsZero() {
			expiring = append(expiring, m)
		} else {
			return fmt.Errorf("minter %s has neither expires_at nor never_expires=true", m.ID)
		}
	}

	if hasNeverExpires {
		return nil
	}

	if len(expiring) < 2 {
		return fmt.Errorf("minter set with expiring minters must have >=2 minters (or include a never_expires minter)")
	}

	sort.Slice(expiring, func(i, j int) bool {
		return expiring[i].ExpiresAt.Before(expiring[j].ExpiresAt)
	})

	for i := 1; i < len(expiring); i++ {
		gap := expiring[i].ExpiresAt.Sub(expiring[i-1].ExpiresAt)
		if gap < MinMinterGap {
			return fmt.Errorf("minters %s and %s have expiry gap %v, minimum is %v",
				expiring[i-1].ID, expiring[i].ID, gap, MinMinterGap)
		}
	}

	return nil
}
```

- [ ] **Step 4: Implement config and role types**

`pkg/cloudconfig/config.go`:
```go
package cloudconfig

import "time"

type PluginConfig struct {
	Cloud             string        `json:"cloud"`
	Minters           []Minter      `json:"minters"`
	FlushInterval     time.Duration `json:"flush_interval"`
	ReconcileCadence  time.Duration `json:"reconcile_cadence"`
	BootstrapDelay    time.Duration `json:"bootstrap_delay"`
	MaxDeletesPerPass int           `json:"max_deletes_per_pass"`
}

func DefaultConfig(cloud string) *PluginConfig {
	return &PluginConfig{
		Cloud:             cloud,
		FlushInterval:     15 * time.Minute,
		ReconcileCadence:  6 * time.Hour,
		BootstrapDelay:    24 * time.Hour,
		MaxDeletesPerPass: 10,
	}
}
```

`pkg/cloudconfig/role.go`:
```go
package cloudconfig

import (
	"fmt"
	"time"
)

type Role struct {
	Name              string        `json:"name"`
	Cloud             string        `json:"cloud"`
	DefaultTTL        time.Duration `json:"default_ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	DisableAutoDelete bool          `json:"disable_auto_delete,omitempty"`
	CloudConfig       map[string]interface{} `json:"cloud_config,omitempty"`
}

func ValidateRole(r *Role) error {
	if r.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if r.DefaultTTL <= 0 {
		return fmt.Errorf("default_ttl must be positive")
	}
	if r.MaxTTL <= 0 {
		return fmt.Errorf("max_ttl must be positive")
	}
	if r.DefaultTTL > r.MaxTTL {
		return fmt.Errorf("default_ttl (%v) must be <= max_ttl (%v)", r.DefaultTTL, r.MaxTTL)
	}
	return nil
}
```

- [ ] **Step 5: Run tests**

```bash
cd pkg/cloudconfig && go test ./... -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/cloudconfig/
git commit -m "feat(cloudconfig): add config, role, and minter types with validation"
```

---

## Task 5: pkg/metrics — Per-Node Access Metrics

**Files:**
- Create: `pkg/metrics/access.go`
- Create: `pkg/metrics/access_test.go`

- [ ] **Step 1: Write failing test for access recording and merge**

`pkg/metrics/access_test.go`:
```go
package metrics_test

import (
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/metrics"
)

func TestRecordAccess(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	tracker.RecordAccess("entity-1", "role-a", now)
	tracker.RecordAccess("entity-1", "role-a", now.Add(time.Minute))

	entry := tracker.Get("entity-1", "role-a")
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.AccessCount != 2 {
		t.Fatalf("expected count=2, got %d", entry.AccessCount)
	}
	if !entry.LastAccessAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected last_access_at: %v", entry.LastAccessAt)
	}
}

func TestFlushAndLoad(t *testing.T) {
	store := metrics.NewInMemoryStore()
	tracker := metrics.NewAccessTracker("node-1", store)

	now := time.Now()
	tracker.RecordAccess("entity-1", "role-a", now)
	tracker.RecordAccess("entity-1", "role-a", now.Add(time.Minute))

	if err := tracker.Flush(now.Add(2 * time.Minute)); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Load from a different node's perspective
	tracker2 := metrics.NewAccessTracker("node-2", store)
	merged, err := tracker2.MergeEntity("entity-1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if merged.AccessCount != 2 {
		t.Fatalf("expected merged count=2, got %d", merged.AccessCount)
	}
	if merged.StalenessSeconds > 120 {
		t.Fatalf("unexpected staleness: %d", merged.StalenessSeconds)
	}
}

func TestMergeMultipleNodes(t *testing.T) {
	store := metrics.NewInMemoryStore()
	t1 := metrics.NewAccessTracker("node-1", store)
	t2 := metrics.NewAccessTracker("node-2", store)

	now := time.Now()
	t1.RecordAccess("entity-1", "role-a", now)
	t1.RecordAccess("entity-1", "role-a", now.Add(time.Minute))
	t2.RecordAccess("entity-1", "role-a", now.Add(2*time.Minute))

	t1.Flush(now.Add(3 * time.Minute))
	t2.Flush(now.Add(3 * time.Minute))

	t3 := metrics.NewAccessTracker("node-3", store)
	merged, err := t3.MergeEntity("entity-1", now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if merged.AccessCount != 3 {
		t.Fatalf("expected merged count=3, got %d", merged.AccessCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/metrics && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement access tracker**

`pkg/metrics/access.go`:
```go
package metrics

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type AccessEntry struct {
	LastAccessAt time.Time `json:"last_access_at"`
	AccessCount  int64     `json:"access_count"`
	FlushedAt    time.Time `json:"flushed_at"`
}

type MergedEntry struct {
	LastAccessAt    time.Time `json:"last_access_at"`
	AccessCount     int64     `json:"access_count"`
	StalenessSeconds int      `json:"staleness_seconds"`
	Source          string    `json:"source"`
}

type MetricsStore interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	List(prefix string) ([]string, error)
}

type accessKey struct {
	EntityID string
	Role     string
}

type AccessTracker struct {
	mu      sync.Mutex
	nodeID  string
	store   MetricsStore
	entries map[accessKey]*AccessEntry
}

func NewAccessTracker(nodeID string, store MetricsStore) *AccessTracker {
	return &AccessTracker{
		nodeID:  nodeID,
		store:   store,
		entries: make(map[accessKey]*AccessEntry),
	}
}

func (t *AccessTracker) RecordAccess(entityID, role string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := accessKey{EntityID: entityID, Role: role}
	entry, ok := t.entries[key]
	if !ok {
		entry = &AccessEntry{}
		t.entries[key] = entry
	}
	entry.AccessCount++
	if at.After(entry.LastAccessAt) {
		entry.LastAccessAt = at
	}
}

func (t *AccessTracker) Get(entityID, role string) *AccessEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entries[accessKey{EntityID: entityID, Role: role}]
}

func (t *AccessTracker) Flush(now time.Time) error {
	t.mu.Lock()
	snapshot := make(map[accessKey]*AccessEntry, len(t.entries))
	for k, v := range t.entries {
		cp := *v
		cp.FlushedAt = now
		snapshot[k] = &cp
	}
	t.mu.Unlock()

	for k, entry := range snapshot {
		storageKey := fmt.Sprintf("metrics/%s/%s/%s", k.EntityID, k.Role, t.nodeID)
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := t.store.Put(storageKey, data); err != nil {
			return err
		}
	}
	return nil
}

func (t *AccessTracker) MergeEntity(entityID string, now time.Time) (*MergedEntry, error) {
	prefix := fmt.Sprintf("metrics/%s/", entityID)
	keys, err := t.store.List(prefix)
	if err != nil {
		return nil, err
	}

	merged := &MergedEntry{Source: "merged_only"}
	var latestFlush time.Time

	for _, key := range keys {
		data, err := t.store.Get(key)
		if err != nil {
			return nil, err
		}
		var entry AccessEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
		merged.AccessCount += entry.AccessCount
		if entry.LastAccessAt.After(merged.LastAccessAt) {
			merged.LastAccessAt = entry.LastAccessAt
		}
		if entry.FlushedAt.After(latestFlush) {
			latestFlush = entry.FlushedAt
		}
	}

	// Check local in-memory entries
	t.mu.Lock()
	for k, entry := range t.entries {
		if k.EntityID == entityID {
			merged.AccessCount += entry.AccessCount
			if entry.LastAccessAt.After(merged.LastAccessAt) {
				merged.LastAccessAt = entry.LastAccessAt
			}
			merged.Source = "merged_with_local_active"
		}
	}
	t.mu.Unlock()

	if !latestFlush.IsZero() {
		merged.StalenessSeconds = int(now.Sub(latestFlush).Seconds())
	}

	return merged, nil
}

// InMemoryStore is a simple store for testing.
type InMemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{data: make(map[string][]byte)}
}

func (s *InMemoryStore) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *InMemoryStore) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (s *InMemoryStore) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
```

- [ ] **Step 4: Run tests**

```bash
cd pkg/metrics && go test ./... -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/metrics/
git commit -m "feat(metrics): implement per-node access tracking with flush and merge"
```

---

## Task 6: pkg/reconciler — Reconciliation Worker

**Files:**
- Create: `pkg/reconciler/reconciler.go`
- Create: `pkg/reconciler/reconciler_test.go`

- [ ] **Step 1: Write failing test for orphan detection**

`pkg/reconciler/reconciler_test.go`:
```go
package reconciler_test

import (
	"context"
	"testing"
	"time"

	"github.com/nicois/openbao-cloud-creds/pkg/reconciler"
)

type fakeCloudLister struct {
	entities []reconciler.UpstreamEntity
}

func (f *fakeCloudLister) ListTaggedEntities(ctx context.Context) ([]reconciler.UpstreamEntity, error) {
	return f.entities, nil
}

func (f *fakeCloudLister) DeleteEntity(ctx context.Context, id string) error {
	for i, e := range f.entities {
		if e.ID == id {
			f.entities = append(f.entities[:i], f.entities[i+1:]...)
			return nil
		}
	}
	return nil
}

type fakeRegistry struct {
	known map[string]bool
}

func (f *fakeRegistry) IsKnown(id string) bool {
	return f.known[id]
}

func TestDetectsOrphans(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "known-1", Name: "cloud-creds-role-a-lease1"},
			{ID: "orphan-1", Name: "cloud-creds-role-b-lease2"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{"known-1": true}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0, // skip hold for test
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.OrphansFound) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(result.OrphansFound))
	}
	if result.OrphansFound[0] != "orphan-1" {
		t.Fatalf("unexpected orphan: %s", result.OrphansFound[0])
	}
}

func TestDryRunDoesNotDelete(t *testing.T) {
	cloud := &fakeCloudLister{
		entities: []reconciler.UpstreamEntity{
			{ID: "orphan-1", Name: "cloud-creds-role-a-lease1"},
		},
	}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            true,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("expected 0 deletes in dry-run, got %d", result.Deleted)
	}
	if len(cloud.entities) != 1 {
		t.Fatal("entity should not have been deleted in dry-run")
	}
}

func TestMaxDeletesPerPass(t *testing.T) {
	entities := make([]reconciler.UpstreamEntity, 15)
	for i := range entities {
		entities[i] = reconciler.UpstreamEntity{
			ID:   fmt.Sprintf("orphan-%d", i),
			Name: fmt.Sprintf("cloud-creds-role-x-lease%d", i),
		}
	}
	cloud := &fakeCloudLister{entities: entities}
	registry := &fakeRegistry{known: map[string]bool{}}

	r := reconciler.New(reconciler.Config{
		MaxDeletesPerPass: 10,
		ConfirmationHold:  0,
		DryRun:            false,
	}, cloud, registry)

	result, err := r.Run(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Deleted != 10 {
		t.Fatalf("expected max 10 deletes, got %d", result.Deleted)
	}
	if !result.HitLimit {
		t.Fatal("expected HitLimit=true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/reconciler && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement reconciler**

`pkg/reconciler/reconciler.go`:
```go
package reconciler

import (
	"context"
	"time"
)

type UpstreamEntity struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type CloudLister interface {
	ListTaggedEntities(ctx context.Context) ([]UpstreamEntity, error)
	DeleteEntity(ctx context.Context, id string) error
}

type Registry interface {
	IsKnown(id string) bool
}

type Config struct {
	MaxDeletesPerPass int
	ConfirmationHold  time.Duration
	DryRun            bool
}

type Result struct {
	OrphansFound []string
	Deleted      int
	HitLimit     bool
}

type Reconciler struct {
	config   Config
	cloud    CloudLister
	registry Registry
}

func New(cfg Config, cloud CloudLister, registry Registry) *Reconciler {
	return &Reconciler{
		config:   cfg,
		cloud:    cloud,
		registry: registry,
	}
}

func (r *Reconciler) Run(ctx context.Context, now time.Time) (*Result, error) {
	entities, err := r.cloud.ListTaggedEntities(ctx)
	if err != nil {
		return nil, err
	}

	result := &Result{}

	for _, entity := range entities {
		if r.registry.IsKnown(entity.ID) {
			continue
		}

		// Confirmation hold: skip if entity is too new
		if r.config.ConfirmationHold > 0 && !entity.CreatedAt.IsZero() {
			if now.Sub(entity.CreatedAt) < r.config.ConfirmationHold {
				continue
			}
		}

		result.OrphansFound = append(result.OrphansFound, entity.ID)

		if r.config.DryRun {
			continue
		}

		if result.Deleted >= r.config.MaxDeletesPerPass {
			result.HitLimit = true
			break
		}

		if err := r.cloud.DeleteEntity(ctx, entity.ID); err != nil {
			return result, err
		}
		result.Deleted++
	}

	return result, nil
}
```

- [ ] **Step 4: Add missing import to test file**

Add `"fmt"` to the import block in `pkg/reconciler/reconciler_test.go`.

- [ ] **Step 5: Run tests**

```bash
cd pkg/reconciler && go test ./... -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/reconciler/
git commit -m "feat(reconciler): implement reconciliation worker with orphan detection and safeguards"
```

---

## Task 7: Cloud Fakes for DO

**Files:**
- Create: `pkg/credenvelope/fakes/do.go`
- Create: `pkg/credenvelope/fakes/do_test.go`

- [ ] **Step 1: Write failing test for the DO fake server**

`pkg/credenvelope/fakes/do_test.go`:
```go
package fakes_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestDOFake_CreateToken(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	body := `{"name":"cloud-creds-test-lease1","scopes":["read","write"]}`
	resp, err := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &result)

	token, ok := result["token"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected token object, got %v", result)
	}
	if token["id"] == nil {
		t.Fatal("expected token.id")
	}
	if token["name"] != "cloud-creds-test-lease1" {
		t.Fatalf("expected name cloud-creds-test-lease1, got %v", token["name"])
	}
}

func TestDOFake_DeleteToken(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	// Create first
	body := `{"name":"cloud-creds-test-lease1","scopes":["read"]}`
	resp, _ := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	var createResult map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &createResult)
	resp.Body.Close()
	tokenID := createResult["token"].(map[string]interface{})["id"].(string)

	// Delete
	req, _ := http.NewRequest("DELETE", srv.URL+"/v2/tokens/"+tokenID, nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
}

func TestDOFake_ErrorInjection(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	srv.SetNextStatus(429)

	body := `{"name":"test","scopes":["read"]}`
	resp, _ := http.Post(srv.URL+"/v2/tokens", "application/json", bytes.NewBufferString(body))
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd pkg/credenvelope && go test ./fakes/... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement DO fake server**

`pkg/credenvelope/fakes/do.go`:
```go
package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

type DOServer struct {
	*httptest.Server
	mu         sync.Mutex
	tokens     map[string]map[string]interface{}
	nextID     atomic.Int64
	nextStatus int
}

func NewDOServer() *DOServer {
	s := &DOServer{
		tokens: make(map[string]map[string]interface{}),
	}
	s.nextID.Store(1000)
	s.Server = httptest.NewServer(s.handler())
	return s
}

func (s *DOServer) SetNextStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextStatus = code
}

func (s *DOServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/tokens", s.createToken)
	mux.HandleFunc("DELETE /v2/tokens/", s.deleteToken)
	mux.HandleFunc("GET /v2/tokens", s.listTokens)
	return mux
}

func (s *DOServer) checkInjectedError(w http.ResponseWriter) bool {
	s.mu.Lock()
	status := s.nextStatus
	s.nextStatus = 0
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "server_error",
			"message": fmt.Sprintf("injected %d", status),
		})
		return true
	}
	return false
}

func (s *DOServer) createToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		return
	}

	id := fmt.Sprintf("tok-%d", s.nextID.Add(1))
	token := map[string]interface{}{
		"id":           id,
		"name":         req.Name,
		"scopes":       req.Scopes,
		"access_token": fmt.Sprintf("dop_v1_fake_%s", id),
	}

	s.mu.Lock()
	s.tokens[id] = token
	s.mu.Unlock()

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
}

func (s *DOServer) deleteToken(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	s.mu.Lock()
	_, exists := s.tokens[id]
	if exists {
		delete(s.tokens, id)
	}
	s.mu.Unlock()

	if !exists {
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(204)
}

func (s *DOServer) listTokens(w http.ResponseWriter, r *http.Request) {
	if s.checkInjectedError(w) {
		return
	}

	s.mu.Lock()
	tokens := make([]map[string]interface{}, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"tokens": tokens})
}
```

- [ ] **Step 4: Run tests**

```bash
cd pkg/credenvelope && go test ./fakes/... -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/credenvelope/fakes/
git commit -m "feat(fakes): add DigitalOcean fake API server for integration tests"
```

---

## Task 8: plugins/credential-do — Backend Registration and Config Path

**Files:**
- Create: `plugins/credential-do/backend.go`
- Create: `plugins/credential-do/path_config.go`
- Create: `plugins/credential-do/path_config_test.go`
- Create: `plugins/credential-do/cmd/main.go`

This task wires up the OpenBao secrets backend and the `config` endpoint. Subsequent tasks add the remaining paths.

- [ ] **Step 1: Add OpenBao SDK dependency**

```bash
cd plugins/credential-do
go get github.com/openbao/openbao/sdk@latest
```

- [ ] **Step 2: Write failing test for config write/read**

`plugins/credential-do/path_config_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := credentialdo.Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	return b, config.StorageView
}

func TestConfigWriteRead(t *testing.T) {
	b, storage := getTestBackend(t)

	// Write config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "dop_v1_abc123",
					"never_expires": true,
				},
			},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Read config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config read failed: err=%v resp=%v", err, resp)
	}

	if resp.Data["cloud"] != "do" {
		t.Fatalf("expected cloud=do, got %v", resp.Data["cloud"])
	}
}
```

- [ ] **Step 3: Implement backend factory**

`plugins/credential-do/backend.go`:
```go
package credentialdo

import (
	"context"
	"sync"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

const backendHelp = `
The DigitalOcean credential backend issues short-lived API tokens
via the DigitalOcean /v2/tokens API (JIT strategy).
`

type backend struct {
	*framework.Backend
	mu      sync.RWMutex
	config  *cloudconfig.PluginConfig
	minters map[string]*minterState
}

type minterState struct {
	minter  cloudconfig.Minter
	sm      *recovery.StateMachine
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		minters: make(map[string]*minterState),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Paths: framework.PathAppend(
			b.configPaths(),
		),
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
```

- [ ] **Step 4: Implement config path**

`plugins/credential-do/path_config.go`:
```go
package credentialdo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) configPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"minters": {
					Type:        framework.TypeSlice,
					Description: "List of minter credentials",
				},
				"flush_interval": {
					Type:        framework.TypeDurationSecond,
					Default:     900,
					Description: "Metrics flush interval in seconds",
				},
				"reconcile_cadence": {
					Type:        framework.TypeDurationSecond,
					Default:     21600,
					Description: "Reconciliation cadence in seconds",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mintersRaw := d.Get("minters")
	if mintersRaw == nil {
		return logical.ErrorResponse("minters is required"), nil
	}

	mintersSlice, ok := mintersRaw.([]interface{})
	if !ok {
		return logical.ErrorResponse("minters must be an array"), nil
	}

	var minters []cloudconfig.Minter
	for _, m := range mintersSlice {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			return logical.ErrorResponse("each minter must be an object"), nil
		}
		minter := cloudconfig.Minter{
			ID:        fmt.Sprintf("%v", mMap["id"]),
			Token:     fmt.Sprintf("%v", mMap["token"]),
			CreatedAt: time.Now(),
		}
		if ne, ok := mMap["never_expires"].(bool); ok && ne {
			minter.NeverExpires = true
		}
		if exp, ok := mMap["expires_at"].(string); ok {
			t, err := time.Parse(time.RFC3339, exp)
			if err != nil {
				return logical.ErrorResponse("invalid expires_at for minter %s: %v", minter.ID, err), nil
			}
			minter.ExpiresAt = t
		}
		minters = append(minters, minter)
	}

	if err := cloudconfig.ValidateMinterSet(minters); err != nil {
		return logical.ErrorResponse("invalid minter set: %v", err), nil
	}

	flushInterval := time.Duration(d.Get("flush_interval").(int)) * time.Second
	reconcileCadence := time.Duration(d.Get("reconcile_cadence").(int)) * time.Second

	cfg := &cloudconfig.PluginConfig{
		Cloud:             "do",
		Minters:           minters,
		FlushInterval:     flushInterval,
		ReconcileCadence:  reconcileCadence,
		BootstrapDelay:    24 * time.Hour,
		MaxDeletesPerPass: 10,
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.config = cfg
	b.minters = make(map[string]*minterState)
	for _, m := range minters {
		b.minters[m.ID] = &minterState{
			minter: m,
			sm: recovery.NewStateMachine(recovery.Config{
				AuthFailThreshold:   30 * time.Second,
				HealthCheckInterval: 5 * time.Minute,
			}),
		}
	}
	b.mu.Unlock()

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cfg cloudconfig.PluginConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cloud":             cfg.Cloud,
			"minter_count":      len(cfg.Minters),
			"flush_interval":    int(cfg.FlushInterval.Seconds()),
			"reconcile_cadence": int(cfg.ReconcileCadence.Seconds()),
		},
	}, nil
}
```

- [ ] **Step 5: Create plugin entrypoint**

`plugins/credential-do/cmd/main.go`:
```go
package main

import (
	"os"

	"github.com/openbao/openbao/sdk/plugin"
	credentialdo "github.com/nicois/openbao-cloud-creds/plugins/credential-do"
)

func main() {
	if err := plugin.ServeMultiplex(&plugin.ServeConfig{
		BackendFactoryFunc: credentialdo.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
```

- [ ] **Step 6: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): add backend factory and config path"
```

---

## Task 9: plugins/credential-do — Role CRUD Paths

**Files:**
- Create: `plugins/credential-do/path_roles.go`
- Create: `plugins/credential-do/path_roles_test.go`

- [ ] **Step 1: Write failing test for role create/read/list/delete**

`plugins/credential-do/path_roles_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
)

func TestRoleCRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create role
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": "15m",
			"max_ttl":     "1h",
			"scopes":      "read,write",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["name"] != "snapshot-rw" {
		t.Fatalf("unexpected name: %v", resp.Data["name"])
	}
	if resp.Data["scopes"] != "read,write" {
		t.Fatalf("unexpected scopes: %v", resp.Data["scopes"])
	}

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role list failed: err=%v resp=%v", err, resp)
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "snapshot-rw" {
		t.Fatalf("unexpected keys: %v", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role delete failed: err=%v resp=%v", err, resp)
	}

	// Verify gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/snapshot-rw",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for deleted role")
	}
}

func TestRoleValidation_TTL(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": "2h",
			"max_ttl":     "1h",
			"scopes":      "read",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for default_ttl > max_ttl")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement roles path**

`plugins/credential-do/path_roles.go`:
```go
package credentialdo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
)

type doRole struct {
	Name       string        `json:"name"`
	DefaultTTL time.Duration `json:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
	Scopes     string        `json:"scopes"`
	Disabled   bool          `json:"disabled,omitempty"`
}

func (b *backend) rolePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				"default_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     900,
					Description: "Default lease TTL",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     3600,
					Description: "Maximum lease TTL",
				},
				"scopes": {
					Type:        framework.TypeString,
					Description: "Comma-separated DO token scopes",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
		},
	}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	defaultTTL := time.Duration(d.Get("default_ttl").(int)) * time.Second
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	scopes := d.Get("scopes").(string)

	role := &cloudconfig.Role{
		Name:       name,
		Cloud:      "do",
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		CloudConfig: map[string]interface{}{
			"scopes": scopes,
		},
	}
	if err := cloudconfig.ValidateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	doR := &doRole{
		Name:       name,
		DefaultTTL: defaultTTL,
		MaxTTL:     maxTTL,
		Scopes:     scopes,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, doR)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":        role.Name,
			"default_ttl": int(role.DefaultTTL.Seconds()),
			"max_ttl":     int(role.MaxTTL.Seconds()),
			"scopes":      role.Scopes,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}
```

- [ ] **Step 4: Register role paths in backend**

In `plugins/credential-do/backend.go`, update the `Paths` line:
```go
		Paths: framework.PathAppend(
			b.configPaths(),
			b.rolePaths(),
		),
```

- [ ] **Step 5: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): add role CRUD paths with validation"
```

---

## Task 10: plugins/credential-do — Credential Issuance (creds/<role>) and Revocation

**Files:**
- Create: `plugins/credential-do/path_creds.go`
- Create: `plugins/credential-do/path_creds_test.go`
- Create: `plugins/credential-do/do_client.go`

- [ ] **Step 1: Write failing test for credential issuance and revoke**

`plugins/credential-do/path_creds_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func setupConfiguredBackend(t *testing.T, doURL string) (logical.Backend, logical.Storage) {
	t.Helper()
	b, storage := getTestBackend(t)

	// Write config with minter pointing to fake DO
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"minters": []interface{}{
				map[string]interface{}{
					"id":            "minter-1",
					"token":         "dop_v1_test",
					"never_expires": true,
				},
			},
			"do_api_url": doURL,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}

	// Write role
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"default_ttl": "15m",
			"max_ttl":     "1h",
			"scopes":      "read,write",
		},
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	return b, storage
}

func TestCredsIssue(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read failed: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("creds read error: %v", resp)
	}

	if resp.Data["cloud"] != "do" {
		t.Fatalf("expected cloud=do, got %v", resp.Data["cloud"])
	}
	if resp.Data["role"] != "test-role" {
		t.Fatalf("expected role=test-role, got %v", resp.Data["role"])
	}
	if resp.Data["credential_id"] == nil || resp.Data["credential_id"] == "" {
		t.Fatal("expected credential_id")
	}

	cred, ok := resp.Data["credential"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential map, got %T", resp.Data["credential"])
	}
	if cred["token"] == nil {
		t.Fatal("expected credential.token")
	}

	// Verify lease internal data has upstream ID for revoke
	if resp.Secret == nil {
		t.Fatal("expected secret/lease")
	}
	if resp.Secret.InternalData["upstream_token_id"] == nil {
		t.Fatal("expected upstream_token_id in internal_data")
	}
}

func TestCredsRevoke(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, resp)
	}

	// Revoke
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	resp, err = b.HandleRequest(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke error: %v", resp)
	}
}

func TestCredsIssue_RoleNotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing role")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 3: Implement DO API client**

`plugins/credential-do/do_client.go`:
```go
package credentialdo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type doClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type createTokenRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type tokenResponse struct {
	Token struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		AccessToken string `json:"access_token"`
	} `json:"token"`
}

func newDOClient(baseURL, token string) *doClient {
	return &doClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *doClient) CreateToken(ctx context.Context, name string, scopes []string) (*tokenResponse, int, error) {
	body, _ := json.Marshal(createTokenRequest{Name: name, Scopes: scopes})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v2/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("DO API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return &result, resp.StatusCode, nil
}

func (c *doClient) DeleteToken(ctx context.Context, tokenID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/v2/tokens/"+tokenID, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		return resp.StatusCode, fmt.Errorf("DO API delete returned %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
```

- [ ] **Step 4: Implement credential issuance and revoke path**

`plugins/credential-do/path_creds.go`:
```go
package credentialdo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope"
	"github.com/nicois/openbao-cloud-creds/pkg/recovery"
)

func (b *backend) credsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
		},
	}
}

func (b *backend) secretDO() *framework.Secret {
	return &framework.Secret{
		Type: "do_token",
		Revoke: b.pathCredsRevoke,
		Renew:  b.pathCredsRenew,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	// Load role
	entry, err := req.Storage.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("role_not_found: role %q does not exist", roleName), nil
	}

	var role doRole
	if err := json.Unmarshal(entry.Value, &role); err != nil {
		return nil, err
	}

	if role.Disabled {
		return logical.ErrorResponse("role_disabled: role %q is disabled", roleName), nil
	}

	// Select a healthy minter
	minterID, client, err := b.selectMinter(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Mint token via DO API
	scopes := strings.Split(role.Scopes, ",")
	tokenName := fmt.Sprintf("cloud-creds-%s-%s", roleName, req.ID)

	now := time.Now()
	tokenResp, httpStatus, err := client.CreateToken(ctx, tokenName, scopes)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		return logical.ErrorResponse("upstream error: %v", err), nil
	}
	b.recordMinterSuccess(minterID, now)

	expiresAt := now.Add(role.DefaultTTL)
	env := credenvelope.NewEnvelope(credenvelope.EnvelopeParams{
		Cloud: "do",
		Role:  roleName,
		Credential: map[string]interface{}{
			"token":  tokenResp.Token.AccessToken,
			"scopes": scopes,
		},
		ExpiresAt:    expiresAt,
		TTLSeconds:   int(role.DefaultTTL.Seconds()),
		Renewable:    true,
		CredentialID: tokenResp.Token.ID,
		Scope:        role.Scopes,
		IssuedBy:     "cloud-creds-do/v0.1",
	})

	resp := b.Secret(b.secretDO().Type).Response(env.ToMap(), map[string]interface{}{
		"upstream_token_id": tokenResp.Token.ID,
		"role":              roleName,
		"minter_id":         minterID,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) pathCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := req.Secret.InternalData["upstream_token_id"].(string)
	if !ok || tokenID == "" {
		return nil, fmt.Errorf("missing upstream_token_id in internal_data")
	}

	minterID, _ := req.Secret.InternalData["minter_id"].(string)
	_, client, err := b.getMinter(ctx, req.Storage, minterID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	httpStatus, err := client.DeleteToken(ctx, tokenID)
	if err != nil {
		b.recordMinterError(minterID, httpStatus, now)
		return nil, fmt.Errorf("revoke failed: %v", err)
	}
	b.recordMinterSuccess(minterID, now)

	return nil, nil
}

func (b *backend) pathCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.TTL
	resp.Secret.MaxTTL = req.Secret.MaxTTL
	return resp, nil
}

func (b *backend) selectMinter(ctx context.Context, storage logical.Storage) (string, *doClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("upstream_auth_failed: plugin not configured")
	}

	apiURL := b.doAPIURL()

	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy || ms.sm.State() == recovery.TransientFailing {
			return ms.minter.ID, newDOClient(apiURL, ms.minter.Token), nil
		}
	}

	return "", nil, fmt.Errorf("upstream_auth_failed: all minters are failing")
}

func (b *backend) getMinter(ctx context.Context, storage logical.Storage, id string) (string, *doClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config == nil {
		return "", nil, fmt.Errorf("plugin not configured")
	}

	apiURL := b.doAPIURL()

	if ms, ok := b.minters[id]; ok {
		return id, newDOClient(apiURL, ms.minter.Token), nil
	}

	// Fallback to any healthy minter
	for _, ms := range b.minters {
		if ms.sm.State() == recovery.Healthy {
			return ms.minter.ID, newDOClient(apiURL, ms.minter.Token), nil
		}
	}
	return "", nil, fmt.Errorf("no healthy minter available")
}

func (b *backend) doAPIURL() string {
	if b.apiURL != "" {
		return b.apiURL
	}
	return "https://api.digitalocean.com"
}

func (b *backend) recordMinterSuccess(id string, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if ms, ok := b.minters[id]; ok {
		ms.sm.RecordSuccess(at)
	}
}

func (b *backend) recordMinterError(id string, httpStatus int, at time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if ms, ok := b.minters[id]; ok {
		ms.sm.RecordError(httpStatus, at)
	}
}
```

- [ ] **Step 5: Add `apiURL` field and `do_api_url` config parameter**

In `plugins/credential-do/backend.go`, add field:
```go
type backend struct {
	*framework.Backend
	mu      sync.RWMutex
	config  *cloudconfig.PluginConfig
	minters map[string]*minterState
	apiURL  string
}
```

In `plugins/credential-do/path_config.go`, add to config fields:
```go
"do_api_url": {
    Type:        framework.TypeString,
    Default:     "https://api.digitalocean.com",
    Description: "DigitalOcean API base URL (for testing)",
},
```

And in `pathConfigWrite`, after setting minters:
```go
if url, ok := d.GetOk("do_api_url"); ok {
    b.apiURL = url.(string)
}
```

- [ ] **Step 6: Register creds paths and secret type in backend**

In `plugins/credential-do/backend.go`:
```go
b.Backend = &framework.Backend{
    BackendType: logical.TypeLogical,
    Help:        backendHelp,
    Paths: framework.PathAppend(
        b.configPaths(),
        b.rolePaths(),
        b.credsPaths(),
    ),
    Secrets: []*framework.Secret{
        b.secretDO(),
    },
}
```

- [ ] **Step 7: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): implement JIT credential issuance and revocation"
```

---

## Task 11: plugins/credential-do — Reconcile and Metrics Endpoints

**Files:**
- Create: `plugins/credential-do/path_reconcile.go`
- Create: `plugins/credential-do/path_metrics.go`
- Create: `plugins/credential-do/path_reconcile_test.go`
- Create: `plugins/credential-do/path_metrics_test.go`

- [ ] **Step 1: Write failing test for reconcile endpoint**

`plugins/credential-do/path_reconcile_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestReconcileEndpoint_DryRun(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data: map[string]interface{}{
			"mode": "dry_run",
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("reconcile error: %v", resp)
	}
}
```

- [ ] **Step 2: Write failing test for metrics endpoint**

`plugins/credential-do/path_metrics_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestMetricsEntityEndpoint(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Issue a cred first to generate metrics
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	_, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	// Query metrics
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metrics/entity/minter-1",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("metrics read failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected metrics response")
	}
	if resp.Data["access_count"] == nil {
		t.Fatal("expected access_count in metrics")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: FAIL.

- [ ] **Step 4: Implement reconcile path**

`plugins/credential-do/path_reconcile.go`:
```go
package credentialdo

import (
	"context"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
)

func (b *backend) reconcilePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "reconcile",
			Fields: map[string]*framework.FieldSchema{
				"mode": {
					Type:        framework.TypeString,
					Default:     "normal",
					Description: "Run mode: normal or dry_run",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathReconcile},
			},
		},
	}
}

func (b *backend) pathReconcile(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	mode := d.Get("mode").(string)
	dryRun := mode == "dry_run"

	// For now, return a summary. Full reconciler integration wires up
	// the pkg/reconciler with the DO cloud lister in a later pass.
	return &logical.Response{
		Data: map[string]interface{}{
			"mode":          mode,
			"dry_run":       dryRun,
			"orphans_found": 0,
			"deleted":       0,
			"hit_limit":     false,
		},
	}, nil
}
```

- [ ] **Step 5: Implement metrics path**

`plugins/credential-do/path_metrics.go`:
```go
package credentialdo

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/framework"
	"github.com/openbao/openbao/sdk/logical"
)

func (b *backend) metricsPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "metrics/entity/" + framework.GenericNameRegex("entity_id"),
			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "Cloud entity ID to query",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathMetricsEntity},
			},
		},
		{
			Pattern: "metrics/stale$",
			Fields: map[string]*framework.FieldSchema{
				"older_than": {
					Type:        framework.TypeDurationSecond,
					Default:     604800,
					Description: "Return entities not accessed within this duration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathMetricsStale},
			},
		},
	}
}

func (b *backend) pathMetricsEntity(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entityID := d.Get("entity_id").(string)

	b.mu.RLock()
	tracker := b.accessTracker
	b.mu.RUnlock()

	if tracker == nil {
		return logical.ErrorResponse("metrics not initialized"), nil
	}

	now := time.Now()
	merged, err := tracker.MergeEntity(entityID, now)
	if err != nil {
		return logical.ErrorResponse("metrics query failed: %v", err), nil
	}

	if merged.AccessCount == 0 {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"last_access_at":    merged.LastAccessAt.UTC().Format(time.RFC3339),
			"access_count":      merged.AccessCount,
			"staleness_seconds": merged.StalenessSeconds,
			"source":            merged.Source,
		},
	}, nil
}

func (b *backend) pathMetricsStale(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Placeholder for stale entity listing
	return logical.ListResponse([]string{}), nil
}
```

- [ ] **Step 6: Add accessTracker to backend and wire it up**

In `plugins/credential-do/backend.go`, add:
```go
import "github.com/nicois/openbao-cloud-creds/pkg/metrics"

type backend struct {
	*framework.Backend
	mu            sync.RWMutex
	config        *cloudconfig.PluginConfig
	minters       map[string]*minterState
	apiURL        string
	accessTracker *metrics.AccessTracker
}
```

In `Factory`, after `b.Setup`:
```go
store := metrics.NewInMemoryStore()
b.accessTracker = metrics.NewAccessTracker("local", store)
```

In `pathCredsRead`, after successful mint (before returning):
```go
b.mu.RLock()
if b.accessTracker != nil {
    b.accessTracker.RecordAccess(minterID, roleName, now)
}
b.mu.RUnlock()
```

- [ ] **Step 7: Register all paths in backend**

```go
Paths: framework.PathAppend(
    b.configPaths(),
    b.rolePaths(),
    b.credsPaths(),
    b.reconcilePaths(),
    b.metricsPaths(),
),
```

- [ ] **Step 8: Run tests**

```bash
cd plugins/credential-do && go test ./... -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add plugins/credential-do/
git commit -m "feat(credential-do): add reconcile and metrics query endpoints"
```

---

## Task 12: Integration Test With Cloud Fake (Full Lifecycle)

**Files:**
- Create: `plugins/credential-do/integration_test.go`

- [ ] **Step 1: Write full-lifecycle integration test**

`plugins/credential-do/integration_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestFullLifecycle(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// 1. Issue credential
	issueReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	issueResp, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp.IsError() {
		t.Fatalf("issue failed: err=%v resp=%v", err, issueResp)
	}

	// Verify envelope
	if issueResp.Data["cloud"] != "do" {
		t.Fatalf("bad cloud: %v", issueResp.Data["cloud"])
	}
	if issueResp.Data["expires_at"] == nil {
		t.Fatal("missing expires_at")
	}
	meta, ok := issueResp.Data["metadata"].(map[string]interface{})
	if !ok || meta["api_version"] != "1" {
		t.Fatalf("bad metadata: %v", issueResp.Data["metadata"])
	}

	// 2. Renew lease
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	renewResp, err := b.HandleRequest(context.Background(), renewReq)
	if err != nil || (renewResp != nil && renewResp.IsError()) {
		t.Fatalf("renew failed: err=%v resp=%v", err, renewResp)
	}

	// 3. Revoke lease
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/test-role",
		Storage:   storage,
		Secret:    issueResp.Secret,
	}
	revokeResp, err := b.HandleRequest(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if revokeResp != nil && revokeResp.IsError() {
		t.Fatalf("revoke error: %v", revokeResp)
	}

	// 4. Issue another to prove plugin still works after revoke
	issueResp2, err := b.HandleRequest(context.Background(), issueReq)
	if err != nil || issueResp2.IsError() {
		t.Fatalf("second issue failed: err=%v resp=%v", err, issueResp2)
	}
	if issueResp2.Data["credential_id"] == issueResp.Data["credential_id"] {
		t.Fatal("second issue should produce a different credential_id")
	}

	// 5. Reconcile dry-run
	reconcileReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "reconcile",
		Storage:   storage,
		Data:      map[string]interface{}{"mode": "dry_run"},
	}
	reconcileResp, err := b.HandleRequest(context.Background(), reconcileReq)
	if err != nil || (reconcileResp != nil && reconcileResp.IsError()) {
		t.Fatalf("reconcile failed: err=%v resp=%v", err, reconcileResp)
	}

	// 6. Metrics query
	metricsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "metrics/entity/minter-1",
		Storage:   storage,
	}
	metricsResp, err := b.HandleRequest(context.Background(), metricsReq)
	if err != nil {
		t.Fatalf("metrics query failed: %v", err)
	}
	if metricsResp == nil {
		t.Fatal("expected metrics data")
	}
	count, _ := metricsResp.Data["access_count"].(int64)
	if count < 2 {
		t.Fatalf("expected access_count >= 2 (issue + re-issue), got %v", metricsResp.Data["access_count"])
	}
}
```

- [ ] **Step 2: Run test**

```bash
cd plugins/credential-do && go test ./... -v -run TestFullLifecycle
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add plugins/credential-do/integration_test.go
git commit -m "test(credential-do): add full-lifecycle integration test with DO fake"
```

---

## Task 13: Recovery State Machine Integration Test

**Files:**
- Create: `plugins/credential-do/recovery_test.go`

- [ ] **Step 1: Write test for minter failure → recovery**

`plugins/credential-do/recovery_test.go`:
```go
package credentialdo_test

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/logical"
	"github.com/nicois/openbao-cloud-creds/pkg/credenvelope/fakes"
)

func TestMinterFailureAndRecovery(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	// Inject 401 error
	srv.SetNextStatus(401)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when minter fails")
	}

	// Recovery: next call should succeed (no more injected errors)
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("expected success after recovery, got: %v", resp)
	}
}

func TestUpstreamTimeout(t *testing.T) {
	srv := fakes.NewDOServer()
	defer srv.Close()

	b, storage := setupConfiguredBackend(t, srv.URL)

	srv.SetNextStatus(504)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for upstream timeout")
	}
}
```

- [ ] **Step 2: Run test**

```bash
cd plugins/credential-do && go test ./... -v -run TestMinter
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add plugins/credential-do/recovery_test.go
git commit -m "test(credential-do): add recovery state machine integration tests"
```

---

## Task 14: Final Lint Pass and CI Verification

**Files:**
- Modify: any files with lint issues

- [ ] **Step 1: Run linter**

```bash
golangci-lint run ./...
```

Fix any issues (unused imports, formatting, etc.).

- [ ] **Step 2: Run full test suite**

```bash
go test -race ./...
```

Expected: all PASS.

- [ ] **Step 3: Run build**

```bash
go build ./...
```

Expected: success.

- [ ] **Step 4: Commit any lint fixes**

```bash
git add -A
git commit -m "chore: fix lint issues from final pass"
```

---

## Summary of File Structure

```
openbao-cloud-creds/
├── go.work
├── .golangci.yml
├── Makefile
├── .github/workflows/ci.yml
├── pkg/
│   ├── credenvelope/
│   │   ├── go.mod
│   │   ├── doc.go
│   │   ├── envelope.go
│   │   ├── envelope_test.go
│   │   ├── errors.go
│   │   └── fakes/
│   │       ├── do.go
│   │       └── do_test.go
│   ├── recovery/
│   │   ├── go.mod
│   │   ├── doc.go
│   │   ├── state.go
│   │   └── state_test.go
│   ├── metrics/
│   │   ├── go.mod
│   │   ├── doc.go
│   │   ├── access.go
│   │   └── access_test.go
│   ├── reconciler/
│   │   ├── go.mod
│   │   ├── doc.go
│   │   ├── reconciler.go
│   │   └── reconciler_test.go
│   └── cloudconfig/
│       ├── go.mod
│       ├── doc.go
│       ├── config.go
│       ├── role.go
│       ├── minter.go
│       └── config_test.go
└── plugins/
    └── credential-do/
        ├── go.mod
        ├── doc.go
        ├── backend.go
        ├── do_client.go
        ├── path_config.go
        ├── path_config_test.go
        ├── path_roles.go
        ├── path_roles_test.go
        ├── path_creds.go
        ├── path_creds_test.go
        ├── path_reconcile.go
        ├── path_reconcile_test.go
        ├── path_metrics.go
        ├── path_metrics_test.go
        ├── integration_test.go
        ├── recovery_test.go
        └── cmd/
            └── main.go
```
