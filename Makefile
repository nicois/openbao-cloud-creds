MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

PLUGIN_DIRS := $(patsubst plugins/%/cmd,%,$(wildcard plugins/*/cmd))
LINT_DIRS := pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/localexpiry pkg/worker pkg/plugintest pkg/telemetry pkg/metricspath conformance $(addprefix plugins/,$(PLUGIN_DIRS))

# The e2e module is entirely behind a build tag, so it is invisible to a lint run
# that does not pass the tag — lint it separately rather than leaving it unlinted.
TAGGED_LINT_DIRS := e2e
E2E_BUILD_TAG := e2e

.PHONY: build test test-conformance test-e2e lint fmt clean smoke-test

build:
	go build $(MODULE_PREFIX)/...

test:
	go test $(MODULE_PREFIX)/...

# The cloud-agnostic conformance table: every registered plugin runs every shared
# category. A plugin missing from the table, or a category neither wired nor
# declared as a gap, fails here instead of going quietly uncovered — see AGENTS.md.
test-conformance:
	go test $(MODULE_PREFIX)/conformance/... -v -run TestConformanceMatrix
	go test -race $(MODULE_PREFIX)/conformance/...

# Drives the plugins through a REAL OpenBao dev server as registered plugin
# processes: HTTP API in, plugin binary out, real leases, real revocation on lease
# end, real plugin reload. Needs `bao` on PATH; no cloud credentials (each cloud's
# fake HTTP server stands in for the upstream). AWS/GCP/OCI are declared gaps in
# the e2e registry — see docs/openbao-integration-gaps.md.
test-e2e:
	cd e2e && go test -tags=$(E2E_BUILD_TAG) -count=1 -v ./...

test-cloud-real:
	go test -tags=cloud_real ./plugins/credential-do/...

# Verifies every plugin builds as a binary and registers + enables in a live
# OpenBao dev server. Requires `bao` on PATH.
smoke-test:
	./scripts/registration-smoke-test.sh

lint:
	@for dir in $(LINT_DIRS); do \
		echo "=== Linting $$dir ==="; \
		(cd $$dir && golangci-lint run ./...) || exit 1; \
	done
	@for dir in $(TAGGED_LINT_DIRS); do \
		echo "=== Linting $$dir (--build-tags=$(E2E_BUILD_TAG)) ==="; \
		(cd $$dir && golangci-lint run --build-tags=$(E2E_BUILD_TAG) ./...) || exit 1; \
	done

fmt:
	gofmt -w .
	go fix
	go fix
	go fix
	goimports -w .

clean:
	go clean $(MODULE_PREFIX)/...
