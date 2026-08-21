MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

PLUGIN_DIRS := $(patsubst plugins/%/cmd,%,$(wildcard plugins/*/cmd))
LINT_DIRS := pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/localexpiry pkg/worker pkg/plugintest pkg/telemetry pkg/metricspath conformance $(addprefix plugins/,$(PLUGIN_DIRS))

.PHONY: build test test-conformance lint fmt clean smoke-test

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

fmt:
	gofmt -w .
	go fix
	go fix
	go fix
	goimports -w .

clean:
	go clean $(MODULE_PREFIX)/...
