MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

PLUGIN_DIRS := $(patsubst plugins/%/cmd,%,$(wildcard plugins/*/cmd))
LINT_DIRS := pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker pkg/plugintest $(addprefix plugins/,$(PLUGIN_DIRS))

.PHONY: build test lint fmt clean smoke-test

build:
	go build $(MODULE_PREFIX)/...

test:
	go test $(MODULE_PREFIX)/...

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
