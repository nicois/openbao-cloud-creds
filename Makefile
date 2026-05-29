MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

.PHONY: build test lint fmt clean

build:
	go build $(MODULE_PREFIX)/...

test:
	go test $(MODULE_PREFIX)/...

test-cloud-real:
	go test -tags=cloud_real ./plugins/credential-do/...

lint:
	@for dir in pkg/credenvelope pkg/recovery pkg/metrics pkg/reconciler pkg/cloudconfig pkg/worker plugins/credential-do; do \
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
