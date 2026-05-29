MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

.PHONY: build test lint fmt clean

build:
	go build $(MODULE_PREFIX)/...

test:
	go test $(MODULE_PREFIX)/...

test-cloud-real:
	go test -tags=cloud_real ./plugins/credential-do/...

lint:
	golangci-lint run ./pkg/... ./plugins/...

fmt:
	gofmt -w .
	go fix
	go fix
	go fix
	goimports -w .

clean:
	go clean $(MODULE_PREFIX)/...
