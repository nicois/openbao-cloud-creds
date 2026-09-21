module github.com/nicois/openbao-cloud-creds/pkg/lineage

go 1.27.0

require (
	github.com/nicois/openbao-cloud-creds/pkg/credenvelope v0.5.0
	github.com/openbao/openbao/sdk/v2 v2.6.2
)

replace github.com/nicois/openbao-cloud-creds/pkg/credenvelope => ../credenvelope
