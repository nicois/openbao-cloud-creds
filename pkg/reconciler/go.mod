module github.com/nicois/openbao-cloud-creds/pkg/reconciler

go 1.26.1

toolchain go1.26.6

require github.com/hashicorp/go-hclog v1.6.3

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
)

require (
	github.com/fatih/color v1.19.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/nicois/openbao-cloud-creds/pkg/capability => ../capability

replace github.com/nicois/openbao-cloud-creds/pkg/cloudconfig => ../cloudconfig

replace github.com/nicois/openbao-cloud-creds/pkg/credenvelope => ../credenvelope

replace github.com/nicois/openbao-cloud-creds/pkg/localexpiry => ../localexpiry

replace github.com/nicois/openbao-cloud-creds/pkg/metrics => ../metrics

replace github.com/nicois/openbao-cloud-creds/pkg/mintledger => ../mintledger

replace github.com/nicois/openbao-cloud-creds/pkg/metricspath => ../metricspath

replace github.com/nicois/openbao-cloud-creds/pkg/plugintest => ../plugintest

replace github.com/nicois/openbao-cloud-creds/pkg/recovery => ../recovery

replace github.com/nicois/openbao-cloud-creds/pkg/telemetry => ../telemetry

replace github.com/nicois/openbao-cloud-creds/pkg/worker => ../worker

replace github.com/nicois/openbao-cloud-creds/plugins/credential-akamai => ../../plugins/credential-akamai

replace github.com/nicois/openbao-cloud-creds/plugins/credential-aws => ../../plugins/credential-aws

replace github.com/nicois/openbao-cloud-creds/plugins/credential-azure => ../../plugins/credential-azure

replace github.com/nicois/openbao-cloud-creds/plugins/credential-do => ../../plugins/credential-do

replace github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale => ../../plugins/credential-exoscale

replace github.com/nicois/openbao-cloud-creds/plugins/credential-gcp => ../../plugins/credential-gcp

replace github.com/nicois/openbao-cloud-creds/plugins/credential-oci => ../../plugins/credential-oci

replace github.com/nicois/openbao-cloud-creds/plugins/credential-ovh => ../../plugins/credential-ovh

replace github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud => ../../plugins/credential-upcloud

replace github.com/nicois/openbao-cloud-creds/plugins/credential-vultr => ../../plugins/credential-vultr
