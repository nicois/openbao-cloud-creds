module github.com/nicois/openbao-cloud-creds/pkg/telemetry

go 1.26.1

toolchain go1.26.6

require github.com/hashicorp/go-metrics v0.5.4

require github.com/hashicorp/go-uuid v1.0.3 // indirect

require (
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
)

replace github.com/nicois/openbao-cloud-creds/pkg/capability => ../capability

replace github.com/nicois/openbao-cloud-creds/pkg/cloudconfig => ../cloudconfig

replace github.com/nicois/openbao-cloud-creds/pkg/credenvelope => ../credenvelope

replace github.com/nicois/openbao-cloud-creds/pkg/localexpiry => ../localexpiry

replace github.com/nicois/openbao-cloud-creds/pkg/metrics => ../metrics

replace github.com/nicois/openbao-cloud-creds/pkg/mintledger => ../mintledger

replace github.com/nicois/openbao-cloud-creds/pkg/metricspath => ../metricspath

replace github.com/nicois/openbao-cloud-creds/pkg/plugintest => ../plugintest

replace github.com/nicois/openbao-cloud-creds/pkg/reconciler => ../reconciler

replace github.com/nicois/openbao-cloud-creds/pkg/recovery => ../recovery

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
