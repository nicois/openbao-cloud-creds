module github.com/nicois/openbao-cloud-creds/conformance

go 1.27.0

require (
	github.com/nicois/openbao-cloud-creds/pkg/credenvelope v0.5.0
	github.com/nicois/openbao-cloud-creds/pkg/mintledger v0.5.0
	github.com/nicois/openbao-cloud-creds/pkg/ownertag v0.5.0
	github.com/nicois/openbao-cloud-creds/pkg/plugintest v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-akamai v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-aws v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-azure v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-do v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-gcp v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-oci v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-ovh v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud v0.5.0
	github.com/nicois/openbao-cloud-creds/plugins/credential-vultr v0.5.0
	github.com/openbao/openbao/sdk/v2 v2.6.2
)

require (
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.8 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.2 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-metrics v0.5.4 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-plugin v1.8.0 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.3 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.2-0.20210821155943-2d9075ca8770 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/capability v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/cloudconfig v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/clusterrole v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/issuedlist v0.5.0
	github.com/nicois/openbao-cloud-creds/pkg/localexpiry v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/minteraffinity v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/mintercapacity v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/reconciler v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/recovery v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/requester v0.5.0
	github.com/nicois/openbao-cloud-creds/pkg/telemetry v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/upstreampurge v0.5.0 // indirect
	github.com/nicois/openbao-cloud-creds/pkg/worker v0.5.0 // indirect
	github.com/oklog/run v1.2.0 // indirect
	github.com/openbao/go-kms-wrapping/v2 v2.8.0 // indirect
	github.com/openbao/openbao/api/v2 v2.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/nicois/openbao-cloud-creds/pkg/credenvelope => ../pkg/credenvelope

replace github.com/nicois/openbao-cloud-creds/pkg/mintledger => ../pkg/mintledger

replace github.com/nicois/openbao-cloud-creds/pkg/plugintest => ../pkg/plugintest

replace github.com/nicois/openbao-cloud-creds/plugins/credential-akamai => ../plugins/credential-akamai

replace github.com/nicois/openbao-cloud-creds/plugins/credential-aws => ../plugins/credential-aws

replace github.com/nicois/openbao-cloud-creds/plugins/credential-azure => ../plugins/credential-azure

replace github.com/nicois/openbao-cloud-creds/plugins/credential-do => ../plugins/credential-do

replace github.com/nicois/openbao-cloud-creds/plugins/credential-exoscale => ../plugins/credential-exoscale

replace github.com/nicois/openbao-cloud-creds/plugins/credential-gcp => ../plugins/credential-gcp

replace github.com/nicois/openbao-cloud-creds/plugins/credential-oci => ../plugins/credential-oci

replace github.com/nicois/openbao-cloud-creds/plugins/credential-ovh => ../plugins/credential-ovh

replace github.com/nicois/openbao-cloud-creds/plugins/credential-upcloud => ../plugins/credential-upcloud

replace github.com/nicois/openbao-cloud-creds/plugins/credential-vultr => ../plugins/credential-vultr

replace github.com/nicois/openbao-cloud-creds/pkg/capability => ../pkg/capability

replace github.com/nicois/openbao-cloud-creds/pkg/cloudconfig => ../pkg/cloudconfig

replace github.com/nicois/openbao-cloud-creds/pkg/localexpiry => ../pkg/localexpiry

replace github.com/nicois/openbao-cloud-creds/pkg/reconciler => ../pkg/reconciler

replace github.com/nicois/openbao-cloud-creds/pkg/recovery => ../pkg/recovery

replace github.com/nicois/openbao-cloud-creds/pkg/telemetry => ../pkg/telemetry

replace github.com/nicois/openbao-cloud-creds/pkg/worker => ../pkg/worker

replace github.com/nicois/openbao-cloud-creds/pkg/ownertag => ../pkg/ownertag

replace github.com/nicois/openbao-cloud-creds/pkg/clusterrole => ../pkg/clusterrole

replace github.com/nicois/openbao-cloud-creds/pkg/minteraffinity => ../pkg/minteraffinity

replace github.com/nicois/openbao-cloud-creds/pkg/mintercapacity => ../pkg/mintercapacity

replace github.com/nicois/openbao-cloud-creds/pkg/upstreampurge => ../pkg/upstreampurge

replace github.com/nicois/openbao-cloud-creds/pkg/requester => ../pkg/requester

replace github.com/nicois/openbao-cloud-creds/pkg/issuedlist => ../pkg/issuedlist
