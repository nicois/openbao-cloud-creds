MODULE_PREFIX := github.com/nicois/openbao-cloud-creds

PLUGIN_DIRS := $(patsubst plugins/%/cmd,%,$(wildcard plugins/*/cmd))
# LINT_DIRS is DERIVED from go.work, not listed. A hand-maintained list drifts: it
# had already lost pkg/capability — the package that gates every configuration write
# — so that package was unlinted while `make lint` reported success, and CI kept a
# third copy of the list that omitted more. Deriving it means adding a module to the
# workspace is enough (A21/A31 in docs/audit-2026-08-22.md).
#
# e2e is excluded here because it compiles only under its build tag and is covered by
# TAGGED_LINT_TARGETS below; linting it untagged would find no files.
LINT_DIRS := $(filter-out e2e,$(shell sed -n 's|^[[:space:]]*\./||p' go.work))

# Code behind a build tag is invisible to a lint run that does not pass the tag, so
# each tagged surface gets its own pass rather than being left unlinted. Format is
# <dir>:<tag>.
TAGGED_LINT_TARGETS := e2e:e2e plugins/credential-do:cloud_real plugins/credential-aws:cloud_real \
	plugins/credential-do:scale
E2E_BUILD_TAG := e2e
CLOUD_REAL_BUILD_TAG := cloud_real
SCALE_BUILD_TAG := scale

.PHONY: check-release-tags install-hooks build build-standalone dist test test-conformance test-e2e test-cloud-real-do test-cloud-real-do-spaces test-cloud-real-aws test-scale lint fmt clean smoke-test

build:
	go build $(MODULE_PREFIX)/...

# Every module must build WITHOUT the workspace, because that is how anyone who is
# not standing in this checkout consumes it: `go install .../cmd@<tag>`, a fork
# building one plugin, or a per-module SCA or licence scan. None of that worked —
# eight of ten plugins declared none of the sibling pkg/ modules they import, three
# had no go.sum at all, and a build-tagged TEST module was silently raising the
# shipped binaries' dependency versions through workspace MVS, so a binary's
# dependency set existed in no single file (A20 in docs/audit-2026-08-22.md).
build-standalone:
	@fail=0; for dir in $(LINT_DIRS) e2e; do 		printf '%-34s ' "$$dir"; 		if (cd $$dir && GOWORK=off go build ./... >/dev/null 2>&1); then echo ok; 		else echo FAILS; fail=1; fi; 	done; 	if [ $$fail -ne 0 ]; then 		echo; echo "A module that does not build standalone cannot be consumed outside this"; 		echo "checkout. Fix its go.mod (require + replace for each sibling) and go.sum."; 		exit 1; 	fi

# Build every plugin as a verifiable artifact and publish the hashes an operator must
# check before `bao plugin register -sha256=...`. There was no release target at all,
# `make build` produced no artifact, and the README never told anyone to verify one —
# for a secrets engine holding long-lived cloud minter credentials, that was the most
# consequential missing instruction in the repo (A20).
dist:
	@rm -rf dist && mkdir -p dist
	@for plugin in $(PLUGIN_DIRS); do 		echo "building $$plugin"; 		CGO_ENABLED=0 go build -trimpath -buildvcs=true 			-o dist/$$plugin $(MODULE_PREFIX)/plugins/$$plugin/cmd || exit 1; 	done
	@cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS
	@echo
	@echo "Register with:  bao plugin register -sha256=<hash from SHA256SUMS> secret <name>"

test:
	go test $(MODULE_PREFIX)/...

# The cloud-agnostic conformance table: every registered plugin runs every shared
# category. A plugin missing from the table, or a category neither wired nor
# declared as a gap, fails here instead of going quietly uncovered — see AGENTS.md.
test-conformance:
	go test $(MODULE_PREFIX)/conformance/... -v -run TestConformanceMatrix
	go test -race $(MODULE_PREFIX)/conformance/...

# Measures what the shared-key lifecycle tick COSTS at fleet scale, with the real
# worker running, inside a testing/synctest bubble so a day of five-minute ticks
# takes seconds of real time instead of a day. Minutes rather than milliseconds, so
# it is tagged out of the default suite — but it is a measurement to run
# periodically and TRACK, not a test to skip: whether the sweeper needs an index is
# a question about these numbers.
#
#   SCALE_ROLES=500000 SCALE_TICKS=24 make test-scale
test-scale:
	cd plugins/credential-do && go test -tags=$(SCALE_BUILD_TAG) -count=1 -v \
		-timeout 3600s -run TestScale ./...

# Drives the plugins through a REAL OpenBao dev server as registered plugin
# processes: HTTP API in, plugin binary out, real leases, real revocation on lease
# end, real plugin reload. Needs `bao` on PATH; no cloud credentials (each cloud's
# fake HTTP server stands in for the upstream). AWS/GCP/OCI are declared gaps in
# the e2e registry — see docs/openbao-integration-gaps.md.
test-e2e:
	cd e2e && go test -tags=$(E2E_BUILD_TAG) -count=1 -v ./...

# Calls the REAL DigitalOcean API with a real PAT, and creates + deletes real
# personal access tokens on that account. Needs CLOUDREAL_DO_TOKEN; use a
# dedicated/disposable account (docs/free-account-viability.md). It probes the one
# assumption no fake can test: that POST /v2/tokens — undocumented, and the whole
# mint path — works when called with a PAT. Scrubbed responses land in
# plugins/credential-do/testdata/cloud-real/ as fixtures.
# CLOUDREAL_DO_TOKEN may come from the environment, from .env.cloud-real (gitignored,
# read by nothing but this target), or from DIGITALOCEAN_PAT / DIGITALOCEAN_TOKEN —
# the names a machine with DO tooling on it already has exported.
# It also runs the Spaces-key probe below (both match -run TestRealDO), so this target
# is the whole DO real-cloud surface.
test-cloud-real-do:
	@set -a; [ -f .env.cloud-real ] && . ./.env.cloud-real; set +a; \
	: $${CLOUDREAL_DO_TOKEN:=$${DIGITALOCEAN_PAT:-$$DIGITALOCEAN_TOKEN}}; \
	export CLOUDREAL_DO_TOKEN CLOUDREAL_DO_SPACES_BUCKET CLOUDREAL_DO_SPACES_REGION; \
	test -n "$$CLOUDREAL_DO_TOKEN" || { echo "no DO token (CLOUDREAL_DO_TOKEN, DIGITALOCEAN_PAT, DIGITALOCEAN_TOKEN or .env.cloud-real)"; exit 1; }; \
	cd plugins/credential-do && go test -tags=$(CLOUD_REAL_BUILD_TAG) -count=1 -v -run TestRealDO ./...

# Just the Spaces-access-key probe: creates and deletes ONE real Spaces key on the
# account. This is the credential type credential-do can actually issue (its token
# mint path is fenced — KI-009), so this is the target that decides whether the
# plugin works against real DigitalOcean at all. It pins what no fake can: that
# POST /v2/spaces/keys answers a bearer PAT (DO's product docs say Spaces keys are
# panel-only, its OpenAPI spec specifies the endpoint), the mint response's field
# names, the list envelope, and that DELETE answers exactly 204.
# The minter PAT needs the spaces_key scopes; a full-access PAT holds them.
# CLOUDREAL_DO_SPACES_BUCKET is optional — the probe's grant names a bucket that need
# not exist, and if DigitalOcean refuses that, point this at a real one to separate
# "the endpoint is closed" from "the grant was rejected".
# CLOUDREAL_DO_SPACES_REGION (default nyc3) decides the endpoint the probe checks.
test-cloud-real-do-spaces:
	@set -a; [ -f .env.cloud-real ] && . ./.env.cloud-real; set +a; \
	: $${CLOUDREAL_DO_TOKEN:=$${DIGITALOCEAN_PAT:-$$DIGITALOCEAN_TOKEN}}; \
	export CLOUDREAL_DO_TOKEN CLOUDREAL_DO_SPACES_BUCKET CLOUDREAL_DO_SPACES_REGION; \
	test -n "$$CLOUDREAL_DO_TOKEN" || { echo "no DO token (CLOUDREAL_DO_TOKEN, DIGITALOCEAN_PAT, DIGITALOCEAN_TOKEN or .env.cloud-real)"; exit 1; }; \
	cd plugins/credential-do && go test -tags=$(CLOUD_REAL_BUILD_TAG) -count=1 -v -run TestRealDOSpacesKeys ./...

# Calls the REAL AWS STS API with a real IAM user's access key. Needs
# CLOUDREAL_AWS_KEY (access_key_id:secret_access_key) and CLOUDREAL_AWS_ROLE_ARN (a
# role the minter may assume); CLOUDREAL_AWS_REGION defaults to us-east-1.
# Unlike DO, nothing is created that needs deleting: STS sessions cannot be
# revoked, so every duration is the shortest the assertion allows and they expire
# on their own. IAM and STS calls are free.
# The minter needs only sts:AssumeRole on the target role, and the target role's
# trust policy must name the minter user and allow BOTH sts:AssumeRole and
# sts:TagSession (the plugin sends session tags). A zero-permission target role is
# enough — AssumeRole returns a valid credential regardless, so the whole plugin
# path is exercised with no blast radius.
# CLOUDREAL_AWS_LOWCAP_ROLE_ARN is optional: set it to a role with a
# MaxSessionDuration below the role TTL to pin the gap the capability probe cannot
# see (it asks for AWS's 900s floor). Absent, the gap is declared, not skipped.
test-cloud-real-aws:
	@set -a; [ -f .env.cloud-real ] && . ./.env.cloud-real; set +a; \
	export CLOUDREAL_AWS_KEY CLOUDREAL_AWS_ROLE_ARN CLOUDREAL_AWS_REGION CLOUDREAL_AWS_LOWCAP_ROLE_ARN; \
	test -n "$$CLOUDREAL_AWS_KEY" || { echo "no AWS minter key (CLOUDREAL_AWS_KEY as access_key_id:secret_access_key, in the environment or .env.cloud-real)"; exit 1; }; \
	test -n "$$CLOUDREAL_AWS_ROLE_ARN" || { echo "no target role (CLOUDREAL_AWS_ROLE_ARN)"; exit 1; }; \
	cd plugins/credential-aws && go test -tags=$(CLOUD_REAL_BUILD_TAG) -count=1 -v -run TestRealAWS ./...

# Verifies every plugin builds as a binary and registers + enables in a live
# OpenBao dev server. Requires `bao` on PATH.
smoke-test:
	./scripts/registration-smoke-test.sh

# Verifies a release's tag set: every module on disk tagged at VERSION, all at ONE commit,
# annotated in the scheme the previous releases used. Run by the pre-push hook before the tags
# leave the machine and by the CI job that fires on a pushed tag, so both call this rather than
# keeping their own idea of which modules a release covers — the module list is derived from
# disk inside the script, which is what stops a module added since the last release from being
# silently left out.
#
# Only meaningful AFTER the tags exist, which is why it is not part of `make test`: between the
# release commit and `git push --tags` the tags legitimately do not exist. The pre-tag half of
# the same contract — that every internal require names one version — is asserted on every
# commit by TestEveryModuleAgreesOnOneVersion in the conformance module.
check-release-tags:
	@test -n "$(VERSION)" || { echo "usage: make check-release-tags VERSION=v0.5.0"; exit 2; }
	./scripts/check-release-tags.sh $(VERSION)

# Points core.hooksPath at .githooks/, so the guards over the two irreversible acts — rewriting
# published history, and publishing a tag the module proxy will cache forever — are the ones in
# the repository rather than whatever each clone happens to have in .git/hooks.
#
# It supersedes an uncommitted .git/hooks copy of the same hooks: git consults hooksPath OR
# .git/hooks, never both. Nothing there is deleted, so `git config --unset core.hooksPath`
# restores the previous behaviour exactly.
install-hooks:
	git config core.hooksPath .githooks
	@echo "core.hooksPath -> .githooks ($$(ls .githooks | tr '\n' ' '))"
	@echo "undo with: git config --unset core.hooksPath"

lint:
	@for dir in $(LINT_DIRS); do \
		echo "=== Linting $$dir ==="; \
		(cd $$dir && golangci-lint run ./...) || exit 1; \
	done
	@for target in $(TAGGED_LINT_TARGETS); do \
		dir=$${target%%:*}; tag=$${target##*:}; \
		echo "=== Linting $$dir (--build-tags=$$tag) ==="; \
		(cd $$dir && golangci-lint run --build-tags=$$tag ./...) || exit 1; \
	done

fmt:
	gofmt -w .
	go fix
	go fix
	go fix
	goimports -w .

clean:
	go clean $(MODULE_PREFIX)/...
