#!/usr/bin/env bash
#
# Verify a release's tag set before it is pushed: every module tagged, at one commit, in the
# scheme the proxy resolves.
#
#   scripts/check-release-tags.sh v0.4.0
#
# Why this is a script and not the test in conformance/. TestEveryModuleAgreesOnOneVersion
# runs on every commit and checks what go.mod SAYS, which is knowable at any time. Tag
# completeness is not: between the release commit and `git push --tags` the tags legitimately
# do not exist, so a test demanding them would fail every release PR and teach people to
# ignore it. This runs once, deliberately, at the point where the answer is meaningful.
#
# Five failures it is aimed at, all of which produce a release that looks done:
#
#   - a module left untagged, so the first consumer to pin it gets "unknown revision";
#   - tags spread across more than one commit, so consumers resolve a set that was never
#     tested together, which is the whole hazard lockstep releases exist to avoid;
#   - tags on something other than what is about to be pushed;
#   - a tag at this version for a module no longer on disk;
#   - a lightweight tag, or one whose message does not match its siblings, in a set where
#     the tag is the only artefact nobody reviews before it is published.
#
# What it CANNOT check, and nothing local can: whether the proxy will serve them. That needs
# the tags pushed and a build from outside this checkout. The last line printed says so.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -ne 1 ]]; then
	echo "usage: $(basename "$0") <version>   e.g. $(basename "$0") v0.4.0" >&2
	exit 2
fi
readonly VERSION="$1"

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "version ${VERSION} is not vMAJOR.MINOR.PATCH" >&2
	exit 2
fi

# The modules a release tags: every directory under pkg/ and plugins/ holding a go.mod.
# Derived from disk rather than listed, so a module added since the last release cannot be
# silently left out -- the failure this whole file exists to prevent.
mapfile -t dirs < <(find pkg plugins -mindepth 2 -maxdepth 2 -name go.mod -printf '%h\n' | sort)
if ((${#dirs[@]} == 0)); then
	echo "found no modules under pkg/ or plugins/, so this check is looking in the wrong place" >&2
	exit 1
fi

missing=() lightweight=() mismessaged=() extra=()
declare -A commits=()

for dir in "${dirs[@]}"; do
	tag="${dir}/${VERSION}"
	if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
		missing+=("${tag}")
		continue
	fi
	if [[ "$(git cat-file -t "refs/tags/${tag}")" != "tag" ]]; then
		lightweight+=("${tag}")
	else
		# The scheme the previous releases used: "<module path> <version>".
		got=$(git for-each-ref --format='%(contents:subject)' "refs/tags/${tag}")
		if [[ "${got}" != "${dir} ${VERSION}" ]]; then
			mismessaged+=("${tag}: got '${got}', want '${dir} ${VERSION}'")
		fi
	fi
	# ^{commit} peels an annotated tag to the commit it names, so a tag object and a
	# lightweight tag are compared on equal terms.
	commits["$(git rev-parse "refs/tags/${tag}^{commit}")"]+="${tag} "
done

# A tag at this version for a module NOT on disk: one removed or renamed after being tagged,
# leaving a version the proxy still serves from a path that no longer exists. Impossible to
# notice by eye across thirty tags.
while read -r tag; do
	[[ -n "${tag}" ]] || continue
	[[ -f "${tag%/"${VERSION}"}/go.mod" ]] || extra+=("${tag}")
done < <(git tag --list "*/${VERSION}")

status=0

report() {
	local -r heading="$1" explanation="$2"
	shift 2
	printf '\n%s\n' "${heading}" >&2
	printf '  %s\n' "$@" >&2
	printf '\n%s\n' "${explanation}" >&2
	status=1
}

((${#missing[@]} == 0)) || report \
	"not tagged at ${VERSION}:" \
	"A consumer pinning one of these resolves nothing: the module exists on disk and in the
release, but there is no revision for the proxy to serve." \
	"${missing[@]}"

((${#lightweight[@]} == 0)) || report \
	"lightweight, where this repository uses annotated tags:" \
	"Re-create with: git tag -a -m '<dir> ${VERSION}' <tag>" \
	"${lightweight[@]}"

((${#mismessaged[@]} == 0)) || report \
	"annotated with an unexpected message:" \
	"Every previous release used '<module dir> <version>'. A tag is the one artefact here
that nobody reviews before it is published." \
	"${mismessaged[@]}"

((${#extra[@]} == 0)) || report \
	"tagged at ${VERSION} but absent from disk:" \
	"The proxy will serve a module path this repository no longer contains." \
	"${extra[@]}"

if ((${#commits[@]} > 1)); then
	printf '\n%s is spread across %d commits:\n' "${VERSION}" "${#commits[@]}" >&2
	for commit in "${!commits[@]}"; do
		printf '\n  %s\n' "$(git log -1 --format='%h %s' "${commit}")" >&2
		# Word-split deliberately: the value is a space-separated tag list.
		# shellcheck disable=SC2086
		printf '    %s\n' ${commits[$commit]} >&2
	done
	printf '\n%s\n' "A lockstep release must name one commit: consumers pinning different modules at the
same version would otherwise resolve a combination nothing ever tested." >&2
	status=1
fi

((status == 0)) || exit "${status}"

tagged=$(git rev-parse "refs/tags/${dirs[0]}/${VERSION}^{commit}")
if [[ "${tagged}" != "$(git rev-parse HEAD)" ]]; then
	printf '%s is tagged at %s, which is not HEAD (%s).\n\n' "${VERSION}" \
		"$(git log -1 --format='%h %s' "${tagged}")" "$(git rev-parse --short HEAD)" >&2
	printf '%s\n' "Refusing to call a release verified when it does not name the commit you are about to
push. Move the tags, or check out the commit they name." >&2
	exit 1
fi

printf 'ok: %d modules tagged %s, all annotated at %s\n' \
	"${#dirs[@]}" "${VERSION}" "$(git rev-parse --short HEAD)"
printf '\nNot checked here, and not checkable locally: whether the proxy serves them. After\n'
printf 'pushing, build a consumer from OUTSIDE this checkout -- that is the only thing that\n'
printf 'exercises the require versions, since every module here reaches its siblings through\n'
printf 'a replace directive.\n'
