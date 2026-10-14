#!/bin/sh
# pin.sh points every separate module's requirement on github.com/ubgo/auth,
# and on its sibling modules in this repository, at the pseudo-version of one
# pushed commit (default HEAD), then tidies each module.
#
# Why: the repository has no version tags, so a requirement of `v0.0.0` that a
# replace directive satisfies during development is "unknown revision v0.0.0"
# in a consumer's build, which ignores replace directives in dependencies. A
# pseudo-version of a commit that is on origin/main resolves for everyone. The
# replace directives stay, so development in the repository still builds
# against the working tree.
#
# Invariants:
#   - The commit must already be on origin/main, or the proxy cannot serve it.
#   - A sibling requirement must point at a commit whose own go.mod is already
#     pinned; a requirement of v0.0.0 anywhere in the graph breaks a consumer.
#     Once every module is pinned that holds by itself; the very first time it
#     took two runs (pin, commit, push, pin again).
#   - The version comes from proxy.golang.org, not from local git, so it is
#     exactly the string a consumer's `go get` resolves.
#
# Needs git, go and jq. Usage: scripts/pin.sh [commit]
set -eu

ref=${1:-HEAD}
root=$(git rev-parse --show-toplevel)
cd "$root"

sha=$(git rev-parse "$ref^{commit}")
git fetch -q origin main
if ! git merge-base --is-ancestor "$sha" origin/main; then
	echo "pin: $sha is not on origin/main; push it first" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
version=$(cd "$tmp" && GOWORK=off GOFLAGS=-mod=mod GOPROXY=https://proxy.golang.org \
	go list -m -f '{{.Version}}' "github.com/ubgo/auth@$sha")
case $version in
v0.0.0-*) ;;
*)
	echo "pin: expected a pseudo-version for $sha, the proxy answered $version" >&2
	exit 1
	;;
esac
echo "pin: $version"

find . -name go.mod -not -path ./go.mod -not -path './.cover/*' -not -path '*/node_modules/*' | sort |
	while read -r f; do
		d=$(dirname "$f")
		paths=$(cd "$d" && go mod edit -json |
			jq -r '.Require[]? | .Path | select(test("^github\\.com/ubgo/auth(/|$)"))')
		[ -n "$paths" ] || continue
		for p in $paths; do
			(cd "$d" && go mod edit -require="$p@$version")
		done
		(cd "$d" && GOWORK=off GOFLAGS=-mod=mod go mod tidy)
		echo "pin: $d"
	done
