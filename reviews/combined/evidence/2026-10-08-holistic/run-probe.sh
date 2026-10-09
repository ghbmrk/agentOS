#!/bin/sh
set -eu
# Run only local, vendored source with an ephemeral Go file/cache.
evidence_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$evidence_dir/../../../.." && pwd)
probe_tmp=$(mktemp -d)
trap 'rm -rf "$probe_tmp"' EXIT HUP INT TERM
cp "$evidence_dir/recall-hint-probe.go.txt" "$probe_tmp/probe.go"
cd "$repo_dir/broker"
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE="$probe_tmp/cache" "${GO:-go}" run -mod=vendor "$probe_tmp/probe.go"
