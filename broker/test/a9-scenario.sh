#!/bin/sh
# A9 offline scenario (assurance/README.md): boot the broker daemon with its
# guest plane, take STOP and STATUS, serve a guest, restart and recover, all
# with no network. See broker/e2e/a9_test.go. The Go build cache lives in the
# sandbox's HOME, so the first run compiles from source, offline.
# The scenario must actually run and pass: a renamed test fails here rather
# than passing with nothing run.
set -eu
cd "$(dirname "$0")/.."
# Offline means no toolchain download either.
export GOTOOLCHAIN=local
want=$(awk '$1 == "toolchain" {print $2}' go.mod)
got=$(go version 2>/dev/null | awk '{print $3}')
if [ "$got" != "$want" ]; then
	echo "a9-scenario: go.mod needs $want but the installed Go is ${got:-missing}." >&2
	echo "Offline means no toolchain download: install $want first." >&2
	exit 1
fi
out=$(go test -count=1 -v -run '^TestA9OfflineScenario$' ./e2e) || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q '^--- PASS: TestA9OfflineScenario ' || { echo "TestA9OfflineScenario did not run" >&2; exit 1; }
