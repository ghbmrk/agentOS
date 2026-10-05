#!/bin/sh
# A9 offline scenario (assurance/README.md): boot the broker daemon with its
# guest plane, take STOP and STATUS, serve a guest, restart and recover, all
# with no network. See broker/e2e/a9_test.go. The Go build cache lives in the
# sandbox's HOME, so the first run compiles from source, offline.
# The scenario must actually run and pass: a renamed test fails here rather
# than passing with nothing run.
set -eu
cd "$(dirname "$0")/.."
out=$(go test -count=1 -v -run '^TestA9OfflineScenario$' ./e2e) || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q '^--- PASS: TestA9OfflineScenario ' || { echo "TestA9OfflineScenario did not run" >&2; exit 1; }
