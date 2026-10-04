#!/bin/sh
# A9 offline scenario (assurance/README.md): boot the broker daemon with its
# guest plane, take STOP and STATUS, serve a guest, restart and recover, all
# with no network. See broker/e2e/a9_test.go. The Go build cache lives in the
# sandbox's HOME, so the first run compiles from source, offline.
set -eu
cd "$(dirname "$0")/.."
exec go test -count=1 -run '^TestA9OfflineScenario$' ./e2e
