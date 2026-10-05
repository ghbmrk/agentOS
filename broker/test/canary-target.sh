#!/bin/sh
# A5 canary target (assurance/README.md): plants the harness's canaries in the
# vault, wires guest plane -> OP-8 meter -> egress proxy as the box does, and
# lets a guest that can reach only its own socket try every route out. The
# guest's transcript and the broker's journal and meter state go to the
# surface. See broker/e2e/a14_test.go.
set -eu
cd "$(dirname "$0")/.."
exec go test -count=1 -run '^TestA14CanaryThroughTheGuestSocket$' ./e2e
