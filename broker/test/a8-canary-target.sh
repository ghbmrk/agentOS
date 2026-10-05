#!/bin/sh
# A5 canary target for A8 (assurance/README.md): plants the harness's canaries
# in the vault, then backs up, restores onto a new drive, re-confirms and
# rotates card secrets, and puts every byte of both drives and the backup on
# the surface, as anyone holding the drive could read it. See
# broker/recovery/a8_test.go.
set -eu
cd "$(dirname "$0")/.."
exec go test -count=1 -run '^TestA8CanaryOnTheDrive$' ./recovery
