#!/bin/sh
# A9 offline scenario for recovery (assurance/README.md): restore onto a new
# drive from a backup and from the old drive, re-enroll the code generator,
# and move the owner's number, all with no network. See broker/recovery.
set -eu
cd "$(dirname "$0")/.."
# Offline means no toolchain download either.
export GOTOOLCHAIN=local
want=$(awk '$1 == "toolchain" {print $2}' go.mod)
got=$(go version 2>/dev/null | awk '{print $3}')
if [ "$got" != "$want" ]; then
	echo "a9-recovery-scenario: go.mod needs $want but the installed Go is ${got:-missing}." >&2
	echo "Offline means no toolchain download: install $want first." >&2
	echo "Under tools/depaudit.py, /root, /home, /tmp and the other masked directories are empty," >&2
	echo "so a toolchain there (such as one GOTOOLCHAIN fetched into ~/go/pkg/mod) is not seen:" >&2
	echo "install it elsewhere (for example /opt/$want) and put its bin first on PATH." >&2
	exit 1
fi
exec go test -count=1 -run '^(TestRestoreFromBackupOntoANewDrive|TestRestoreFromTheOldDriveItself|TestLostPhoneReEnrollsTheCodeGeneratorWithTheRecoveryKey|TestLostNumberMovesWithTheRecoveryKeyAndTheOldNumberCanDoNothing)$' ./recovery
