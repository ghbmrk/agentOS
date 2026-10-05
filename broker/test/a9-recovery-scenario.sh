#!/bin/sh
# A9 offline scenario for recovery (assurance/README.md): restore onto a new
# drive from a backup and from the old drive, re-enroll the code generator,
# and move the owner's number, all with no network. See broker/recovery.
set -eu
cd "$(dirname "$0")/.."
exec go test -count=1 -run '^(TestRestoreFromBackupOntoANewDrive|TestRestoreFromTheOldDriveItself|TestLostPhoneReEnrollsTheCodeGeneratorWithTheRecoveryKey|TestLostNumberMovesWithTheRecoveryKeyAndTheOldNumberCanDoNothing)$' ./recovery
