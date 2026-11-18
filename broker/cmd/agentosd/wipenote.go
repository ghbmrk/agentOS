package main

import (
	"errors"
	"io/fs"
	"os"
)

// wipeFailed holds the files an orderly shutdown leaves when it ends with
// MOR set, so the firmware wipes memory at the next start (HW-8, OWN-17):
// agentos-keeper-wipe.service's ExecStopPost writes the first when the wipe
// of the setup files fails (MOR-wipe-owner, #6094), and
// agentos-mor.service's the second when `agentos-mor clear` refuses or
// fails (MOR-clear-owner, #6111); each removes its own on success. Their
// errors are kept in the journal only, which the owner never reads.
var wipeFailed = []string{"/var/lib/agentos-wipe/failed", "/var/lib/agentos-mor/refused"}

// wipeFailedLine is STATUS's line while either file exists: an orderly
// restart runs the wipe and the clear again, and their success removes it.
const wipeFailedLine = "Shutdown: my last one could not finish erasing my memory; " + fixRestart + "."

// wipeNote is STATUS's note on the last shutdown's wipe, read from paths
// at each STATUS. A file that cannot be checked counts as there, so an
// unknown result is told, never hidden.
func wipeNote(paths []string) func() string {
	return func() string {
		for _, p := range paths {
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				return wipeFailedLine
			}
		}
		return ""
	}
}
