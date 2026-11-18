package main

import (
	"errors"
	"io/fs"
	"os"
)

// wipeFailed is the file agentos-keeper-wipe.service's ExecStopPost writes
// when a shutdown's wipe of the setup files fails, and removes when one
// succeeds (MOR-wipe-owner, #6094; HW-8, OWN-17). A failed wipe leaves MOR
// set, so the firmware wipes memory at the next start; its error is kept in
// the journal (image/ASSUMPTIONS.md MOR-wipe-journal), which the owner
// never reads.
const wipeFailed = "/var/lib/agentos-wipe/failed"

// wipeFailedLine is STATUS's line while the file exists: an orderly
// restart runs the wipe again, and its success removes the line.
const wipeFailedLine = "Shutdown: my last one could not erase setup files from memory; " + fixRestart + "."

// wipeNote is STATUS's note on the last shutdown's wipe, read from path at
// each STATUS. A file that cannot be checked counts as there, so an
// unknown result is told, never hidden.
func wipeNote(path string) func() string {
	return func() string {
		_, err := os.Lstat(path)
		return lineIf(!errors.Is(err, fs.ErrNotExist), wipeFailedLine)
	}
}
