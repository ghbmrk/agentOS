package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
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

// wipeFailedAgain is the line once a record ends " again": the shutdown
// before it failed too, so a restart has been tried and did not help
// (MOR-clear-owner-fu, #6133). The record's mtime cannot tell: it is
// written at a shutdown, so it always predates the boot that reads it.
const wipeFailedAgain = "Shutdown: my last one could not finish erasing my memory; tell support."

// wipeNote is STATUS's note on the last shutdown's wipe, read from paths
// at each STATUS. A file that cannot be checked or read counts as there
// and asks for a restart, so an unknown result is told, never hidden.
func wipeNote(paths []string) func() string {
	return func() string {
		line := ""
		for _, p := range paths {
			if !recorded(p) {
				continue
			}
			if again(p) {
				return wipeFailedAgain
			}
			line = wipeFailedLine
		}
		return line
	}
}

// again is whether the record at path ends " again". A link, or a record
// that cannot be read, is not: the line then asks for a restart.
func again(path string) bool {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	return err == nil && strings.HasSuffix(strings.TrimSpace(string(b)), " again")
}

// recorded is whether path is there or cannot be checked.
func recorded(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
