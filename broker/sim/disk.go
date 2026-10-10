package sim

import (
	"bytes"
	"errors"
	"math/rand"
)

// errCrash is what every disk call returns once a crash point has fired,
// until the harness reboots the machine.
var errCrash = errors.New("sim: crashed")

// Disk is a journal.Store that models one journal file the way a POSIX file
// system keeps it. Live is what a running process reads (the page cache);
// Durable is what survives a power cut. A crash can be armed to fire at the
// Nth write, fsync, rename or directory sync, counting from now.
type Disk struct {
	live, durable []byte
	// renamed holds a Rewrite's new content once it has been renamed over
	// the journal but before the directory is synced: a power cut keeps
	// either the old file or this one.
	renamed []byte
	pending bool

	rng     *rand.Rand
	crashIn int // points left before the armed crash; 0 means none armed
	crashed bool
	mutant  Mutant
	log     func(string)
}

func newDisk(rng *rand.Rand, m Mutant, log func(string)) *Disk {
	return &Disk{rng: rng, mutant: m, log: log}
}

// Arm makes the nth crash point from now fire.
func (d *Disk) Arm(n int) { d.crashIn = n }

// Crashed reports whether a crash point has fired since the last reboot.
func (d *Disk) Crashed() bool { return d.crashed }

// point counts one crash point and reports whether the crash fires here.
func (d *Disk) point(kind string) bool {
	if d.crashIn == 0 {
		return false
	}
	d.crashIn--
	if d.crashIn > 0 {
		return false
	}
	d.crashed = true
	d.log("crash " + kind)
	return true
}

func (d *Disk) Append(line []byte) error {
	if d.crashed {
		return errCrash
	}
	if d.point("write") {
		// A write cut short leaves some prefix of the line in the page cache.
		d.live = append(d.live, line[:d.rng.Intn(len(line))]...)
		return errCrash
	}
	d.live = append(d.live, line...)
	if d.point("fsync") {
		return errCrash
	}
	if d.mutant != MutantSkipFsync {
		d.sync()
	}
	return nil
}

func (d *Disk) ReadAll() ([]byte, error) {
	if d.crashed {
		return nil, errCrash
	}
	return bytes.Clone(d.live), nil
}

func (d *Disk) Truncate(n int64) error {
	if d.crashed {
		return errCrash
	}
	if d.point("write") {
		return errCrash
	}
	if n < int64(len(d.live)) {
		d.live = d.live[:n]
	}
	if d.point("fsync") {
		return errCrash
	}
	d.sync()
	return nil
}

// Rewrite follows journal.FileStore: write a temp file, fsync it, rename it
// over the journal, fsync the directory.
func (d *Disk) Rewrite(data []byte) error {
	if d.crashed {
		return errCrash
	}
	if d.point("write") || d.point("fsync") || d.point("rename") {
		// The temp file never replaced the journal.
		return errCrash
	}
	d.live = bytes.Clone(data)
	d.renamed, d.pending = bytes.Clone(data), true
	if d.point("dirsync") {
		return errCrash
	}
	if d.mutant != MutantTornErase {
		d.syncDir()
	}
	return nil
}

func (d *Disk) sync() {
	if !d.pending {
		d.durable = bytes.Clone(d.live)
	}
}

func (d *Disk) syncDir() {
	if d.pending {
		d.durable, d.renamed, d.pending = d.renamed, nil, false
		d.sync()
	}
}

// Kill models the process dying: the page cache survives, so the next
// process reads what this one wrote, synced or not.
func (d *Disk) Kill() {
	d.crashed, d.crashIn = false, 0
}

// PowerCut models the machine losing power: unsynced bytes are lost, except
// that an unsynced append may have reached the medium in part, and a rename
// whose directory was not synced may or may not have.
func (d *Disk) PowerCut() {
	d.crashed, d.crashIn = false, 0
	if d.pending {
		if d.rng.Intn(2) == 0 {
			d.durable = d.renamed
		}
		d.renamed, d.pending = nil, false
	} else if bytes.HasPrefix(d.live, d.durable) {
		extra := len(d.live) - len(d.durable)
		if extra > 0 {
			d.durable = bytes.Clone(d.live[:len(d.durable)+d.rng.Intn(extra+1)])
		}
	}
	d.live = bytes.Clone(d.durable)
}

// open models journal.OpenFile, which fsyncs the directory it opens in.
func (d *Disk) open() { d.syncDir() }

// Durable returns what a power cut now would leave.
func (d *Disk) Durable() []byte { return bytes.Clone(d.durable) }
