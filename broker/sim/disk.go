package sim

import (
	"bytes"
	"errors"
	"math/rand"
)

// errCrash is what every disk call returns once a crash point has fired,
// until the harness reboots the machine.
var errCrash = errors.New("sim: crashed")

// errIO is a write or sync the disk refused while the process lives on
// (EIO, ENOSPC). Unlike a crash, the caller sees it and keeps running.
var errIO = errors.New("sim: i/o error")

// Disk is a journal.Store that models one journal file the way a POSIX file
// system keeps it. Live is what a running process reads (the page cache);
// Durable is what survives a power cut. A crash can be armed to fire at the
// Nth write, fsync, rename or directory sync, counting from now, and so can
// a failure: the call returns errIO and the process keeps running.
type Disk struct {
	live, durable []byte
	// renamed holds a Rewrite's new content once it has been renamed over
	// the journal but before the directory is synced: a power cut keeps
	// either the old file or this one.
	renamed []byte
	pending bool

	rng     *rand.Rand
	crashIn int  // points left before the armed fault; 0 means none armed
	fail    bool // the armed fault is a failure, not a crash
	crashed bool
	// failed: a call returned errIO since the journal was last opened.
	// Any later write before a reopen is the bug class SIM-sim targets: a
	// write after a torn one glues a complete line to the torn prefix.
	failed bool
	mutant Mutant
	log    func(string)
	// written is told the bytes of every append the disk acknowledged,
	// and wrote of every write call made while failed.
	written func(line []byte)
	wrote   func(call string)
}

func newDisk(rng *rand.Rand, m Mutant, log func(string)) *Disk {
	return &Disk{rng: rng, mutant: m, log: log, written: func([]byte) {}, wrote: func(string) {}}
}

// Arm makes the nth crash point from now crash the machine.
func (d *Disk) Arm(n int) { d.crashIn, d.fail = n, false }

// Fail makes the nth point from now fail with errIO instead.
func (d *Disk) Fail(n int) { d.crashIn, d.fail = n, true }

// Crashed reports whether a crash point has fired since the last reboot.
func (d *Disk) Crashed() bool { return d.crashed }

// Failed reports whether a call failed since the journal was last opened.
func (d *Disk) Failed() bool { return d.failed }

// point counts one fault point and reports whether the armed fault fires
// here, crash or failure.
func (d *Disk) point(kind string) bool {
	if d.crashIn == 0 {
		return false
	}
	d.crashIn--
	if d.crashIn > 0 {
		return false
	}
	if d.fail {
		d.failed = true
		d.log("fail " + kind)
		return true
	}
	d.crashed = true
	d.log("crash " + kind)
	return true
}

// faultErr is what a call returns when its point fired.
func (d *Disk) faultErr() error {
	if d.crashed {
		return errCrash
	}
	return errIO
}

// writing records a write call made after a failure, before a reopen.
func (d *Disk) writing(call string) {
	if d.failed {
		d.wrote(call)
	}
}

func (d *Disk) Append(line []byte) error {
	if d.crashed {
		return errCrash
	}
	d.writing("append")
	if d.point("write") {
		// A write cut short leaves some prefix of the line in the page cache.
		d.live = append(d.live, line[:d.rng.Intn(len(line))]...)
		if d.failed && d.mutant == MutantAckShortWrite {
			// A store that ignores a short write's count: the torn prefix
			// is synced and the append reported done.
			d.failed = false
			d.sync()
			d.written(line)
			return nil
		}
		return d.faultErr()
	}
	d.live = append(d.live, line...)
	if d.point("fsync") {
		return d.faultErr()
	}
	if d.mutant != MutantSkipFsync {
		d.sync()
	}
	d.written(line)
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
	d.writing("truncate")
	if d.point("write") {
		return d.faultErr()
	}
	if n < int64(len(d.live)) {
		d.live = d.live[:n]
	}
	if d.point("fsync") {
		return d.faultErr()
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
	d.writing("rewrite")
	if d.point("write") || d.point("fsync") || d.point("rename") {
		// The temp file never replaced the journal.
		return d.faultErr()
	}
	d.live = bytes.Clone(data)
	d.renamed, d.pending = bytes.Clone(data), true
	if d.point("dirsync") {
		return d.faultErr()
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

// Disarm drops an armed fault that has not fired.
func (d *Disk) Disarm() { d.crashIn = 0 }

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

// open models journal.OpenFile, which fsyncs the directory it opens in. A
// new engine starts from what it reads, so an earlier failure is behind it.
func (d *Disk) open() {
	d.failed = false
	d.syncDir()
}

// Durable returns what a power cut now would leave.
func (d *Disk) Durable() []byte { return bytes.Clone(d.durable) }
