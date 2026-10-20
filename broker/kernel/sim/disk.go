package sim

import (
	"errors"
	"math/rand/v2"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// errCrash is what the disk returns once a crash point has fired, until the
// harness reboots the machine.
var errCrash = errors.New("sim: crashed")

// errFull is a write refused for want of space; nothing reaches the medium.
var errFull = errors.New("sim: disk full")

// Disk is a kernel.Store whose Append is durable when it returns. A crash
// armed at the nth append cuts that append short: some prefix of the frame
// reaches the medium, which Open trims as a torn frame.
type Disk struct {
	b       []byte
	rng     *rand.Rand
	crashIn int
	crashed bool
	full    bool
	refused int // appends refused for want of space, over the disk's life
}

// Fill makes every append fail, writing nothing, until the next Reboot.
func (d *Disk) Fill() { d.full = true }

// Arm makes the nth append from now crash. Zero disarms.
func (d *Disk) Arm(n int) { d.crashIn = n }

// Reboot clears the crash; the bytes written so far stay.
func (d *Disk) Reboot() { d.crashed, d.crashIn, d.full = false, 0, false }

func (d *Disk) Append(b []byte) error {
	if d.crashed {
		return errCrash
	}
	if d.full {
		d.refused++
		return errFull
	}
	if d.crashIn > 0 {
		d.crashIn--
		if d.crashIn == 0 {
			d.crashed = true
			d.b = append(d.b, b[:d.rng.IntN(len(b))]...)
			return errCrash
		}
	}
	d.b = append(d.b, b...)
	return nil
}

func (d *Disk) ReadAll() ([]byte, error) {
	if d.crashed {
		return nil, errCrash
	}
	return append([]byte(nil), d.b...), nil
}

func (d *Disk) Truncate(n int) error {
	if d.crashed {
		return errCrash
	}
	if n < 0 || n > len(d.b) {
		return kernel.ErrCorrupt
	}
	d.b = d.b[:n]
	return nil
}
