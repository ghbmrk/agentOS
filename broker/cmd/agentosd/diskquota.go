package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/vm"
)

// checkDiskQuotaFlag refuses a -disk-quota value other than on or off at
// startup, so a typo never reads to the owner as a disk without quotas
// (L3 S3 on #174).
func checkDiskQuotaFlag(mode string) error {
	if mode != "on" && mode != "off" {
		return fmt.Errorf("-disk-quota=%q: want on or off", mode)
	}
	return nil
}

// machineQuota opens the per-machine disk quotas for agent machines kept in
// stateDir (RES-4). mode is -disk-quota: "on" requires project quotas on
// stateDir's file system; "off" runs machines without, where a guest can
// fill the disk, and says so in off.
func machineQuota(mode, stateDir string) (q vm.Quota, off bool, err error) {
	switch mode {
	case "off":
		return nil, true, nil
	case "on":
	default:
		return nil, false, fmt.Errorf("-disk-quota=%q: want on or off", mode)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, false, err
	}
	fs, err := quota.Open(stateDir)
	if err != nil {
		return nil, false, fmt.Errorf("%w; a guest could fill the disk the journal is on: mount it with prjquota, or run with -disk-quota=off to accept that", err)
	}
	return fs, false, nil
}

// machineDisk is how agent machines get their disk quotas: q and off go
// to vm.Config, and err, when set, keeps every machine off.
type machineDisk struct {
	q   vm.Quota
	off bool
	err error
}

// openMachineDisk opens the quotas for machines kept in dir per mode (-disk-
// quota), adding STATUS's line to notes while machines run without them
// (security R2 on #152).
func openMachineDisk(mode, dir string, notes *[]func() string) machineDisk {
	var d machineDisk
	d.q, d.off, d.err = machineQuota(mode, dir)
	if d.off {
		log.Printf("-disk-quota=off: agent machines run without disk quotas; a guest can fill the state disk (RES-4)")
	}
	if n := quotaNote(d.off, d.err); n != "" {
		*notes = append(*notes, func() string { return n })
	}
	return d
}

// set gives c the machines' quotas.
func (d machineDisk) set(c *vm.Config) { c.Quota, c.NoQuota = d.q, d.off }

// quotaNote is STATUS's line while agent machines run without disk quotas
// (security R2 on #152): declared off, or on but unavailable or not set up,
// when no machine starts. It names no path: the log has the cause.
func quotaNote(off bool, err error) string {
	switch {
	case errors.Is(err, quota.ErrUnsupported):
		return "Agent machines are off: my disk can't limit what each one writes."
	case err != nil:
		return "Agent machines are off: their disk space could not be set up."
	case off:
		return "Disk limits are off: an agent machine could fill the disk."
	}
	return ""
}
