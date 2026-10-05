package main

import (
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/vm"
)

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
