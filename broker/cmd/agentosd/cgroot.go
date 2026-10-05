package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
)

// agentNoLimits is STATUS's agent line when the broker may not manage the
// box's cgroups or they lack a controller, so no machine may start (RES-2:
// none runs unbudgeted). It names no controller (UX ruling on #155); the
// log line lists the missing ones.
const agentNoLimits = "Agent: off, the box can't yet keep the agent within its limits; it needs an update."

// cgroupHost is where the broker reads its cgroup facts; tests point it at
// a fake cgroupfs.
type cgroupHost struct {
	FS        string            // cgroup v2 mount, /sys/fs/cgroup
	ProcSelf  string            // /proc/self/cgroup
	Delegated func(string) bool // the group carries systemd's delegate mark
}

var liveCgroups = cgroupHost{FS: "/sys/fs/cgroup", ProcSelf: "/proc/self/cgroup", Delegated: delegateMarked}

// errNotDelegated means the broker has no proof the group is its own to
// manage. Writing outside a delegated subtree could move or limit other
// processes on the box, so the broker refuses rather than guesses.
var errNotDelegated = errors.New("cgroup not delegated to the broker")

// delegatedRoot is the group the broker may manage: its own cgroup or one
// beneath it, and only with proof of delegation: systemd's delegate mark on
// the broker's own group (Delegate=yes), or an explicit root that the
// operator vouches for with -cgroup-delegated. It reads and writes nothing
// under the cgroupfs.
func delegatedRoot(h cgroupHost, flagRoot string, vouched bool) (string, error) {
	b, err := os.ReadFile(h.ProcSelf)
	if err != nil {
		return "", err
	}
	rel, ok := "", false
	for _, line := range strings.Split(string(b), "\n") {
		if v, found := strings.CutPrefix(line, "0::"); found {
			rel, ok = v, true
			break
		}
	}
	if !ok || !strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("%w: no cgroup v2 entry in %s", errNotDelegated, h.ProcSelf)
	}
	own := filepath.Join(h.FS, rel)
	root := own
	if flagRoot != "" {
		root = filepath.Clean(flagRoot)
	}
	if root != own && !strings.HasPrefix(root, own+"/") {
		return "", fmt.Errorf("%w: %s is outside the broker's own group %s", errNotDelegated, root, own)
	}
	if (vouched && flagRoot != "") || (h.Delegated != nil && h.Delegated(own)) {
		return root, nil
	}
	return "", fmt.Errorf("%w: %s has no delegate mark (run under systemd Delegate=yes, or pass -cgroup-root with -cgroup-delegated)", errNotDelegated, own)
}

// openMachines finds the delegated root and applies the component budget
// there. Any failure leaves the cgroupfs untouched by delegatedRoot and
// machines off.
func openMachines(h cgroupHost, flagRoot string, vouched bool, mem budget.Memory) (*cgroup.Group, error) {
	root, err := delegatedRoot(h, flagRoot, vouched)
	if err != nil {
		return nil, err
	}
	g, err := openPool(root, mem)
	if err != nil {
		return nil, err
	}
	if n := ioWeightNote(h.FS, root); n != "" {
		log.Print(n)
	}
	return g, nil
}

// ioWeightNote says why I/O weights are inert, or "" when iocost weighs
// them on at least one disk (budget R12). The host image enables iocost
// on the state disk (SR2-4i); io.cost.qos lives in the cgroup root, which
// the broker only reads.
func ioWeightNote(fsRoot, root string) string {
	if _, err := os.Stat(filepath.Join(root, "broker", "io.weight")); err != nil {
		return "cgroup: io.weight absent (kernel has no iocost): machines' disk use is not weighed against the broker"
	}
	b, _ := os.ReadFile(filepath.Join(fsRoot, "io.cost.qos"))
	for _, line := range strings.Split(string(b), "\n") {
		if hasField(line, "enable=1") {
			return ""
		}
	}
	return "cgroup: iocost is off on every disk (io.cost.qos): io.weight is written but machines' disk use is not weighed against the broker"
}

func hasField(line, f string) bool {
	for _, x := range strings.Fields(line) {
		if x == f {
			return true
		}
	}
	return false
}
