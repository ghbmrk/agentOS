package main

import (
	"errors"
	"io"
	"slices"
	"testing"
)

// REQ: CLK-1, LOG-2

var good = []string{
	"-log", "/var/lib/agentos-kernel/log",
	"-owner-sock", "/run/agentos-kernel/owner.sock", "-owner-uid", "981",
	"-meter-sock", "/run/agentos-kernel/meter.sock", "-meter-uid", "982",
	"-clerk", "exit=/run/agentos-exit/kernel.sock,983",
	"-clerk", "mail=/run/agentos-mail/kernel.sock,984",
}

// CLK-1: the kernel process refuses to run as any of its peers: the owner
// side, the model clerk and every clerk it calls.
func TestEveryPeerUIDIsRefusedToTheKernel(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(c.Peers)
	if !slices.Equal(c.Peers, []int{981, 982, 983, 984}) || c.Clerks["exit"].UID != 983 || c.Clerks["mail"].Socket != "/run/agentos-mail/kernel.sock" {
		t.Fatalf("parse: %+v", c)
	}
	for _, bad := range [][]string{
		append(slices.Clone(good), "-clerk", "exit=/x,985"),
		append(slices.Clone(good), "-clerk", "web=rel.sock,985"),
		append(slices.Clone(good), "-clerk", "web=/x,0"),
		append(slices.Clone(good), "-owner-uid", "0"),
		append(slices.Clone(good), "stray"),
		good[2:],
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// LOG-2: with no anchor off the log's disk the kernel does not start, and
// it takes no keys from the unlock step.
func TestNoAnchorNoKernel(t *testing.T) {
	if err := start(good, io.Discard, productionAnchor); !errors.Is(err, errNoAnchor) {
		t.Fatalf("got %v, want errNoAnchor", err)
	}
}
