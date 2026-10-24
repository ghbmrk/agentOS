package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: CLK-1, LOG-2, KRN-2

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
	if os.Geteuid() == 0 {
		t.Skip("as root the root refusal comes first (TestARefusedKernelLeavesTheKeysUnread)")
	}
	r := fullPipe(t)
	if err := start(good, io.Discard, productionAnchor, r); !errors.Is(err, errNoAnchor) {
		t.Fatalf("got %v, want errNoAnchor", err)
	}
	unread(t, r)
}

// CLK-1: a kernel refused as root or as a peer's uid takes no key, so the
// keys never sit in a process a peer could read (#2896 L3 item 1).
func TestARefusedKernelLeavesTheKeysUnread(t *testing.T) {
	args := slices.Clone(good)
	args[slices.Index(args, "-owner-uid")+1] = strconv.Itoa(os.Getuid())
	r := fullPipe(t)
	anchor := func() (kernel.Anchor, error) { return &kernel.MemAnchor{}, nil }
	err := start(args, io.Discard, anchor, r)
	if err == nil || !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("got %v, want a root or peer-uid refusal", err)
	}
	unread(t, r)
}

// fullPipe is a pipe's read end holding a hand-off-sized payload, its
// writer closed.
func fullPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if _, err := w.Write(make([]byte, 600)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return r
}

// unread checks that every byte is still in the pipe.
func unread(t *testing.T, r *os.File) {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil || len(b) != 600 {
		t.Fatalf("the hand-off was read: %d bytes left, %v", len(b), err)
	}
}

// KRN-2 (#2892): the kernel's process links no clerk's code, so no mail or
// model parser is in it: of broker/clerk it links only the unlock step's
// hand-off, and no IMAP library or the golang.org/x/net and x/text modules the
// mail clerk brings (the standard library's vendored copies are its own).
func TestTheKernelProcessLinksNoClerkCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	const clerk = "github.com/ghbmrk/agentos/broker/clerk"
	for _, p := range strings.Fields(string(out)) {
		if p == clerk || strings.HasPrefix(p, clerk+"/") && p != clerk+"/handoff" ||
			strings.HasPrefix(p, "github.com/emersion/") || strings.HasPrefix(p, "golang.org/x/net/") || strings.HasPrefix(p, "golang.org/x/text/") {
			t.Errorf("agentos-kernel links %s", p)
		}
	}
}
