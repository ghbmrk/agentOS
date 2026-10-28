package main

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel/anchor"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// REQ: CLK-1, LOG-2, KRN-2, BAK-1

var good = []string{
	"-log", "/var/lib/agentos-kernel/log", "-anchor-dir", "/var/lib/agentos-kernel/anchor",
	"-owner-sock", "/run/agentos-kernel/owner.sock", "-owner-uid", "981",
	"-meter-sock", "/run/agentos-kernel/meter.sock", "-meter-uid", "982",
	"-clerk", "exit=/run/agentos-exit/kernel.sock,983",
	"-clerk", "mail=/run/agentos-mail/kernel.sock,984",
	"-backup-dir", "/var/lib/agentos-kernel/backups",
	"-keys-dir", "/var/lib/agentos-kernel/keys",
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
		append(slices.Clone(good), "-anchor-dir", "anchor"),
		append(slices.Clone(good), "-up", "up"),
		good[2:],
		good[4:],
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// REQ: CLK-1
// MAIL-keys: -clerk-key names a clerk, its key socket and the one unit the
// kernel hands that clerk's key to; each part is checked and a clerk is
// named once.
func TestClerkKeyFlags(t *testing.T) {
	c, err := parse(append(slices.Clone(good), "-clerk-key", "mail=/run/agentos-kernel/clerk-mail.key,agentos-keeper-mail.service",
		"-clerk-key", "driver-hue=/run/agentos-kernel/clerk-driver-hue.key,agentos-driver@hue.service"), io.Discard)
	if err != nil || c.ClerkKeys["mail"] != (proc.KeyClerk{Socket: "/run/agentos-kernel/clerk-mail.key", Unit: "agentos-keeper-mail.service"}) ||
		c.ClerkKeys["driver-hue"].Unit != "agentos-driver@hue.service" {
		t.Fatalf("parse: %+v %v", c.ClerkKeys, err)
	}
	for _, bad := range []string{
		"mail=/k,agentos-keeper-mail.service,x", "Mail=/k,agentos-keeper-mail.service", "mail=k,agentos-keeper-mail.service",
		"mail=/k,agentos-keeper-mail", "mail=/k", "=/k,a.service", "mail=/k,a b.service", "mail=/k,../a.service",
	} {
		if _, err := parse(append(slices.Clone(good), "-clerk-key", bad), io.Discard); err == nil {
			t.Errorf("-clerk-key %q accepted", bad)
		}
	}
	twice := append(slices.Clone(good), "-clerk-key", "mail=/a,a.service", "-clerk-key", "mail=/b,b.service")
	if _, err := parse(twice, io.Discard); err == nil {
		t.Error("a clerk's key given twice was accepted")
	}
}

// KRN-erase: the kernel never starts with its content closed, so the
// subject-key table's directory is required, and absolute.
func TestTheKernelNeedsItsKeyTable(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil || c.KeyDir != "/var/lib/agentos-kernel/keys" {
		t.Fatalf("parse: %q %v", c.KeyDir, err)
	}
	for _, bad := range [][]string{good[:len(good)-2], append(slices.Clone(good), "-keys-dir", "keys")} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// BAK-1, LOG-4 (MIG-4-recovery-e3): an erase must reach every backup taken
// before, so the backups' records directory is required, and absolute.
func TestTheKernelNeedsItsBackupDir(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil || c.BackupDir != "/var/lib/agentos-kernel/backups" {
		t.Fatalf("parse: %q %v", c.BackupDir, err)
	}
	i := slices.Index(good, "-backup-dir")
	for _, bad := range [][]string{slices.Delete(slices.Clone(good), i, i+2), append(slices.Clone(good), "-backup-dir", "backups")} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// LOG-2: with no TPM connection there is no counter to anchor the log,
// and the kernel does not start: not on a closed descriptor, a file on the
// drive or a pipe standing in for the TPM.
func TestNoTPMNoKernel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the root refusal comes first (TestARefusedKernelLeavesTheKeysUnread)")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "tpm"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for name, tpm := range map[string]*os.File{"none": nil, "file": f, "pipe": r} {
		if err := start(good, io.Discard, anchor.Open, handoffPipe(t), tpm); !errors.Is(err, anchor.ErrNoTPM) {
			t.Errorf("%s: got %v, want ErrNoTPM", name, err)
		}
	}
}

// handoffPipe is a pipe holding a whole hand-off, its writer closed.
func handoffPipe(t *testing.T) *os.File {
	t.Helper()
	k := handoff.KernelKeys{
		Head:    ed25519.NewKeyFromSeed(make([]byte, 32)),
		Counter: handoff.Counter{SRK: []byte{1}, Handle: 0x01800000, Name: []byte{2}, Auth: []byte("a")},
		Anchors: []key.PublicKey{key.Ed25519(make([]byte, 32))},
		Slot:    handoff.SlotTPM,
	}
	b, err := k.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return r
}

// CLK-1: a kernel refused as root or as a peer's uid takes no key, so the
// keys never sit in a process a peer could read (#2896 L3 item 1).
func TestARefusedKernelLeavesTheKeysUnread(t *testing.T) {
	args := slices.Clone(good)
	args[slices.Index(args, "-owner-uid")+1] = strconv.Itoa(os.Getuid())
	r := fullPipe(t)
	anchor := func(string, handoff.KernelKeys, *os.File) (kernel.Anchor, error) { return &kernel.MemAnchor{}, nil }
	err := start(args, io.Discard, anchor, r, nil)
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
// hand-off and the clerks' key hand-off (MAIL-keys), and no IMAP library or the golang.org/x/net and x/text modules the
// mail clerk brings (the standard library's vendored copies are its own).
func TestTheKernelProcessLinksNoClerkCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	const clerk = "github.com/ghbmrk/agentos/broker/clerk"
	for _, p := range strings.Fields(string(out)) {
		if p == clerk || strings.HasPrefix(p, clerk+"/") && p != clerk+"/handoff" && p != clerk+"/clerkkey" ||
			strings.HasPrefix(p, "github.com/emersion/") || strings.HasPrefix(p, "golang.org/x/net/") || strings.HasPrefix(p, "golang.org/x/text/") {
			t.Errorf("agentos-kernel links %s", p)
		}
	}
}

// REQ: HW-15, HW-16
// EDGE-link-core-c2b: -link-sock and -link-uid come together, the link's
// uid is a peer the kernel refuses to run as, and it is no other peer's,
// since its socket is the only one that logs an edge candidate. Without
// them there is no link socket. Revert mutants: the LinkUID append to
// Peers dropped; the shared-uid check dropped.
func TestTheLinkSocketIsTheLinksAlone(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil || c.LinkSock != "" {
		t.Fatalf("no link flags: %+v, %v", c.MainConfig, err)
	}
	link := append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock", "-link-uid", "980")
	if c, err = parse(link, io.Discard); err != nil || c.LinkSock != "/run/agentos-kernel/link.sock" || c.LinkUID != 980 || !slices.Contains(c.Peers, 980) {
		t.Fatalf("link flags: %+v, %v", c.MainConfig, err)
	}
	for _, bad := range [][]string{
		append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock"),
		append(slices.Clone(good), "-link-uid", "980"),
		append(slices.Clone(good), "-link-sock", "link.sock", "-link-uid", "980"),
		append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock", "-link-uid", "0"),
		append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock", "-link-uid", "981"),
		append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock", "-link-uid", "982"),
		append(slices.Clone(good), "-link-sock", "/run/agentos-kernel/link.sock", "-link-uid", "984"),
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad[len(good):])
		}
	}
}
