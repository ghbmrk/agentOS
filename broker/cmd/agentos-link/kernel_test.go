package main

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// REQ: HW-15, HW-16

// TestSpeaksTheKernelsLinkWire runs this command's kernel client against the
// kernel process's real LinkSide (EDGE-link-core c2b, ASSUMPTIONS
// EDGE-link-c2-3), so the two cannot drift: the link key's public half, a
// TLS 1.3 handshake signed by the kernel's linksign, a hello logged as the
// candidate, the page step's enrolment served, and the revoke closing the
// connection. Revert mutants: a call renamed on either side (linkkey,
// linksign, edgekey or edgecandidate refused as "no call"); an argument's
// JSON name changed (the kernel's ErrArgs); LinkSign refusing what
// crypto/tls asks it to sign (the handshake fails).
func TestSpeaksTheKernelsLinkWire(t *testing.T) {
	head, headPriv, _ := ed25519.GenerateKey(nil)
	_, ownerPriv, _ := ed25519.GenerateKey(nil)
	_, sparePriv, _ := ed25519.GenerateKey(nil)
	_, linkPriv, _ := ed25519.GenerateKey(nil)
	owner := key.Ed25519Signer(ownerPriv)
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: head, Sign: headPriv, LinkKey: linkPriv,
		Anchors: []key.PublicKey{owner.Public(), key.Ed25519Signer(sparePriv).Public()},
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	dir, err := os.MkdirTemp("", "link")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "k.sock")
	ln, err := proc.ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeKernel(ln, h, proc.LinkSide, func() int64 { return time.Now().UnixMilli() })
	kc := kernelConn{sock, os.Getuid()}

	pub, err := kc.LinkKey()
	if err != nil || !pub.Equal(linkPriv.Public()) {
		t.Fatalf("linkkey: %x, %v", pub, err)
	}
	if _, err := kc.LinkSign([]byte("not a CertificateVerify")); !errors.As(err, new(Refused)) || !strings.Contains(err.Error(), proc.ErrLinkSign.Error()) {
		t.Fatalf("linksign over another message: %v", err)
	}

	// A served link on loopback, its consumer on a Unix socket, as newCore
	// serves one over the fake kernel.
	s, err := newServer(kc, &syncBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	s.wait = time.Second
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := net.Listen("unix", filepath.Join(dir, "items.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close(); cl.Close() })
	go s.serve(tl)
	go s.serveConsumer(cl)
	cw, err := net.Dial("unix", cl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cw.Close() })
	c := &core{t: t, s: s, addr: tl.Addr().String(), pin: pub, cons: bufio.NewReader(cw), cw: cw}

	// A new edge: the handshake pins the link key the kernel signed with,
	// and its hello is the kernel's candidate.
	e := newEdge(t)
	if got, err := kc.EdgeKey(e.key()); err != nil || got != (Edge{}) {
		t.Fatalf("edgekey of a new edge: %+v, %v", got, err)
	}
	conn := e.dial(c.addr, c.pin)
	conn.Write(helloFrame(t, e.helloBody(conn, nil)))
	if !closedWithin(conn, 3*time.Second) {
		t.Fatal("the hello connection stayed open")
	}
	pending := func() (k ed25519.PublicKey) {
		h.With(func(kk *kernel.Kernel) error { k = kk.State().PendingEdge(head); return nil })
		return k
	}
	if !eventually(t, 2*time.Second, func() bool { return pending().Equal(e.key()) }) {
		t.Fatal("the hello was not logged as the candidate")
	}
	// The kernel's refusal crosses in its own words.
	if err := kc.EdgeCandidate(e.key(), make([]byte, kernel.HelloNonce), make([]byte, ed25519.SignatureSize)); !errors.As(err, new(Refused)) || !strings.Contains(err.Error(), kernel.ErrEdgeHello.Error()) {
		t.Fatalf("a hello that does not verify: %v", err)
	}

	// The page step: the owner's hardware key enrols the candidate, and
	// the edge is served.
	if err := h.With(func(k *kernel.Kernel) error {
		c := key.Approve(owner, kernel.EdgeEnrollHash(k.State().EdgeChanges(), k.Box(), e.key(), k.EdgeReplaces(e.key())))
		return k.EdgeEnroll(time.Now().UnixMilli(), e.key(), c)
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := kc.EdgeKey(e.key()); err != nil || got != (Edge{Live: true}) {
		t.Fatalf("edgekey once enrolled: %+v, %v", got, err)
	}
	live := e.dial(c.addr, c.pin)
	defer live.Close()
	live.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindText, Origin: "+15550100", Body: []byte("hi")}))
	if w, ok := c.item(3 * time.Second); !ok || w.Kind != edgelink.KindText || w.Label != edgelink.LabelSecondLine {
		t.Fatalf("the enrolled edge's text arrived as %+v (%v)", w, ok)
	}

	// The owner cuts it: the connection closes within a second.
	if err := h.With(func(k *kernel.Kernel) error { return k.EdgeRevoke(time.Now().UnixMilli(), e.key()) }); err != nil {
		t.Fatal(err)
	}
	if !closedWithin(live, 1500*time.Millisecond) {
		t.Fatal("the revoked edge's connection stayed open")
	}
	if got, err := kc.EdgeKey(e.key()); err != nil || got != (Edge{Revoked: true}) {
		t.Fatalf("edgekey once revoked: %+v, %v", got, err)
	}
}
