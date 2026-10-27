package main

import (
	"crypto"
	"crypto/ed25519"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// REQ: HW-16

// holdSlots opens n connections to addr that never start a handshake, so
// each holds a handshake slot until it closes or handshakeFor passes.
func holdSlots(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	held := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	t.Cleanup(func() { closeAll(held) })
	return held
}

func closeAll(cs []net.Conn) {
	for _, c := range cs {
		c.Close()
	}
}

func TestServedHandshakesAreCapped(t *testing.T) {
	c := newCore(t)
	live := newEdge(t)
	c.k.setLive(live.key())
	lc := live.dial(c.addr, c.pin)
	defer lc.Close()
	lc.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindDevice, Origin: "lamp", Body: []byte("on")}))
	if _, ok := c.item(3 * time.Second); !ok {
		t.Fatal("the live edge was not served")
	}

	// The served live connection holds no slot, so handshakeCap stalled
	// handshakes fit beside it and only the one after them is refused.
	// Mutant: handle's release() before serveLive dropped, so the live
	// connection keeps its slot and one stalled handshake is refused too.
	held := holdSlots(t, c.addr, handshakeCap)
	extra, err := net.Dial("tcp", c.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	// Mutant: the server's slots made unbounded (make(slots, 1<<20)): the
	// extra connection waits for its handshake deadline instead of closing.
	if !closedWithin(extra, time.Second) {
		t.Fatal("a handshake over the cap was not refused")
	}
	if !eventually(t, time.Second, func() bool { return c.s.refused.Load() == 1 }) {
		t.Fatalf("refused %d, want 1", c.s.refused.Load())
	}
	if !eventually(t, time.Second, func() bool {
		return strings.Contains(c.log.String(), "refused a connection over the handshake cap (1 so far)")
	}) {
		t.Fatalf("the refusal was not logged: %q", c.log.String())
	}

	// A stalled handshake that ends frees its slot. Mutant: release's
	// s.slots.give() dropped (killed above: the live slot is never freed).
	closeAll(held)
	if !eventually(t, 2*time.Second, func() bool { return c.s.faults.Load() == int64(handshakeCap) }) {
		t.Fatalf("faults %d, want %d", c.s.faults.Load(), handshakeCap)
	}
	other := newEdge(t)
	oc := other.dial(c.addr, c.pin)
	defer oc.Close()
	oc.Write(helloFrame(t, other.helloBody(oc, nil)))
	if !eventually(t, 3*time.Second, func() bool { _, n := c.k.counts(); return n == 1 }) {
		t.Fatal("a hello after the cap freed was not reported")
	}
	// The live edge is still served throughout.
	lc.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindDevice, Origin: "lamp", Body: []byte("off")}))
	if _, ok := c.item(3 * time.Second); !ok {
		t.Fatal("the live edge stopped being served")
	}
}

func TestCaptureHandshakesAreCapped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg, err := captureConfig()
	if err != nil {
		t.Fatal(err)
	}
	pin := cfg.Certificates[0].PrivateKey.(crypto.Signer).Public().(ed25519.PublicKey)
	log := &syncBuffer{}
	got := make(chan hello, 1)
	go func() {
		if h, err := firstHello(ln, cfg, log, 2*time.Second); err == nil {
			got <- h
		}
	}()
	addr := ln.Addr().String()

	held := holdSlots(t, addr, handshakeCap)
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	// Mutant: firstHello's slots made unbounded (make(slots, 1<<20)).
	if !closedWithin(extra, time.Second) {
		t.Fatal("a handshake over the cap was not refused before the store")
	}
	if !eventually(t, time.Second, func() bool {
		return strings.Contains(log.String(), "refused a connection before the store over the handshake cap (1 so far)")
	}) {
		t.Fatalf("the refusal was not logged: %q", log.String())
	}

	// Mutant: firstHello's defer slots.give() dropped (the edge below is
	// refused).
	closeAll(held)
	if !eventually(t, 2*time.Second, func() bool {
		return strings.Count(log.String(), "closed a connection before the store on a fault") == handshakeCap
	}) {
		t.Fatalf("the held handshakes did not end: %q", log.String())
	}
	first := newEdge(t)
	c := first.dial(addr, pin)
	defer c.Close()
	c.Write(helloFrame(t, first.helloBody(c, nil)))
	select {
	case h := <-got:
		if !h.key.Equal(first.key()) {
			t.Fatalf("took key %x, want the edge's", h.key)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hello taken after the cap freed")
	}
}
