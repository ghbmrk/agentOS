package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// REQ: HW-15

// captureCore runs the pre-store hello reader on a loopback listener and
// returns its address, the key the edge pins (the ephemeral core key) and
// the first hello it takes.
func captureCore(t *testing.T, wait time.Duration) (string, ed25519.PublicKey, <-chan hello) {
	t.Helper()
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
	got := make(chan hello, 1)
	go func() {
		if h, err := firstHello(ln, cfg, io.Discard, wait); err == nil {
			got <- h
		}
	}()
	return ln.Addr().String(), pin, got
}

func TestFirstHelloWinsOnlyBeforeTheStore(t *testing.T) {
	dir := t.TempDir()
	path, store := filepath.Join(dir, "first-edge"), filepath.Join(dir, "store")

	t.Run("a badly signed hello and a small-order key's are not taken; the first valid one is", func(t *testing.T) {
		addr, pin, got := captureCore(t, 2*time.Second)
		// Badly signed: over another connection's nonce. Mutant: readHello's
		// VerifyHello check dropped.
		bad := newEdge(t)
		c := bad.dial(addr, pin)
		c.Write(helloFrame(t, bad.helloBody(c, make([]byte, 32))))
		closedWithin(c, 2*time.Second)
		// The identity key, whose forged hello verifies over any nonce.
		// Mutant: `kernel.SmallOrder(key) ||` dropped from readHello.
		so := edge{t, smallOrderSigner{}}
		c = so.dial(addr, pin)
		c.Write(helloFrame(t, so.helloBody(c, nil)))
		closedWithin(c, 2*time.Second)
		select {
		case h := <-got:
			t.Fatalf("took the hello of key %x", h.key)
		case <-time.After(100 * time.Millisecond):
		}
		first, second := newEdge(t), newEdge(t)
		c1 := first.dial(addr, pin)
		c1.Write(helloFrame(t, first.helloBody(c1, nil)))
		var h hello
		select {
		case h = <-got:
		case <-time.After(3 * time.Second):
			t.Fatal("no hello taken")
		}
		c2 := second.dial(addr, pin)
		c2.Write(helloFrame(t, second.helloBody(c2, nil)))
		if !h.key.Equal(first.key()) {
			t.Fatalf("took key %x, want the first edge's", h.key)
		}
		// The bytes the child hands its parent are the parent's to check and
		// write. Mutant: takeCapture writes without validCapture.
		if err := takeCapture(bytes.NewReader(h.capture()), path, store); err != nil {
			t.Fatalf("takeCapture: %v", err)
		}
	})

	t.Run("the capture is root's own file, mode 0600, as enrollment takes it", func(t *testing.T) {
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Mutant: writeCapture's Chmod(0o600) made 0o644. The uid is the
		// euid, root in the unit.
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("capture mode %v, want a regular file 0600", fi.Mode())
		}
		if uid := int(fi.Sys().(*syscall.Stat_t).Uid); uid != os.Geteuid() {
			t.Fatalf("capture owned by %d, want this process's euid %d", uid, os.Geteuid())
		}
		b, _ := os.ReadFile(path)
		if len(b) != captureLen || !validCapture(b) {
			t.Fatalf("capture is %d bytes and not one valid hello", len(b))
		}
	})

	t.Run("a second capture is not written", func(t *testing.T) {
		before, _ := os.ReadFile(path)
		second := capture(t, newEdge(t))
		// Mutant: writeCapture's Lstat(path) check dropped and its Link
		// made a Rename (either alone still refuses the second).
		if err := takeCapture(bytes.NewReader(second), path, store); err != errTaken {
			t.Fatalf("second capture: %v, want errTaken", err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatal("the second capture replaced the first")
		}
	})

	t.Run("bad bytes from the reader are not written", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "first-edge")
		good := capture(t, newEdge(t))
		forged := append(append(append([]byte(nil), identityKey...), make([]byte, 32)...), append([]byte{1}, make([]byte, 63)...)...)
		for name, b := range map[string][]byte{
			"short":       good[:captureLen-1],
			"bad sig":     append(append([]byte(nil), good[:captureLen-1]...), good[captureLen-1]^1),
			"small order": forged,
		} {
			if err := takeCapture(bytes.NewReader(b), p, store); err != errBadCapture {
				t.Errorf("%s: %v, want errBadCapture", name, err)
			}
			if _, err := os.Lstat(p); err == nil {
				t.Fatalf("%s: a capture was written", name)
			}
		}
	})

	t.Run("once the store exists no hello is written", func(t *testing.T) {
		d := t.TempDir()
		p, st := filepath.Join(d, "first-edge"), filepath.Join(d, "store")
		if err := os.WriteFile(st, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		// Mutant: writeCapture's Lstat(store) check dropped.
		if err := takeCapture(bytes.NewReader(capture(t, newEdge(t))), p, st); err != errStoreExists {
			t.Fatalf("capture with a store: %v, want errStoreExists", err)
		}
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a capture was written after the store")
		}
		if err := writeable(config{capture: p, store: st}); err != errStoreExists {
			t.Fatalf("writeable with a store: %v", err)
		}
	})
}

// capture is a valid capture by e over a random nonce.
func capture(t *testing.T, e edge) []byte {
	nonce := make([]byte, 32)
	nonce[0] = 7
	sig, err := e.signer.Sign(nil, append([]byte("agentos.edge.hello.v1\x00"), nonce...), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return hello{e.key(), nonce, sig}.capture()
}

// REQ: HW-15

// TestTheStoreEndsTheCaptureWindow: once enrollment makes the store, the
// capture ends by itself, freeing the port for the served link, and it never
// ends before then.
func TestTheStoreEndsTheCaptureWindow(t *testing.T) {
	old := storePoll
	storePoll = 10 * time.Millisecond
	t.Cleanup(func() { storePoll = old })
	store := filepath.Join(t.TempDir(), "store")
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go untilStore(ctx, store, func() { close(done) })
	select {
	case <-done:
		t.Fatal("ended with no store")
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the store did not end the window")
	}
	// A stopped capture stops looking.
	ctx2, cancel2 := context.WithCancel(context.Background())
	ended := make(chan struct{})
	go func() { untilStore(ctx2, filepath.Join(t.TempDir(), "none"), func() {}); close(ended) }()
	cancel2()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("untilStore outlived its context")
	}
}
