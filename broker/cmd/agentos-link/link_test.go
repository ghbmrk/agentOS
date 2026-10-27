package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// REQ: HW-15, HW-16, HW-17

// core is a served link on loopback, with its consumer on a Unix socket.
type core struct {
	t    *testing.T
	k    *fakeKernel
	s    *server
	log  *syncBuffer
	addr string
	pin  []byte
	cons *bufio.Reader
	cw   net.Conn
}

func newCore(t *testing.T) *core {
	t.Helper()
	k := newFakeKernel(t)
	log := &syncBuffer{}
	s, err := newServer(k, log)
	if err != nil {
		t.Fatal(err)
	}
	s.wait = 300 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := net.Listen("unix", filepath.Join(t.TempDir(), "items.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); cl.Close() })
	go s.serve(ln)
	go s.serveConsumer(cl)
	cw, err := net.Dial("unix", cl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cw.Close() })
	pub, _ := k.LinkKey()
	return &core{t, k, s, log, ln.Addr().String(), pub, bufio.NewReader(cw), cw}
}

// item is the next item on the consumer socket, or false after d.
func (c *core) item(d time.Duration) (wireItem, bool) {
	ch := make(chan wireItem, 1)
	go func() {
		line, err := c.cons.ReadBytes('\n')
		var w wireItem
		if err == nil && json.Unmarshal(line, &w) == nil {
			ch <- w
		}
	}()
	select {
	case w := <-ch:
		return w, true
	case <-time.After(d):
		return wireItem{}, false
	}
}

func TestOnlyTheLiveEdgeIsServed(t *testing.T) {
	c := newCore(t)
	live := newEdge(t)
	c.k.setLive(live.key())

	// The live key's items arrive with their kind's label. The handshake
	// pins the link key, so the core signed it through the kernel's
	// LinkSign (decision 4).
	lc := live.dial(c.addr, c.pin)
	defer lc.Close()
	lc.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindText, Origin: "+15550100", Body: []byte("hi")}))
	w, ok := c.item(3 * time.Second)
	// Mutant: serveLive's Item takes a label other than f.Kind.Label().
	if !ok || w.Kind != edgelink.KindText || w.Origin != "+15550100" || string(w.Body) != "hi" || w.Label != edgelink.LabelSecondLine {
		t.Fatalf("live edge's text arrived as %+v (%v)", w, ok)
	}

	asked, _ := c.k.counts()
	other := newEdge(t)
	// Another key's hello is read, reported and closed; nothing is
	// delivered. Mutant: handle serves every key (e.Live check dropped).
	oc := other.dial(c.addr, c.pin)
	oc.Write(helloFrame(t, other.helloBody(oc, nil)))
	if !closedWithin(oc, 3*time.Second) {
		t.Fatal("a hello connection stayed open")
	}
	if !eventually(t, 2*time.Second, func() bool { _, n := c.k.counts(); return n == 1 }) {
		t.Fatal("the hello was not reported")
	}
	if h := c.k.candidates[0]; !h.key.Equal(other.key()) {
		t.Fatalf("reported key %x, want the other edge's", h.key)
	}
	if w, ok := c.item(100 * time.Millisecond); ok {
		t.Fatalf("a hello delivered %+v", w)
	}
	// Mutant: handle asks EdgeKey once and caches it.
	if a, _ := c.k.counts(); a <= asked {
		t.Fatalf("edgekey asked %d times after %d, want a new ask for the new connection", a, asked)
	}

	faults := func() int64 { return c.s.faults.Load() }
	for name, send := range map[string]func(*tls.Conn, edge){
		// Mutant: readHello reads on the FromEdge stream.
		"a non-hello frame": func(conn *tls.Conn, e edge) {
			conn.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindText, Origin: "+15550100", Body: []byte("x")}))
		},
		// Mutant: readHello's trailing-byte check dropped.
		"a second frame": func(conn *tls.Conn, e edge) {
			b := helloFrame(t, e.helloBody(conn, nil))
			conn.Write(append(b, b...))
		},
		// Mutant: readHello's read deadline dropped (the test then hangs
		// until the core's closedWithin fails).
		"no hello in time": func(*tls.Conn, edge) {},
	} {
		before := faults()
		_, cands := c.k.counts()
		e := newEdge(t)
		conn := e.dial(c.addr, c.pin)
		send(conn, e)
		if !closedWithin(conn, 3*time.Second) {
			t.Fatalf("%s: the connection stayed open", name)
		}
		if !eventually(t, time.Second, func() bool { return faults() == before+1 }) {
			t.Fatalf("%s: faults %d, want %d", name, faults(), before+1)
		}
		if _, n := c.k.counts(); n != cands {
			t.Fatalf("%s: reported a candidate", name)
		}
	}

	// A revoked key's hello is read and not reported. Mutant: handle's
	// e.Revoked return dropped.
	rev := newEdge(t)
	c.k.mu.Lock()
	c.k.revoked[string(rev.key())] = true
	c.k.mu.Unlock()
	_, cands := c.k.counts()
	rc := rev.dial(c.addr, c.pin)
	rc.Write(helloFrame(t, rev.helloBody(rc, nil)))
	closedWithin(rc, 3*time.Second)
	time.Sleep(100 * time.Millisecond)
	if _, n := c.k.counts(); n != cands {
		t.Fatal("a revoked key's hello was reported")
	}

	// The core's outbound frames reach the live edge.
	if _, err := c.cw.Write([]byte(`{"kind":1,"origin":"https://example.org/","body":""}` + "\n")); err != nil {
		t.Fatal(err)
	}
	lc.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := edgelink.ReadFrame(lc, edgelink.ToEdge)
	if err != nil || f.Kind != edgelink.KindFetch || f.Origin != "https://example.org/" {
		t.Fatalf("the edge read %+v, %v; want the fetch", f, err)
	}
}

func TestRevokeClosesTheConnection(t *testing.T) {
	c := newCore(t)
	live := newEdge(t)
	c.k.setLive(live.key())
	lc := live.dial(c.addr, c.pin)
	defer lc.Close()
	lc.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindDevice, Origin: "lamp", Body: []byte("on")}))
	if _, ok := c.item(3 * time.Second); !ok {
		t.Fatal("the live edge was not served")
	}
	// An edge.revoked (or edge.cut) makes the kernel stop naming the key
	// live. Mutant: recheck's ticker never closes (its !e.Live dropped).
	c.k.setLive(nil)
	if !closedWithin(lc, time.Second) {
		t.Fatal("a revoked edge's connection outlived a second")
	}
	if n := c.s.faults.Load(); n != 0 {
		t.Fatalf("a revoke counted %d faults", n)
	}
}

func TestBadFrameClosesAndCounts(t *testing.T) {
	c := newCore(t)
	live := newEdge(t)
	c.k.setLive(live.key())
	lc := live.dial(c.addr, c.pin)
	defer lc.Close()
	const canary = "+1555CANARY0199"
	// Version 2, with a canary origin the log must never carry.
	b := frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindText, Origin: canary, Body: []byte(canary)})
	b[0] = 2
	lc.Write(b)
	// Mutant: serveLive skips a frame that fails (continue in place of return).
	if !closedWithin(lc, 3*time.Second) {
		t.Fatal("a bad frame left the connection open")
	}
	// Mutant: serveLive's s.fault() dropped.
	if !eventually(t, time.Second, func() bool { return c.s.faults.Load() == 1 }) {
		t.Fatalf("faults %d, want 1", c.s.faults.Load())
	}
	if strings.Contains(c.log.String(), "CANARY") {
		t.Fatalf("the log carries the edge's content: %q", c.log.String())
	}
	if _, ok := c.item(100 * time.Millisecond); ok {
		t.Fatal("a bad frame delivered an item")
	}
}

func TestListensOnTheLinkInterfaceOnly(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	ln, err := listenLink("lo", port)
	if err != nil {
		t.Fatalf("listen on lo: %v", err)
	}
	defer ln.Close()
	// Mutant: listenLink's Control dropped (the socket is then bound to no
	// device).
	if dev, err := boundDevice(ln); err != nil || dev != "lo" {
		t.Fatalf("bound to %q (%v), want lo", dev, err)
	}
	for _, bad := range []string{"", "no-such-if0", "a/b", "eth 0", "sixteen-bytes-ab"} {
		if l, err := listenLink(bad, port+1); err == nil {
			l.Close()
			t.Errorf("listened on interface %q", bad)
		}
	}
}
