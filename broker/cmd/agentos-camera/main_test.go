package main

// REQ: DEV-3, DEV-7, DEV-8, DEV-10, CLK-1, KRN-7, NET-2, A16

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Every key here is generated per run: synthetic, never a real credential.

const camAddr = "192.168.1.60:8443"

var (
	lepton = camwire.Shape{Width: 4, Height: 3}
	marker = []byte("MARKER-PAYLOAD-c4d9")
)

func init() { backoff = camera.Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond} }

// node is a synthetic camera node on camwire: a TLS 1.3 server with its
// own P-256 key that requires the core's client key. Its key can be
// swapped, as a spoofed node's would be.
type node struct {
	mu    sync.Mutex
	cert  tls.Certificate
	core  []byte
	dials atomic.Int32
	// mute makes the node accept and send nothing (silence).
	mute  atomic.Bool
	conns atomic.Int32 // connections live now
}

func newCert(t testing.TB) (tls.Certificate, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pin := netguard.KeyHash(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, hex.EncodeToString(pin[:])
}

func (n *node) swap(t testing.TB) string {
	c, pin := newCert(t)
	n.mu.Lock()
	n.cert = c
	n.mu.Unlock()
	return pin
}

func (n *node) connect(ctx context.Context, _, addr string) (net.Conn, error) {
	n.dials.Add(1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	b, err := ln.Accept()
	if err != nil {
		a.Close()
		return nil, err
	}
	go n.handle(b)
	return a, nil
}

func (n *node) handle(raw net.Conn) {
	defer raw.Close()
	n.mu.Lock()
	cert, core := n.cert, n.core
	n.mu.Unlock()
	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			pub, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if b, _ := pub.Bytes(); !ok || !bytes.Equal(b, core) {
				return errors.New("not the core's key")
			}
			return nil
		},
	})
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if tc.Handshake() != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	n.conns.Add(1)
	defer n.conns.Add(-1)
	for {
		if !n.mute.Load() {
			for _, f := range []camwire.Frame{video(), thermal()} {
				if camwire.WriteFrame(tc, camwire.ToCore, lepton, f) != nil {
					return
				}
			}
		}
		tc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		var b [1]byte
		if _, err := tc.Read(b[:]); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
	}
}

func video() camwire.Frame {
	return camwire.Frame{Type: camwire.TypeVideo, Payload: append([]byte{0, 0, 0, 1, 0x65}, marker...)}
}

func thermal() camwire.Frame {
	s := make([]byte, 2*int(lepton.Width)*int(lepton.Height))
	copy(s, marker)
	p := camwire.AppendThermal(nil, camwire.Thermal{Width: lepton.Width, Height: lepton.Height, Counter: 9, Samples: s})
	return camwire.Frame{Type: camwire.TypeThermal, Payload: p}
}

// feed is a fake decoder feed: it counts frames per camera and records cuts.
type feed struct {
	mu     sync.Mutex
	frames map[string]int
	cuts   map[string]int
	added  map[string]bool
}

func newFeed() *feed {
	return &feed{frames: map[string]int{}, cuts: map[string]int{}, added: map[string]bool{}}
}

func (f *feed) Frame(id string, _ camwire.Frame) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames[id]++
	return nil
}
func (f *feed) Cut(id string) { f.mu.Lock(); f.cuts[id]++; f.mu.Unlock() }
func (f *feed) Add(id string, video, _ camwire.Shape) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if video.Width == 0 {
		return camera.ErrShapes
	}
	f.added[id] = true
	return nil
}
func (f *feed) Remove(id string) { f.mu.Lock(); delete(f.added, id); f.mu.Unlock() }
func (f *feed) n(id string) int  { f.mu.Lock(); defer f.mu.Unlock(); return f.frames[id] }

type lines struct {
	mu sync.Mutex
	l  []string
}

func (l *lines) add(s string) { l.mu.Lock(); l.l = append(l.l, s); l.mu.Unlock() }
func (l *lines) all() string  { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.l, "\n") }

// box is one core: the clerk's directory and sealed store, which survive a
// restart, and the running host.
type box struct {
	t      *testing.T
	dir    string
	sealer clerk.Sealer
	node   *node
	h      *host
	feed   *feed
	log    *lines
	cancel context.CancelFunc
	done   chan struct{}
}

func newBox(t *testing.T) *box {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "camera")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sk := make([]byte, 32)
	rand.Read(sk)
	sealer, err := clerk.NewAESSealer(sk)
	if err != nil {
		t.Fatal(err)
	}
	b := &box{t: t, dir: dir, sealer: sealer, node: &node{}}
	b.boot()
	b.node.mu.Lock()
	b.node.core = b.h.point[:]
	b.node.mu.Unlock()
	b.node.swap(t)
	t.Cleanup(b.halt)
	return b
}

// boot starts a host on the box's directory, as the process does at start.
func (b *box) boot() {
	b.t.Helper()
	sec, err := run.OpenSecrets(b.dir, b.sealer)
	if err != nil {
		b.t.Fatal(err)
	}
	b.feed, b.log = newFeed(), &lines{}
	b.h, err = newHostWith(b.dir, sec, b.node.connect, b.log.add, func(func(string, camera.Kind)) (decoder, error) { return b.feed, nil })
	if err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.h.start(ctx); err != nil {
		cancel()
		b.t.Fatal(err)
	}
	b.cancel, b.done = cancel, make(chan struct{})
	go func() { b.h.tick(ctx, time.Hour); close(b.done) }()
}

// halt stops the host as SIGTERM does: streams end, open segments are
// written.
func (b *box) halt() {
	if b.cancel == nil {
		return
	}
	b.cancel()
	<-b.done
	b.cancel = nil
}

func (b *box) restart() { b.halt(); b.boot() }

func (b *box) pin() string {
	b.node.mu.Lock()
	defer b.node.mu.Unlock()
	leaf, _ := x509.ParseCertificate(b.node.cert.Certificate[0])
	k := netguard.KeyHash(leaf)
	return hex.EncodeToString(k[:])
}

func (b *box) rec(id, capture string, retention int64) record {
	return record{ID: id, Addr: camAddr, Key: b.pin(), Video: shape{640, 480}, Thermal: shape{lepton.Width, lepton.Height},
		Capture: capture, IntervalSec: 1, RetentionSec: retention}
}

func (b *box) status() string { return strings.Join(b.h.status(), "\n") }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Lifecycle row "Node listed by the enforcer, not connected": a STATUS
// line with the fingerprint's first 8 characters, and no dial.
func TestListedNodeStatusNoDial(t *testing.T) {
	b := newBox(t)
	key := b.pin()
	if err := b.h.setListed([]listed{{Addr: camAddr, Key: key}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.status(), "camera node at "+camAddr+": listed by the enforcer, key "+key[:8]) {
		t.Fatalf("no listed line in STATUS:\n%s", b.status())
	}
	time.Sleep(50 * time.Millisecond)
	if b.node.dials.Load() != 0 {
		t.Fatal("a listed node was dialed")
	}
	if b.h.setListed([]listed{{Addr: "not an address", Key: key}}) == nil {
		t.Fatal("a malformed listing was taken")
	}
	// Once connected, the listed line goes.
	if err := b.h.connect(b.rec("porch", "off", 0)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.status(), "listed by the enforcer") {
		t.Fatal("a connected node is still listed")
	}
}

// Lifecycle row "Connected, capture off": no stream opened, before or
// after a restart.
func TestConnectedCaptureOffNoStream(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "off", 0)); err != nil {
		t.Fatal(err)
	}
	b.restart()
	time.Sleep(50 * time.Millisecond)
	if b.node.dials.Load() != 0 {
		t.Fatal("a camera with capture off was dialed")
	}
	if !strings.Contains(b.status(), "camera porch: capture off") {
		t.Fatalf("STATUS:\n%s", b.status())
	}
}

// Lifecycle row "Capture turned on (tier 4)": the stream opens and its
// frames reach the decoder feed and the store's ring.
func TestCaptureOnStreams(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "off", 0)); err != nil {
		t.Fatal(err)
	}
	if err := b.h.setCapture("porch", "continuous"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames at the decoder", func() bool { return b.feed.n("porch") >= 4 })
	if rs, err := b.h.store.Recent("porch"); err != nil || len(rs) == 0 {
		t.Fatalf("the ring holds %d frames, %v", len(rs), err)
	}
	// Turning it off ends the stream and drops the memory-only ring.
	if err := b.h.setCapture("porch", "off"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the stream to close", func() bool { return b.node.conns.Load() == 0 })
	if rs, _ := b.h.store.Recent("porch"); len(rs) != 0 {
		t.Fatalf("the ring kept %d frames after capture off", len(rs))
	}
	if b.h.setCapture("porch", "always") == nil {
		t.Fatal("an unknown mode was taken")
	}
}

// #3625 and lifecycle row "Restart of the core": the pin, turn-on and
// retention reload, the stream resumes, a retained camera's segments
// survive the first sweep, and a camera disconnected while the core was
// down has its capture erased by it.
func TestRestartKeepsRetainedCapture(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 3600)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") >= 4 })
	b.halt()
	segs, err := b.h.store.Segments("porch")
	if err != nil || len(segs) == 0 {
		t.Fatalf("no segment written at stop: %d, %v", len(segs), err)
	}
	// A second camera's capture, left from one disconnected while down.
	orphan := filepath.Join(b.dir, "capture", "gone")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	dials := b.node.dials.Load()
	b.boot()
	after, err := b.h.store.Segments("porch")
	if err != nil || len(after) < len(segs) {
		t.Fatalf("the first sweep erased retained capture: %d of %d left, %v", len(after), len(segs), err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a disconnected camera's capture survived the first sweep")
	}
	waitFor(t, "the stream to resume", func() bool { return b.node.dials.Load() > dials && b.feed.n("porch") > 0 })
	if !strings.Contains(b.status(), "camera porch: capture continuous, kept 1h0m0s") {
		t.Fatalf("STATUS:\n%s", b.status())
	}
}

// #3625, the failure path, and Security and L3 point 1 on 0658b8c: a
// connected camera that does not start (here, its shapes refused by a
// newer decoder) keeps its retained capture, while every camera that did
// start still has its capture expire on time.
func TestPartialStartKeepsAndExpires(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 3600)); err != nil {
		t.Fatal(err)
	}
	y := b.rec("yard", "continuous", 1)
	y.Addr = "192.168.1.61:8443"
	if err := b.h.connect(y); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") >= 4 && b.feed.n("yard") >= 4 })
	b.halt()
	porch, _ := b.h.store.Segments("porch")
	yard, _ := b.h.store.Segments("yard")
	if len(porch) == 0 || len(yard) == 0 {
		t.Fatal("no segment")
	}
	sec, _ := run.OpenSecrets(b.dir, b.sealer)
	var err error
	b.feed = newFeed()
	refuse := refusing{b.feed, "porch"}
	b.h, err = newHostWith(b.dir, sec, b.node.connect, b.log.add, func(func(string, camera.Kind)) (decoder, error) { return refuse, nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.h.start(ctx); err != nil {
		t.Fatal(err)
	}
	b.h.stop() // no new segments: only the old ones are in question
	done := make(chan struct{})
	go func() { b.h.tick(ctx, 20*time.Millisecond); close(done) }()
	waitFor(t, "yard's capture to expire", func() bool { s, _ := b.h.store.Segments("yard"); return len(s) == 0 })
	cancel()
	<-done
	if after, err := b.h.store.Segments("porch"); err != nil || len(after) != len(porch) {
		t.Fatalf("a sweep erased capture of a camera that did not start: %d of %d, %v", len(after), len(porch), err)
	}
}

// refusing is a decoder feed that refuses one camera's shapes.
type refusing struct {
	*feed
	id string
}

func (r refusing) Add(id string, v, th camwire.Shape) error {
	if id == r.id {
		return camera.ErrShapes
	}
	return r.feed.Add(id, v, th)
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// Lifecycle row "Re-pin (tier 4)": a node presenting another key is
// refused and off; after the owner re-pins, the new key streams and the
// old one is refused.
func TestRepin(t *testing.T) {
	b := newBox(t)
	oldPin := b.pin()
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })
	newPin := b.node.swap(t)
	// End the live stream so the clerk redials and meets the new key.
	b.h.mu.Lock()
	b.h.halt("porch")
	b.h.started = true
	b.h.run(b.h.st.Cameras[0])
	b.h.mu.Unlock()
	waitFor(t, "the node to be off", func() bool { return strings.Contains(b.status(), "camera porch: off") })
	if !strings.Contains(b.log.all(), "event "+string(camera.KeyRefused)) {
		t.Fatalf("no tamper event logged:\n%s", b.log.all())
	}
	before := b.feed.n("porch")
	if err := b.h.repin("porch", "", newPin); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames under the new pin", func() bool { return b.feed.n("porch") > before })
	st, _ := load(b.dir)
	if st.Cameras[0].Key != newPin || newPin == oldPin {
		t.Fatal("the new pin was not saved")
	}
	if b.h.repin("porch", "", "zz") == nil {
		t.Fatal("a malformed key was taken")
	}
}

// Lifecycle row "Disconnect": the pin, turn-on and segments are erased,
// the segment key goes, and the node is dialed no more.
func TestDisconnectErases(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 3600)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") >= 4 })
	b.h.store.Flush()
	if err := b.h.disconnect("porch"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the stream to close", func() bool { return b.node.conns.Load() == 0 })
	dials := b.node.dials.Load()
	if _, err := os.Stat(filepath.Join(b.dir, "capture", "porch")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the camera's capture survived its disconnect")
	}
	sec, _ := run.OpenSecrets(b.dir, b.sealer)
	if sec.Has(camera.SegmentSlots + "porch") {
		t.Fatal("the segment key survived the disconnect")
	}
	b.restart()
	time.Sleep(50 * time.Millisecond)
	if b.node.dials.Load() != dials || strings.Contains(b.status(), "porch") {
		t.Fatal("a disconnected camera came back")
	}
	if b.h.disconnect("porch") == nil {
		t.Fatal("disconnecting an unknown camera succeeded")
	}
}

// Lifecycle row "STOP (KRN-7)": every stream closes, none opens until
// RESUME, across a restart.
func TestStopClosesStreams(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a stream", func() bool { return b.node.conns.Load() == 1 })
	if err := b.h.stop(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the stream to close", func() bool { return b.node.conns.Load() == 0 })
	b.restart()
	dials := b.node.dials.Load()
	time.Sleep(50 * time.Millisecond)
	if b.node.dials.Load() != dials || !strings.Contains(b.status(), "stopped (STOP)") {
		t.Fatal("a stream opened during a STOP")
	}
	if err := b.h.resume(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the stream after RESUME", func() bool { return b.node.conns.Load() == 1 })
}

// RES-2: past maxCameras a connect is refused, and a duplicate name too.
func TestConnectAdmission(t *testing.T) {
	b := newBox(t)
	for i := range maxCameras {
		r := b.rec("cam-"+string(rune('a'+i)), "off", 0)
		r.Addr = "192.168.1." + string(rune('1'+i)) + ":8443"
		if err := b.h.connect(r); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := b.h.connect(b.rec("one-more", "off", 0)); !errors.Is(err, camera.ErrAdmission) {
		t.Fatalf("connect past the cap: %v", err)
	}
	if err := b.h.connect(b.rec("cam-a", "off", 0)); !errors.Is(err, errExists) {
		t.Fatalf("a duplicate name: %v", err)
	}
	bad := b.rec("porch", "off", 0)
	bad.Addr = "8.8.8.8:8443"
	if b.h.disconnect("cam-a") != nil || b.h.connect(bad) == nil {
		t.Fatal("a camera off the home network was connected")
	}
}

// A16 and DEV-7: no payload byte, and no client key byte, appears in the
// log, STATUS or the cameras file.
func TestCaptureAndKeyNotLogged(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 3600)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") >= 4 })
	b.halt()
	var raw []byte
	sec, _ := run.OpenSecrets(b.dir, b.sealer)
	sec.DeviceKey(clientSlot)(func(k []byte) error { raw = bytes.Clone(k); return nil })
	state, _ := os.ReadFile(filepath.Join(b.dir, stateName))
	for _, hay := range [][]byte{[]byte(b.log.all()), []byte(b.status()), state} {
		if bytes.Contains(hay, marker) || len(raw) == 0 || bytes.Contains(hay, raw) ||
			strings.Contains(string(hay), hex.EncodeToString(raw)) {
			t.Fatal("capture or the client key leaked")
		}
	}
	// The segments on disk are sealed (part c), so the marker is not there.
	filepath.Walk(filepath.Join(b.dir, "capture"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			if c, _ := os.ReadFile(p); bytes.Contains(c, marker) {
				t.Fatal("capture on disk in the clear:", p)
			}
		}
		return nil
	})
}

// A torn or malformed cameras file refuses the start whole, so no camera
// is dropped and then swept.
func TestBadStateRefused(t *testing.T) {
	b := newBox(t)
	b.halt()
	for _, body := range []string{"{", `{"cameras":[{"id":"porch","addr":"x","key":"00","capture":"off"}]}`} {
		os.WriteFile(filepath.Join(b.dir, stateName), []byte(body), 0o600)
		if _, err := load(b.dir); !errors.Is(err, errState) {
			t.Fatalf("%q loaded: %v", body, err)
		}
	}
}

// The owner socket admits only the owner side's uid, answers each call
// strictly, and STATUS carries the client's public key for the enforcer.
func TestOwnerSocket(t *testing.T) {
	b := newBox(t)
	sock := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := sockets.ListenPeers(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serve(ln, b.h)
	call := func(op string, args any) (map[string]any, string) {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		a, _ := json.Marshal(args)
		json.NewEncoder(c).Encode(map[string]any{"op": op, "args": json.RawMessage(a)})
		var out map[string]any
		json.NewDecoder(c).Decode(&out)
		e, _ := out["error"].(string)
		return out, e
	}
	if _, e := call("camera/connect", b.rec("porch", "off", 0)); e != "" {
		t.Fatal(e)
	}
	if _, e := call("camera/capture", map[string]any{"ID": "porch", "Capture": "off", "Extra": 1}); e == "" {
		t.Fatal("an unknown field was taken")
	}
	if _, e := call("camera/frames", nil); e == "" {
		t.Fatal("an unknown call was answered")
	}
	out, e := call("camera/status", nil)
	if e != "" {
		t.Fatal(e)
	}
	res, _ := out["result"].(map[string]any)
	if res["client"] != hex.EncodeToString(b.h.point[:]) || !strings.Contains(strings.Join(toStrings(res["lines"]), "\n"), "camera porch") {
		t.Fatalf("status answer: %v", out)
	}
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, s := range l {
		str, _ := s.(string)
		out = append(out, str)
	}
	return out
}

func TestParse(t *testing.T) {
	good := []string{"-dir", "/d", "-owner-sock", "/s", "-owner-uid", "0", "-runsc", "/r", "-runsc-root", "/rr", "-decode-root", "/dr", "-cgroup", "/c"}
	if _, err := parse(good, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(good); i += 2 {
		bad := append(append([]string{}, good[:i]...), good[i+2:]...)
		if _, err := parse(bad, &bytes.Buffer{}); err == nil {
			t.Fatalf("parse without %s succeeded", good[i])
		}
	}
	if _, err := parse(append(good, "extra"), &bytes.Buffer{}); err == nil {
		t.Fatal("an extra argument was taken")
	}
}

// The end-to-end run against a synthetic node: connect, turn-on, a key
// swap (refused, off), the owner's re-pin, silence and recovery, restart
// and disconnect, all through the host as the owner socket drives it.
func TestEndToEnd(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "off", 3600)); err != nil {
		t.Fatal(err)
	}
	if err := b.h.setCapture("porch", "continuous"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })

	// Silence: the node stops sending; an event; frames again on recovery.
	b.node.mute.Store(true)
	waitFor(t, "a silent event", func() bool { return strings.Contains(b.log.all(), "event "+string(camera.Silent)) })
	n := b.feed.n("porch")
	b.node.mute.Store(false)
	waitFor(t, "recovery", func() bool { return b.feed.n("porch") > n })

	// Key swap: refused before any frame; off; re-pin brings it back.
	newPin := b.node.swap(t)
	b.restart()
	waitFor(t, "the node to be off", func() bool { return strings.Contains(b.status(), "camera porch: off") })
	if b.feed.n("porch") != 0 {
		t.Fatal("a frame from a node with another key reached the decoder")
	}
	if err := b.h.repin("porch", "", newPin); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames after the re-pin", func() bool { return b.feed.n("porch") > 0 })

	if err := b.h.disconnect("porch"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "capture", "porch")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capture survived the disconnect")
	}
	if bytes.Contains([]byte(b.log.all()), marker) {
		t.Fatal("capture in the log")
	}
}

// failSave makes the next save fail: cameras.json becomes a non-empty
// directory, so WriteAtomic cannot rename over it.
func failSave(t *testing.T, dir string) (undo func()) {
	p := filepath.Join(dir, stateName)
	b, _ := os.ReadFile(p)
	os.Remove(p)
	os.Mkdir(p, 0o700)
	os.WriteFile(filepath.Join(p, "x"), nil, 0o600)
	return func() { os.RemoveAll(p); os.WriteFile(p, b, 0o600) }
}

// Security point 1 on 0658b8c: a capture turn-on whose save fails opens
// nothing, and the clerk's own gate stays off.
func TestCaptureFailedSaveOpensNothing(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "off", 0)); err != nil {
		t.Fatal(err)
	}
	undo := failSave(t, b.dir)
	defer undo()
	if err := b.h.setCapture("porch", "continuous"); err == nil {
		t.Fatal("the save did not fail")
	}
	if b.h.st.Cameras[0].Capture != "off" {
		t.Fatal("the record kept the new mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := b.h.clerk.Run(ctx, "porch"); !errors.Is(err, camera.ErrCaptureOff) || b.node.dials.Load() != 0 {
		t.Fatalf("the clerk's gate opened after a failed turn-on: %v, %d dials", err, b.node.dials.Load())
	}
}

// Security point 1 on 0658b8c: a re-pin whose save fails leaves the old
// key pinned in the clerk: the old node still streams.
func TestRepinFailedSaveKeepsOldKey(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })
	_, other := newCert(t)
	undo := failSave(t, b.dir)
	defer undo()
	if err := b.h.repin("porch", "", other); err == nil {
		t.Fatal("the save did not fail")
	}
	// Force a redial: the node with the old key must still be accepted.
	b.h.mu.Lock()
	b.h.halt("porch")
	b.h.run(b.h.st.Cameras[0])
	b.h.mu.Unlock()
	n := b.feed.n("porch")
	waitFor(t, "frames under the old pin", func() bool { return b.feed.n("porch") > n })
	if strings.Contains(b.status(), "camera porch: off") {
		t.Fatal("the clerk took the unsaved key")
	}
}

// L3 point 4 on 0658b8c: a node that came back at another address with a
// new key is re-pinned there and streams.
func TestRepinMovesAddress(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })
	newPin := b.node.swap(t)
	if err := b.h.repin("porch", "192.168.1.70:8443", newPin); err != nil {
		t.Fatal(err)
	}
	n := b.feed.n("porch")
	waitFor(t, "frames at the new address", func() bool { return b.feed.n("porch") > n })
	st, _ := load(b.dir)
	if st.Cameras[0].Addr != "192.168.1.70:8443" || st.Cameras[0].Key != newPin {
		t.Fatalf("saved: %+v", st.Cameras[0])
	}
}

// Security point 3 on 0658b8c: a listed address with a zone, or off the
// home network, is refused, so the enforcer's channel cannot put its own
// text into a STATUS line.
func TestListedAddressCanonical(t *testing.T) {
	b := newBox(t)
	key := b.pin()
	for _, a := range []string{"[fe80::1%a\nb]:80", "[fe80::1%x camera porch: capture off]:80", "8.8.8.8:443"} {
		if b.h.setListed([]listed{{Addr: a, Key: key}}) == nil {
			t.Errorf("%q was listed", a)
		}
	}
	if err := b.h.setListed([]listed{{Addr: "[fd00::0001]:8443", Key: strings.ToUpper(key)}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.status(), "camera node at [fd00::1]:8443: listed by the enforcer, key "+key[:8]) {
		t.Fatalf("STATUS:\n%s", b.status())
	}
}

// redial ends porch's runner and starts it again, so the clerk dials the
// node afresh under the pin it holds now.
func (b *box) redial(id string) {
	b.h.mu.Lock()
	defer b.h.mu.Unlock()
	b.h.halt(id)
	if i := b.h.find(id); i >= 0 {
		b.h.run(b.h.st.Cameras[i])
	}
}

// #3967: a capture turn-on whose apply fails (the clerk does not hold the
// camera: its decoder refused it at start) leaves the record, the file
// and the clerk's gate at the old mode, and opens no stream.
func TestCaptureFailedApplyRollsBack(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "off", 0)); err != nil {
		t.Fatal(err)
	}
	b.halt()
	sec, err := run.OpenSecrets(b.dir, b.sealer)
	if err != nil {
		t.Fatal(err)
	}
	b.feed = newFeed()
	b.h, err = newHostWith(b.dir, sec, b.node.connect, b.log.add, func(func(string, camera.Kind)) (decoder, error) { return refusing{b.feed, "porch"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.h.setCapture("porch", "continuous") == nil {
		t.Fatal("the turn-on was applied")
	}
	if b.h.st.Cameras[0].Capture != "off" {
		t.Fatal("the record kept the new mode")
	}
	if st, err := load(b.dir); err != nil || st.Cameras[0].Capture != "off" {
		t.Fatalf("the file kept the new mode: %+v, %v", st, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := b.h.clerk.Run(ctx, "porch"); err == nil || b.node.dials.Load() != 0 {
		t.Fatalf("the clerk's gate opened after a failed turn-on: %v, %d dials", err, b.node.dials.Load())
	}
}

// #3967: a re-pin at a new address that the clerk refuses (off the home
// network) puts the old address and key back: the record and the file
// hold them, the old node streams again, and the new key is refused.
func TestRepinFailedAddRollsBack(t *testing.T) {
	b := newBox(t)
	oldPin := b.pin()
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })
	other, otherPin := newCert(t)
	if b.h.repin("porch", "8.8.8.8:443", otherPin) == nil {
		t.Fatal("the clerk took an address off the home network")
	}
	if st, err := load(b.dir); err != nil || st.Cameras[0].Addr != camAddr || st.Cameras[0].Key != oldPin {
		t.Fatalf("the file kept the refused pin: %+v, %v", st, err)
	}
	if r := b.h.st.Cameras[0]; r.Addr != camAddr || r.Key != oldPin {
		t.Fatalf("the record kept the refused pin: %+v", r)
	}
	n := b.feed.n("porch")
	waitFor(t, "frames under the old pin", func() bool { return b.feed.n("porch") > n })
	b.node.mu.Lock()
	b.node.cert = other
	b.node.mu.Unlock()
	b.redial("porch")
	waitFor(t, "the new key to be refused", func() bool { return strings.Contains(b.status(), "camera porch: off") })
}

// #3967: a re-pin at the same address whose key the clerk refuses (all
// zero) leaves the old key pinned, and the stream it ended runs again.
func TestRepinFailedRepinRollsBack(t *testing.T) {
	b := newBox(t)
	oldPin := b.pin()
	if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") > 0 })
	if b.h.repin("porch", "", strings.Repeat("00", 32)) == nil {
		t.Fatal("the clerk took an all-zero key")
	}
	if st, err := load(b.dir); err != nil || st.Cameras[0].Key != oldPin {
		t.Fatalf("the file kept the refused key: %+v, %v", st, err)
	}
	n := b.feed.n("porch")
	waitFor(t, "frames under the old pin", func() bool { return b.feed.n("porch") > n })
}

// slotFails is a sealer that cannot seal one sealed slot, as a slot that
// fails on every start.
type slotFails struct {
	clerk.Sealer
	slot string
}

func (s slotFails) Seal(plain, aad []byte) ([]byte, error) {
	if bytes.HasSuffix(aad, []byte("/"+s.slot)) {
		return nil, errors.New("the slot fails")
	}
	return s.Sealer.Seal(plain, aad)
}

// #3968: a camera whose sealed key slot fails at every start no longer
// keeps the others down. The start goes on; the broken camera keeps its
// directory through every sweep, is never dialed, and is shown refused;
// every other camera streams and its capture expires; the owner's
// disconnect erases the broken one.
func TestBrokenSlotKeepsOthersRunning(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect(b.rec("porch", "continuous", 3600)); err != nil {
		t.Fatal(err)
	}
	y := b.rec("yard", "continuous", 1)
	y.Addr = "192.168.1.61:8443"
	if err := b.h.connect(y); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frames", func() bool { return b.feed.n("porch") >= 4 && b.feed.n("yard") >= 4 })
	b.halt()
	porchDir := filepath.Join(b.dir, "capture", "porch")
	porch, err := os.ReadDir(porchDir)
	if err != nil || len(porch) == 0 {
		t.Fatalf("no segment: %v", err)
	}
	yard, _ := b.h.store.Segments("yard")
	if len(yard) == 0 {
		t.Fatal("no yard segment")
	}
	// The slot is lost and cannot be made again.
	sec, _ := run.OpenSecrets(b.dir, b.sealer)
	if err := sec.Remove(camera.SegmentSlots + "porch"); err != nil {
		t.Fatal(err)
	}
	b.sealer = slotFails{b.sealer, camera.SegmentSlots + "porch"}
	for i := range 2 { // the slot fails on every start
		sec, err = run.OpenSecrets(b.dir, b.sealer)
		if err != nil {
			t.Fatal(err)
		}
		b.feed = newFeed()
		b.h, err = newHostWith(b.dir, sec, b.node.connect, b.log.add, func(func(string, camera.Kind)) (decoder, error) { return b.feed, nil })
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := b.h.start(ctx); err != nil {
			cancel()
			t.Fatalf("one camera's slot kept every camera down: %v", err)
		}
		done := make(chan struct{})
		go func() { b.h.tick(ctx, 20*time.Millisecond); close(done) }()
		b.cancel, b.done = cancel, done // halted by the cleanup on the last start
		waitFor(t, "yard to stream", func() bool { return b.feed.n("yard") >= 4 })
		waitFor(t, "yard's old capture to expire", func() bool {
			s, _ := b.h.store.Segments("yard")
			return !slicesHas(s, yard[0].Name)
		})
		if i == 0 {
			b.halt()
		}
		if after, err := os.ReadDir(porchDir); err != nil || len(after) != len(porch) {
			t.Fatalf("a sweep erased the broken camera's capture: %d of %d, %v", len(after), len(porch), err)
		}
		if b.feed.n("porch") != 0 || strings.Contains(strings.Join(b.h.clerk.Status(), "\n"), "camera porch:") {
			t.Fatal("the broken camera was connected")
		}
		if !strings.Contains(b.status(), "camera porch: refused: its capture store did not open") {
			t.Fatalf("STATUS:\n%s", b.status())
		}
		if !errors.Is(b.h.setCapture("porch", "off"), errBroken) {
			t.Fatal("a change on the broken camera was taken")
		}
	}
	if err := b.h.disconnect("porch"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(porchDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the disconnect left the broken camera's capture")
	}
	if st, _ := load(b.dir); len(st.Cameras) != 1 || st.Cameras[0].ID != "yard" || strings.Contains(b.status(), "porch") {
		t.Fatalf("the broken camera is still connected: %+v\n%s", st, b.status())
	}
	// Its name is free again: a camera connected under it streams.
	p := b.rec("porch", "continuous", 0)
	p.Addr = "192.168.1.62:8443"
	if err := b.h.connect(p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reconnected camera to stream", func() bool { return b.feed.n("porch") > 0 })
}

func slicesHas(segs []camera.Segment, name string) bool {
	for _, s := range segs {
		if s.Name == name {
			return true
		}
	}
	return false
}
