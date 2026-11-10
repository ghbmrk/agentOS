package main

// The daemon's own steps that only a failure or a second call shows
// (#5207): open's defaults and refusals, the clock's logs, the page's
// listeners and certificate, the channel's guards, and the firewall's
// kicks.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// TestOpenDefaults: a daemon given no clock or random source runs on the
// system's.
func TestOpenDefaults(t *testing.T) {
	x := newBox(t, true)
	x.d.Close()
	dp := x.deps()
	dp.Now, dp.Rand = nil, nil
	d, err := open(x.cfg, x.dir, dp)
	if err != nil {
		t.Fatal(err)
	}
	x.d = d
	if d.dp.Rand != rand.Reader {
		t.Error("no random source: not crypto/rand")
	}
	if d.dp.Now == nil || d.dp.Now().Sub(time.Now()).Abs() > time.Minute {
		t.Error("no clock: not the system's")
	}
}

// TestOpenRefusesBadState: a state directory others can read, or a
// channel key file that holds no key, stops the start.
func TestOpenRefusesBadState(t *testing.T) {
	x := newBox(t, true)
	x.d.Close()
	if err := os.Chmod(x.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if d, err := x.open(); !errors.Is(err, errStateDir) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("a group-readable state directory: %v", err)
	}
	os.Chmod(x.dir, 0o700)
	key := filepath.Join(x.dir, fileChannelKey)
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := x.open(); !errors.Is(err, errKeyFile) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("a channel key file with no key: %v", err)
	}
	os.Remove(key)
	x.start()
}

// TestChannelEventLogged: each authenticated request is a channel line
// in the log, in the owner's zone.
func TestChannelEventLogged(t *testing.T) {
	x := newBox(t, true)
	c, _ := x.dial(x.serve(), x.core)
	c.read()
	waitFor(t, func() bool {
		x.mu.Lock()
		defer x.mu.Unlock()
		for _, l := range x.log {
			if strings.Contains(l, " UTC channel ") {
				return true
			}
		}
		return false
	})
}

// TestKickCoalesces: a kick while one is waiting returns at once.
func TestKickCoalesces(t *testing.T) {
	x := newBox(t, false)
	for range 3 {
		x.d.kick()
	}
	if n := len(x.d.changed); n != 1 {
		t.Fatalf("%d kicks waiting, want 1", n)
	}
}

// TestTickLogsFailures: a policy step, a firewall load or a certificate
// renewal that fails at a tick is logged, and the tick goes on.
func TestTickLogsFailures(t *testing.T) {
	x := newBox(t, false)
	a := newAuthenticator(t)
	x.b.enrol(a, caseCode)
	x.advance(time.Second)
	if w := x.b.approve(a, home()); w.Code != http.StatusOK {
		t.Fatalf("approve home: %d %s", w.Code, w.Body)
	}
	x.fail(filePolicy, true)
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if x.logs("policy: ") == 0 {
		t.Error("a policy step that was not saved was not logged")
	}
	x.fail(filePolicy, false)

	x.d.fwMu.Lock()
	x.d.loaded = "stale"
	x.d.fwMu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.advance(time.Second)
	if x.logs("firewall: nft: refused") == 0 {
		t.Error("a refused firewall load was not logged")
	}

	x.d.certMu.Lock()
	x.d.cert.Leaf.Certificate = [][]byte{[]byte("not a certificate")}
	x.d.certMu.Unlock()
	page := x.d.Page()
	x.advance(time.Second)
	if x.logs("page certificate: ") == 0 || x.d.Page() != page {
		t.Error("a leaf that cannot be renewed was not logged, or rebuilt the page")
	}
}

// TestRenewalNotSaved: a renewed leaf whose save fails is logged and not
// taken; the next tick after a saved one renews nothing.
func TestRenewalNotSaved(t *testing.T) {
	x := newBox(t, false)
	page := x.d.Page()
	x.fail(fileCert, true)
	x.advance(397 * 24 * time.Hour)
	if x.logs("page certificate: ") == 0 || x.d.Page() != page {
		t.Fatal("a renewal that was not saved was not logged, or rebuilt the page")
	}
	x.fail(fileCert, false)
	x.advance(time.Second)
	if page = x.d.Page(); page == nil {
		t.Fatal("no page")
	}
	x.advance(time.Second)
	if x.d.Page() != page {
		t.Fatal("a tick after the renewal renewed again")
	}
}

// TestRenewOnlyNearEnd: a tick with the leaf far from its end keeps the
// page as it is; one near its end renews the leaf and rebuilds the page.
func TestRenewOnlyNearEnd(t *testing.T) {
	x := newBox(t, false)
	page := x.d.Page()
	x.advance(time.Hour)
	if x.d.Page() != page {
		t.Fatal("a tick rebuilt the page with nothing changed")
	}
	x.advance(397 * 24 * time.Hour)
	if x.d.Page() == page {
		t.Fatal("a leaf at its end did not rebuild the page")
	}
}

// TestCoreStateToldOnce: a tick tells the alerts the core's state only
// when it changed, since each telling shows the light again.
func TestCoreStateToldOnce(t *testing.T) {
	x := newBox(t, true)
	x.d.Close()
	cl := &countLight{}
	dp := x.deps()
	dp.Light = cl
	d, err := open(x.cfg, x.dir, dp)
	if err != nil {
		t.Fatal(err)
	}
	x.d = d
	x.advance(time.Second) // the minute's Refresh
	x.mu.Lock()
	d.coreSeen.Store(int64(x.el) + 1)
	x.mu.Unlock()
	cl.mu.Lock()
	cl.n = 0
	cl.mu.Unlock()
	for range 5 {
		x.advance(time.Second)
	}
	if d.alerts.Status().CoreDown {
		t.Fatal("a core heard a moment ago is shown down")
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.n != 1 {
		t.Fatalf("the core coming up showed the light %d times, want once", cl.n)
	}
}

// TestPageListeners: a rebuilt page closes the old page's listeners, and
// Close closes the page's.
func TestPageListeners(t *testing.T) {
	x := newBox(t, false)
	x.d.dp.Listen = true
	x.d.cfg.Page = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")}
	x.d.cfg.PageAllow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if err := x.d.rebuildPage(); err != nil {
		t.Fatal(err)
	}
	old := x.d.pageLns[0].Addr().String()
	if err := x.d.rebuildPage(); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", old); err == nil {
		c.Close()
		t.Fatal("the old page's listener still accepts")
	}
	cur := x.d.pageLns[0].Addr().String()
	// The listener is served: a permanent accept failure ends Serve,
	// which logs it.
	f, err := x.d.pageLns[0].(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Shutdown(int(f.Fd()), syscall.SHUT_RD); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return x.logs("page: ") > 0 })
	if err := x.d.rebuildPage(); err != nil {
		t.Fatal(err)
	}
	cur = x.d.pageLns[0].Addr().String()
	x.d.Close()
	if c, err := net.Dial("tcp", cur); err == nil {
		c.Close()
		t.Fatal("the page's listener accepts after Close")
	}
	x.start()
}

// TestPageListenRefused: an address the page cannot listen on is the
// rebuild's error.
func TestPageListenRefused(t *testing.T) {
	x := newBox(t, false)
	x.d.dp.Listen = true
	x.d.cfg.Page = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:0")}
	x.d.cfg.PageAllow = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := x.d.rebuildPage(); err == nil {
		t.Fatal("a page address not on this host was listened on")
	}
}

// TestRebuildPageRefused: a page the configuration cannot build is an
// error, and the page in force stays.
func TestRebuildPageRefused(t *testing.T) {
	x := newBox(t, false)
	page := x.d.Page()
	x.d.cfg.PageAllow = nil
	if err := x.d.rebuildPage(); err == nil {
		t.Fatal("a page with no allowed network was built")
	}
	if x.d.Page() != page {
		t.Fatal("a refused page replaced the one in force")
	}
}

// TestNoCoreNoChannel: with no core pinned, revoking the core's key and
// serving the channel are both errNoCore.
func TestNoCoreNoChannel(t *testing.T) {
	x := newBox(t, false)
	if err := x.d.RevokeCore(nil, nil); !errors.Is(err, errNoCore) {
		t.Errorf("RevokeCore: %v", err)
	}
	if err := x.d.ServeChannel(&scriptListener{}); !errors.Is(err, errNoCore) {
		t.Errorf("ServeChannel: %v", err)
	}
}

// errEntropy is failReader's error.
var errEntropy = errors.New("entropy: none")

type dryReader struct{}

func (dryReader) Read([]byte) (int, error) { return 0, errEntropy }

// TestChannelCertNeedsEntropy: with no randomness the channel serves
// nothing, and says why.
func TestChannelCertNeedsEntropy(t *testing.T) {
	x := newBox(t, true)
	x.d.dp.Rand = dryReader{}
	if err := x.d.ServeChannel(&scriptListener{}); !errors.Is(err, errEntropy) {
		t.Fatalf("ServeChannel with no randomness: %v", err)
	}
}

// holdConn is an accepted connection from the core whose handshake read
// waits until released.
type holdConn struct {
	*probeConn
	release chan struct{}
}

func (c *holdConn) Read([]byte) (int, error) {
	c.probeConn.Read(nil)
	<-c.release
	return 0, net.ErrClosed
}

// TestCoreConnsCapped: past MaxCoreConns a connection is closed unread,
// and its slot given back, so the slots free to zero.
func TestCoreConnsCapped(t *testing.T) {
	x := newBox(t, true)
	release := make(chan struct{})
	var held []*holdConn
	for range MaxCoreConns {
		held = append(held, &holdConn{newProbeConn(coreAddr), release})
	}
	extra := newProbeConn(coreAddr)
	hard := errors.New("accept: listener broken")
	l := &scriptListener{}
	// The extra connection comes once every slot is taken.
	for _, c := range held {
		l.steps = append(l.steps, c)
	}
	waitAll := &gateConn{probeConn: extra, wait: func() {
		for _, c := range held {
			<-c.read
		}
	}}
	l.steps = append(l.steps, waitAll, hard)
	if err := x.d.ServeChannel(l); !errors.Is(err, hard) {
		t.Fatalf("ServeChannel: %v", err)
	}
	if !extra.closed.Load() {
		t.Fatal("a connection past the cap was left open")
	}
	select {
	case <-extra.read:
		t.Fatal("a connection past the cap was read")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	waitFor(t, func() bool { return x.d.conns.Load() == 0 })
}

// gateConn waits for wait before it reports its address, so the listener
// accepts it only after wait.
type gateConn struct {
	*probeConn
	wait func()
}

func (c *gateConn) RemoteAddr() net.Addr { c.wait(); return c.probeConn.RemoteAddr() }

// TestAbortedHandshakeNotServed: a client that aborts the TLS handshake
// after the server's flight gets no session and no channel line.
func TestAbortedHandshakeNotServed(t *testing.T) {
	x := newBox(t, true)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cert, err := ephemeralCert(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		x.d.serveConn(tls.Server(a, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
		close(done)
	}()
	refuse := errors.New("refused")
	cl := tls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return refuse }})
	if err := cl.HandshakeContext(context.Background()); err == nil {
		t.Fatal("the client's refusal did not end the handshake")
	}
	b.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an aborted handshake was served")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, l := range x.log {
		if strings.Contains(l, " channel ") {
			t.Fatalf("an aborted handshake reached the channel: %s", l)
		}
	}
}

// TestPageApplyKicks: a change the page applies at once kicks the
// firewall.
func TestPageApplyKicks(t *testing.T) {
	x, a := enrolled(t, false)
	select {
	case <-x.d.changed:
	default:
	}
	if w := x.b.approve(a, policy.Document{}); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if x.current().Device("tv") != nil {
		t.Fatal("fixture: the tightening did not apply at once")
	}
	if len(x.d.changed) != 1 {
		t.Fatal("a change the page applied did not kick the firewall")
	}
}

// TestLoadRefusesUncompiled: a document the firewall cannot compile is
// refused before the resolver or the ruleset is touched.
func TestLoadRefusesUncompiled(t *testing.T) {
	x, _ := enrolled(t, false)
	doc := home()
	doc.Devices = append(doc.Devices, policy.Device{ID: "tv2", Network: policy.NetDevices, WiFi: "vlan101", Everyday: true})
	touched := func() (int, int) {
		x.dns.mu.Lock()
		defer x.dns.mu.Unlock()
		x.fire.mu.Lock()
		defer x.fire.mu.Unlock()
		return len(x.dns.applied), len(x.fire.loads) + len(x.fire.ctxs) + x.fire.listed
	}
	applies, loads := touched()
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), doc)
	x.d.fwMu.Unlock()
	if err == nil {
		t.Fatal("a document two devices share a VLAN in was loaded")
	}
	if a, l := touched(); a != applies || l != loads {
		t.Fatal("a refused document touched the resolver or the ruleset")
	}
}

// TestFailedListingBytesDropped: a running table that does not read is
// taken as empty, whatever bytes came with the error, so the load is
// the document's own.
func TestFailedListingBytesDropped(t *testing.T) {
	x, _ := enrolled(t, false)
	x.fire.mu.Lock()
	x.fire.listAt = func(int) ([]byte, error, bool) {
		return []byte(`{"nftables": [`), errors.New("nft: list failed"), true
	}
	x.fire.mu.Unlock()
	doc := home()
	doc.Devices[0].Allow = []string{"tv.example", "tv2.example"}
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), doc)
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if x.fire.last() != x.fullLoad(doc) {
		t.Fatal("the load read the bytes of a failed listing")
	}
	if x.logs("firewall: running table unreadable") == 0 {
		t.Fatal("the unreadable running table was not logged")
	}
}

// TestMergingReloadFailureLogged: a reload a port's merging asks for
// that fails is logged at the reading.
func TestMergingReloadFailureLogged(t *testing.T) {
	x, _, _ := capped(t)
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.merges(x.cfg.Layout.Core, errors.New("offload: core0: rx-gro on"))
	x.advance(readEvery)
	if x.logs("firewall: nft: refused") == 0 {
		t.Fatal("a refused reload at the reading was not logged")
	}
}

// TestChannelCountsRead: the channel's counts read trips a cap it finds
// passed, fails when the running table does not read, and, as the fresh
// day's reading does, ends its listing's context when it returns.
func TestChannelCountsRead(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 600))
	x.advance(readEvery)
	x.fire.mu.Lock()
	x.fire.listErr = errors.New("nft: list failed")
	x.fire.mu.Unlock()
	if _, err := x.d.counts(); err == nil {
		t.Fatal("a counts read whose listing failed answered")
	}
	x.fire.mu.Lock()
	x.fire.listErr = nil
	x.fire.mu.Unlock()
	x.d.fwMu.Lock()
	_, err := x.d.freshState(context.Background(), x.d.dp.Now())
	x.d.fwMu.Unlock()
	x.fire.mu.Lock()
	ctx := x.fire.listCtx
	x.fire.mu.Unlock()
	if err != nil || ctx.Err() == nil {
		t.Fatalf("the fresh day's reading left its listing's context running: %v", err)
	}
	x.setListing(listing(t, x, doc, 7, 1100))
	if _, err := x.d.counts(); err != nil {
		t.Fatal(err)
	}
	x.fire.mu.Lock()
	ctx = x.fire.listCtx
	x.fire.mu.Unlock()
	if ctx.Err() == nil {
		t.Fatal("the counts read left its listing's context running")
	}
	waitFor(t, func() bool { return x.d.cut.Stage() == channel.Tripped })
}
