package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/heads"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Silence is how long the core may send the enforcer nothing before the
// page shows it down: two missed beats of a heartbeat sent each summary
// interval (KRN-12 Silence; ASSUMPTIONS ENF-l-7).
const Silence = 2 * wire.SummaryInterval

// MaxCoreConns is how many channel connections may be open at once: the
// one in use and a reconnect that replaces it. Any more is closed before
// the TLS handshake (channel ASSUMPTIONS ENF-d-4: the per-source limit is
// the listener's).
const MaxCoreConns = 2

// handshakeTimeout bounds a channel connection's TLS handshake.
const handshakeTimeout = 10 * time.Second

// firewall is the nft loader (broker/enforcer/nft/load.Loader).
type firewall interface {
	Load(ctx context.Context, ruleset string) error
	List(ctx context.Context, table string) ([]byte, error)
}

// deps is what the daemon takes from the box: production values in
// main.go, fakes in the lifecycle test.
type deps struct {
	Now     func() time.Time
	Elapsed func() time.Duration // CLOCK_BOOTTIME in production (#4507)
	Rand    io.Reader
	Fire    firewall
	Network enrol.Network
	Light   alert.Light
	Radio   channel.Radio
	Logf    func(string)
	// Listen binds the page's addresses; the lifecycle test drives the
	// page's handler instead.
	Listen bool
}

// Enforcer is the daemon: every piece of slices a to h wired to one
// policy engine behind one lock (channel ASSUMPTIONS ENF-d-5).
type Enforcer struct {
	cfg Config
	dir string
	dp  deps

	// mu is the policy lock: the page, the channel and the clock call
	// the engine only under it, and the book takes it itself.
	mu     sync.Mutex
	engine *policy.Engine
	book   *enrol.Book
	alerts *alert.Alerts
	heads  *heads.Store // nil with no core pinned
	ch     *channel.Channel
	chCfg  channel.Config
	cut    *cut
	core   ed25519.PublicKey
	coreCA []byte

	certMu sync.Mutex
	cert   page.Cert

	pageMu    sync.Mutex
	page      *page.Server
	pageOwner key.PublicKey
	pageLns   []net.Listener

	fwMu   sync.Mutex
	loaded string // hash of the document the firewall last loaded

	coreSeen atomic.Int64 // Elapsed at the core's last authenticated line, +1; 0 never
	conns    atomic.Int32
	changed  chan struct{}
	lastLit  time.Time
}

var errNoCore = errors.New("no core pinned: the channel is off")

// open builds the daemon from the state directory. The enrolment store
// must already be provisioned (-provision), as the image's first boot does.
func open(cfg Config, dir string, dp deps) (*Enforcer, error) {
	if dp.Now == nil {
		dp.Now = time.Now
	}
	if dp.Rand == nil {
		dp.Rand = rand.Reader
	}
	if dp.Elapsed == nil || dp.Fire == nil || dp.Network == nil || dp.Light == nil || dp.Radio == nil || dp.Logf == nil {
		return nil, errors.New("daemon: deps incomplete")
	}
	if err := checkStateDir(dir); err != nil {
		return nil, err
	}
	d := &Enforcer{cfg: cfg, dir: dir, dp: dp, changed: make(chan struct{}, 1)}
	at := func(name string) string { return filepath.Join(dir, name) }
	var err error
	if d.alerts, err = alert.New(alert.Config{Send: d.send, Light: dp.Light, Journal: fileJournal{at(fileAlerts)}, Now: dp.Now}); err != nil {
		return nil, fmt.Errorf("alerts: %w", err)
	}
	if d.book, err = enrol.Open(enrol.Config{Name: cfg.Name, Store: fileStore{at(fileEnrol)}, Network: dp.Network,
		Alerts: d.alerts, Lock: &d.mu, Now: dp.Now, Rand: dp.Rand}); err != nil {
		return nil, fmt.Errorf("enrolment: %w", err)
	}
	if d.engine, err = d.book.OpenPolicy(fileStore{at(filePolicy)}); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if d.cut, err = openCut(fileStore{at(fileCut)}, d.alerts, dp.Logf); err != nil {
		return nil, err
	}
	if d.cert, err = pageCert(fileStore{at(fileCert)}, cfg.Name, dp.Now()); err != nil {
		return nil, fmt.Errorf("page certificate: %w", err)
	}
	if d.coreCA, err = (fileStore{at(fileCoreCA)}).Load(); err != nil {
		return nil, err
	}
	if d.core, err = coreKey(fileStore{at(fileCoreKey)}); err != nil {
		return nil, fmt.Errorf("core key: %w", err)
	}
	if d.core != nil {
		if err := d.openChannel(at); err != nil {
			return nil, err
		}
	}
	d.alerts.Recovery(d.recoveryPending())
	if err := d.syncFirewall(context.Background()); err != nil {
		dp.Logf("firewall: " + err.Error())
	}
	if err := d.rebuildPage(); err != nil {
		d.Close()
		return nil, fmt.Errorf("page: %w", err)
	}
	return d, nil
}

func (d *Enforcer) openChannel(at func(string) string) error {
	priv, err := channelKey(fileStore{at(fileChannelKey)}, d.dp.Rand)
	if err != nil {
		return fmt.Errorf("channel key: %w", err)
	}
	if d.heads, err = heads.Open(heads.Config{Kernel: d.core, Journal: fileJournal{at(fileHeads)}, Fork: d.fork}); err != nil {
		return fmt.Errorf("heads: %w", err)
	}
	d.chCfg = channel.Config{
		Core: d.core, Key: priv, Revoked: d.heads.Revoked,
		Policy: lockedPolicy{d}, Radio: d.dp.Radio, Heads: d.heads, Alerts: d.alerts, Cut: d.cut,
		Log: d.event, Now: d.dp.Now, Elapsed: d.dp.Elapsed,
	}
	if d.ch, err = channel.New(d.chCfg); err != nil {
		return fmt.Errorf("channel: %w", err)
	}
	return nil
}

// send is the alerts' owner line: the kernel, over the channel. The core
// may drop it; the enforcer's page, log and light are the record (P6).
func (d *Enforcer) send(a wire.Alert) error {
	if d.ch == nil {
		return errNoCore
	}
	return d.ch.Alert(a)
}

func (d *Enforcer) fork(seq uint64) {
	if _, err := d.alerts.Raise(alert.HeadFork, ""); err != nil {
		d.dp.Logf(fmt.Sprintf("heads: fork at %d: alert: %v", seq, err))
	}
}

// event is the channel's log: one line per request and refusal, in the
// owner's zone, through Event.Line so no field is dropped (#4185). Every
// line but a failed hello's is the authenticated core's, which is what
// keeps the core counted as up.
func (d *Enforcer) event(e channel.Event) {
	if e.Kind != channel.KindPreAuth && !(e.Kind == channel.KindHello && e.Code == wire.Refused) {
		d.coreSeen.Store(int64(d.dp.Elapsed()) + 1)
	}
	d.dp.Logf(e.At.In(d.cfg.zone).Format("2006-01-02 15:04 MST") + " channel " + e.Line())
}

// coreUp reports whether the core spoke within Silence.
func (d *Enforcer) coreUp() bool {
	s := d.coreSeen.Load()
	return s != 0 && d.dp.Elapsed()-time.Duration(s-1) < Silence
}

func (d *Enforcer) recoveryPending() bool {
	_, ok := d.book.Recovery()
	return ok
}

// kick asks the run loop to bring the firewall up to the policy in force.
func (d *Enforcer) kick() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

// syncFirewall loads the ruleset for the policy in force if it is not the
// one loaded. A load that fails leaves the previous ruleset (nft's
// transaction, P5) and is tried again at the next tick.
func (d *Enforcer) syncFirewall(ctx context.Context) error {
	d.mu.Lock()
	doc := d.engine.Current()
	d.mu.Unlock()
	h, err := policy.Hash(doc)
	if err != nil {
		return err
	}
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	if h == d.loaded {
		return nil
	}
	var running []byte
	if d.loaded != "" {
		if running, err = d.dp.Fire.List(ctx, nft.Table); err != nil {
			d.dp.Logf("firewall: running table unreadable, resolver answers start empty: " + err.Error())
			running = nil
		}
	}
	text, err := nft.Reload(doc, d.cfg.Layout, running)
	if err != nil {
		return err
	}
	if err := d.dp.Fire.Load(ctx, text); err != nil {
		return err
	}
	d.loaded = h
	return nil
}

// Tick is the daemon's clock: replacement passkeys and loosenings whose
// wait is over, the firewall, the core's silence, the light and the
// page's certificate, and the page rebuilt for the passkey in force.
func (d *Enforcer) Tick(ctx context.Context) {
	now := d.dp.Now()
	// The book takes the policy lock itself (enrol ASSUMPTIONS ENF-c-8).
	if _, err := d.book.Tick(); err != nil {
		d.dp.Logf("enrolment: " + err.Error())
	}
	d.alerts.Recovery(d.recoveryPending())
	d.mu.Lock()
	_, err := d.engine.Tick(now.UnixMilli())
	d.mu.Unlock()
	if err != nil {
		d.dp.Logf("policy: " + err.Error())
	}
	if err := d.syncFirewall(ctx); err != nil {
		d.dp.Logf("firewall: " + err.Error())
	}
	d.alerts.Core(d.coreUp())
	if now.Sub(d.lastLit) >= time.Minute {
		d.lastLit = now
		if err := d.alerts.Refresh(); err != nil {
			d.dp.Logf("light: " + err.Error())
		}
	}
	rebuild := d.renewCert(now)
	d.pageMu.Lock()
	rebuild = rebuild || d.pageOwner != d.book.Owner()
	d.pageMu.Unlock()
	if rebuild {
		if err := d.rebuildPage(); err != nil {
			d.dp.Logf("page: " + err.Error())
		}
	}
}

// renewCert renews the page's leaf when it is near its end and reports
// whether it changed.
func (d *Enforcer) renewCert(now time.Time) bool {
	d.certMu.Lock()
	defer d.certMu.Unlock()
	r, err := d.cert.Renew(d.cfg.Name, now)
	if err != nil {
		d.dp.Logf("page certificate: " + err.Error())
		return false
	}
	if leafEqual(r, d.cert) {
		return false
	}
	if err := saveCert(fileStore{filepath.Join(d.dir, fileCert)}, r); err != nil {
		d.dp.Logf("page certificate: " + err.Error())
		return false
	}
	d.cert = r
	return true
}

// rebuildPage builds the page for the passkey in force (enrol ASSUMPTIONS
// ENF-c-8) and, when listening, moves the page's addresses to it. The old
// page takes no tap from the moment the book's passkey changed, so the gap
// before this runs refuses rather than accepts.
func (d *Enforcer) rebuildPage() error {
	d.certMu.Lock()
	cert := d.cert
	d.certMu.Unlock()
	owner := d.book.Owner()
	pc := page.Config{
		Name: d.cfg.Name, Owner: owner, Enrol: d.book, CA: cert.Root, CoreCA: d.coreCA,
		Addrs: d.cfg.Page, Allow: d.cfg.PageAllow, Policy: pagePolicy{d}, Lock: &d.mu,
		Log: d.dp.Logf, Zone: d.cfg.zone, Cert: cert.Leaf, Now: d.dp.Now,
	}
	if d.ch != nil {
		pc.Channel = d.cut
	}
	s, err := page.New(pc)
	if err != nil {
		return err
	}
	d.pageMu.Lock()
	defer d.pageMu.Unlock()
	old := d.pageLns
	d.page, d.pageOwner, d.pageLns = s, owner, nil
	for _, ln := range old {
		ln.Close()
	}
	if !d.dp.Listen {
		return nil
	}
	for _, a := range d.cfg.Page {
		ln, err := net.Listen("tcp", a.String())
		if err != nil {
			return err
		}
		d.pageLns = append(d.pageLns, ln)
		go func() {
			if err := s.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				d.dp.Logf("page: " + err.Error())
			}
		}()
	}
	return nil
}

// Page is the page in force, for the lifecycle test.
func (d *Enforcer) Page() *page.Server {
	d.pageMu.Lock()
	defer d.pageMu.Unlock()
	return d.page
}

// Close stops the page's listeners. The state is on disk after every
// change, so a close is the same as a power loss.
func (d *Enforcer) Close() {
	d.pageMu.Lock()
	defer d.pageMu.Unlock()
	for _, ln := range d.pageLns {
		ln.Close()
	}
	d.pageLns = nil
}

// RevokeCore revokes the kernel's channel sub-key on the owner's
// enforcer passkey assertion (heads ASSUMPTIONS ENF-h-1).
func (d *Enforcer) RevokeCore(sub ed25519.PublicKey, sig []byte) error {
	if d.heads == nil {
		return errNoCore
	}
	return d.heads.RevokeSubKey(d.book.Owner(), sub, sig)
}

// ServeChannel accepts the core's connections on ln: only from
// CoreAllow, at most MaxCoreConns at once, TLS 1.3 under a certificate
// made for this run. The hello inside, bound to the connection's
// exporter, is what authenticates both ends (wire ASSUMPTIONS ENF-d-w1).
func (d *Enforcer) ServeChannel(ln net.Listener) error {
	if d.ch == nil {
		return errNoCore
	}
	cert, err := ephemeralCert(d.dp.Rand)
	if err != nil {
		return err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil || !inPrefixes(d.cfg.CoreAllow, ap.Addr().Unmap()) {
			c.Close() // not the core's segment: no handshake, no answer
			continue
		}
		if d.conns.Add(1) > MaxCoreConns {
			d.conns.Add(-1)
			c.Close()
			continue
		}
		go func() {
			defer d.conns.Add(-1)
			defer c.Close()
			d.serveConn(tls.Server(c, tc))
		}()
	}
}

func (d *Enforcer) serveConn(t *tls.Conn) {
	t.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := t.Handshake(); err != nil {
		return
	}
	t.SetDeadline(time.Time{})
	cs := t.ConnectionState()
	exp, err := cs.ExportKeyingMaterial(wire.ExporterLabel, nil, wire.ExporterLen)
	if err != nil {
		return
	}
	_ = d.ch.Serve(t, exp)
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ephemeralCert is a self-signed Ed25519 certificate for one run: TLS
// needs one, and nothing trusts it; the hellos do the authenticating.
func ephemeralCert(r io.Reader) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return tls.Certificate{}, err
	}
	t := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentos-enforcer channel"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(r, t, t, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// lockedPolicy is the engine as the channel reaches it: every call under
// the policy lock, and a change to the policy in force kicks the firewall.
type lockedPolicy struct{ d *Enforcer }

func (p lockedPolicy) Current() policy.Document {
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	return p.d.engine.Current()
}

func (p lockedPolicy) Tighten(op policy.Op, nowMS int64) error {
	p.d.mu.Lock()
	err := p.d.engine.Tighten(op, nowMS)
	p.d.mu.Unlock()
	if err == nil {
		p.d.kick()
	}
	return err
}

func (p lockedPolicy) Secure(device, cmd string, nowMS int64) error {
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	return p.d.engine.Secure(device, cmd, nowMS)
}

func (p lockedPolicy) Export() ([]byte, error) {
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	return p.d.engine.Export()
}

// pagePolicy is the engine as the page reaches it: the page holds the
// policy lock around each call (page.Config.Lock), so this takes none,
// and a change applied at once kicks the firewall.
type pagePolicy struct{ d *Enforcer }

func (p pagePolicy) Current() policy.Document  { return p.d.engine.Current() }
func (p pagePolicy) Pending() []policy.Pending { return p.d.engine.Pending() }
func (p pagePolicy) Cancel(id string) error    { return p.d.engine.Cancel(id) }
func (p pagePolicy) Propose(next policy.Proposal, sig []byte, nowMS int64) (policy.Outcome, error) {
	o, err := p.d.engine.Propose(next, sig, nowMS)
	if err == nil && o.Applied {
		p.d.kick()
	}
	return o, err
}
