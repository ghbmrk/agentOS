package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/dns"
	dnsrun "github.com/ghbmrk/agentos/broker/enforcer/dns/run"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/enforcer/wol"
	"golang.org/x/sys/unix"
)

// The network side of the daemon (ENF-l-b1, #3670): the resolver's
// instances, the mDNS pair relay and the Wake-on-LAN relay, and the byte
// caps' counter, each moved in step with the firewall (ASSUMPTIONS
// ENF-l-11 to ENF-l-15).

const (
	fileTraffic = "traffic.json" // traffic.Counter's saved day
	fileLoaded  = "loaded.json"  // the document the running ruleset was compiled from
	// readEvery is the byte caps' reading interval: what a power cut can
	// lose of the day's count (traffic ASSUMPTIONS ENF-cap-6).
	readEvery = 10 * time.Second
	wakeRetry = time.Second
)

type network struct {
	// filter is the mDNS relay's memory of names for the process's
	// lifetime: the relay keeps it across restarts and the page reads it
	// (mdns.HeardBy), so a pin is offered only from what the relay heard
	// (#4531 comment 6568595938).
	filter *mdns.Filter

	mdnsMu   sync.Mutex
	mdnsStop context.CancelFunc
	mdnsDone chan struct{}
	mdnsPlan mdns.Plan
	mdnsDown bool // the relay ended on its own: started again at the tick

	relay *wol.Relay // nil with no machine to wake

	// prevDoc is the document the previous process last loaded
	// (fileLoaded), which the running table was compiled from: the first
	// load after a crash reads that table against it, so its bytes since
	// the last reading count (Potency 6656993166). nil when none.
	prevDoc *policy.Document

	// merging is each counted port that merges segments, or could not be
	// read: its error, logged when it starts or changes. Its caps are
	// held spent while it lasts (ENF-l-16). d.fwMu guards it and reload.
	merging map[string]string
	// reload asks syncFirewall for a full load of the policy in force,
	// so the quotas start again from the counts with merging's caps
	// spent or no longer spent: a running quota keeps its own count.
	reload bool
	// unserved is why the served interfaces are not as set up (served),
	// "" while they are: no resolver instance runs meanwhile (ENF-l-21).
	// d.fwMu guards it.
	unserved string
	// The resolver as the page shows it (pageResolver, #5164 R1), each
	// set under d.fwMu and read under resMu, so the page never waits on a
	// load: whether its instances run (the files the last taken load
	// started, or none since the served check stopped them), the served
	// check's failure, the policy in force's, and the last refused
	// load's error ("" once one is taken).
	resMu      sync.Mutex
	resRuns    bool
	stopServed error
	stopPolicy string
	stopLoad   string
	// refreshErr is the resolver step's last failure, logged once while
	// it lasts ("" while it works).
	refreshErr string

	// The byte caps: counter is nil when the saved state did not read
	// back (spent), and then every capped send is dropped until the
	// state is replaced (traffic ErrState; ENF-l-14).
	counter  *traffic.Counter
	spent    bool
	boot     string
	past     bool
	lastRead time.Time
}

// openNetwork builds the network side before the first load: the relay's
// filter, the Wake-on-LAN relay and the byte caps restored from disk.
func (d *Enforcer) openNetwork() error {
	// The byte caps count each packet as the port received it: one that
	// merges segments counts one IP header for several, so its caps are
	// loaded spent while it does (ASSUMPTIONS ENF-l-16).
	d.offloads()
	d.net.filter = mdns.NewFilter()
	ms, err := d.cfg.machines()
	if err != nil {
		return fmt.Errorf("wake: %w", err)
	}
	if len(ms) > 0 {
		if d.net.relay, err = wol.New(d.cfg.Layout, ms); err != nil {
			return fmt.Errorf("wake: %w", err)
		}
	}
	if d.net.boot, err = d.dp.Boot(); err != nil {
		return fmt.Errorf("boot id: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.dp.FireWait)
	defer cancel()
	if d.net.past, err = d.dp.Fire.QuotaPast(ctx); err != nil {
		// Left false, a cap lets one byte more through, which the next
		// reading trips on (nft.Drop.Past).
		d.dp.Logf("firewall: quota edge unreadable, caps drop one byte late: " + err.Error())
	}
	d.mu.Lock()
	caps := traffic.CapsOf(d.engine.Current())
	d.mu.Unlock()
	if b, err := d.store(fileLoaded).Load(); err != nil || b != nil {
		var doc policy.Document
		if err == nil {
			doc, err = policy.Decode(b)
		}
		if err != nil {
			d.dp.Logf("byte caps: the last loaded document is unreadable, the running table's bytes since the last reading are not counted: " + err.Error())
		} else {
			d.net.prevDoc = &doc
		}
	}
	b, err := d.store(fileTraffic).Load()
	switch {
	case err != nil:
		return fmt.Errorf("byte caps: %w", err)
	case b == nil:
		d.net.counter = traffic.NewCounter(d.dp.Now, caps)
	default:
		// Restore's only error is traffic.ErrState: the saved day does not read back.
		if d.net.counter, err = traffic.Restore(d.dp.Now, caps, b); err != nil {
			d.net.counter, d.net.spent = nil, true
			d.dp.Logf("byte caps: saved day unreadable, every capped send stays dropped until " + fileTraffic + " is replaced: " + err.Error())
		}
	}
	return nil
}

// ServeWake runs the Wake-on-LAN relay until ctx ends; with no machine
// to wake it waits.
// A relay that stops on its own is started again after wakeRetry.
func (d *Enforcer) ServeWake(ctx context.Context) error {
	if d.net.relay == nil {
		<-ctx.Done()
		return nil
	}
	for {
		err := d.dp.Wake(ctx, d.net.relay)
		if ctx.Err() != nil {
			return nil
		}
		d.dp.Logf(fmt.Sprintf("wake: relay stopped, started again in %s: %v", wakeRetry, err))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wakeRetry):
		}
	}
}

// loadNetwork loads doc's ruleset in step with the resolver and moves the
// pair relay and the byte caps to it. d.fwMu is held. The listed dnsmasq
// instances whose lists change are stopped before the load and started
// on the new lists after it (#4464), and the running table is read
// inside that step, so nothing fills a set between the read and the load.
// The running table is read on every load, the first after a restart
// included, so the resolver's answers survive a restart (#4754 Potency
// point 1).
func (d *Enforcer) loadNetwork(ctx context.Context, doc policy.Document) (err error) {
	defer func() {
		// A refused load leaves the resolver as it was, stopped
		// included, so the page names the refusal (#5243 L3 item 1).
		if err != nil {
			d.net.resMu.Lock()
			d.net.stopLoad = err.Error()
			d.net.resMu.Unlock()
		}
	}()
	l := d.cfg.Layout
	// One compile check refuses all three: a document that does not
	// compile touches neither the resolver nor the ruleset.
	paths, err := nft.Paths(doc, l)
	ann, aerr := nft.Announces(doc, l)
	hears, herr := nft.Hears(doc, l)
	if err := cmp.Or(err, aerr, herr); err != nil {
		return err
	}
	files, genErr := dns.Generate(doc, l, d.cfg.DNS)
	if err := genErr; err != nil {
		// A document the resolver cannot serve still loads, so a
		// tightening is never held back; every instance stops, so no
		// list resolves at all until one can be served (ENF-l-11).
		d.dp.Logf("dns: the policy in force cannot be served, every resolver instance stops: " + err.Error())
		files = dns.Files{}
	}
	if d.servedLocked(); d.net.unserved != "" {
		// No instance starts on an interface that could hold a prefix or
		// route the upstream check did not see (ENF-l-21). They stop
		// before the load, not inside it: a refused load starts the
		// instances it stopped again (dns/run Apply), which would bring
		// back the old ones while the check fails (#5164 item 7). Its
		// only failure, a closed set, fails the load's Apply below too.
		d.dp.DNS.Apply(dns.Files{}, func() error { return nil })
		files = dns.Files{}
		d.net.resMu.Lock()
		d.net.resRuns = false
		d.net.resMu.Unlock()
	}
	caps := traffic.CapsOf(doc)
	load := func() error {
		running, err := d.dp.Fire.List(ctx, nft.Table)
		if err != nil {
			d.dp.Logf("firewall: running table unreadable, resolver answers start empty: " + err.Error())
			running = nil
		}
		// A full load starts new counters (a new Gen), so the bytes since
		// the last reading are read from the table it replaces first, or
		// they would count nowhere (nft ENF-cap-trip-c-2; Potency
		// 6656589394). A cap they pass trips once the load is done.
		// The first load after a restart reads it against the document
		// the previous process loaded; after a clean stop that reading
		// counts nothing new, after a crash it counts the bytes since its
		// last one (same boot, same Gen: traffic ENF-cap-6).
		was := d.loadedDoc
		if d.loaded == "" && d.net.prevDoc != nil {
			was = *d.net.prevDoc
		}
		if d.net.counter != nil && (d.loaded != "" || d.net.prevDoc != nil) && running != nil {
			over, err := d.addReading(was, running)
			if err != nil {
				d.dp.Logf("byte caps: before the load: " + err.Error())
			}
			// Tripped off this goroutine: the load holds fwMu, which
			// cut.Trip never takes and the edge's trip takes after its
			// record (tripEdge), so neither waits on the load.
			for _, o := range over {
				go d.overrun(o)
			}
		}
		text, err := nft.Reload(doc, l, running)
		if err != nil {
			return err
		}
		drops, err := nft.Drops(doc, l, nil, d.drop(caps))
		if err != nil {
			return err
		}
		lctx, cancel := context.WithTimeout(ctx, d.dp.FireWait)
		defer cancel()
		return d.dp.Fire.Load(lctx, joinRules(text, drops))
	}
	if err := d.dp.DNS.Apply(files, load); err != nil {
		if d.net.counter != nil && d.loaded != "" {
			d.net.counter.SetCaps(traffic.CapsOf(d.loadedDoc)) // the ruleset still in force
		}
		return err
	}
	// The policy in force is doc only once its load is taken; a refused
	// one leaves the resolver on the old policy's files, or none.
	why := ""
	if genErr != nil {
		why = genErr.Error()
	}
	d.net.resMu.Lock()
	d.net.resRuns = len(dnsrun.Names(files)) > 0
	d.net.stopPolicy, d.net.stopLoad = why, ""
	d.net.resMu.Unlock()
	b, err := policy.Encode(doc)
	if err == nil {
		err = d.store(fileLoaded).Save(b)
	}
	if err != nil {
		d.dp.Logf("byte caps: loaded document not saved: " + err.Error())
	}
	d.startMDNS(mdns.NewPlan(paths, ann).Hearing(hears))
	return nil
}

// joinRules appends the drop's text to a full load's, in one transaction.
func joinRules(text, drops string) string {
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text + drops
}

// drop is the byte caps' drop for caps: the counter's day, or, when the
// saved day was unreadable, every cap spent, so every capped send is
// dropped (ENF-l-14).
func (d *Enforcer) drop(caps traffic.Caps) nft.Drop {
	var p nft.Drop
	if d.net.counter != nil {
		c := d.net.counter
		c.SetCaps(caps)
		p = c.Drop()
	} else {
		p = traffic.NewCounter(d.dp.Now, caps).Drop()
		for i := range p.Groups {
			p.Groups[i].Count = p.Groups[i].Cap
		}
		p.EdgeCount = p.EdgeCap
	}
	p.Past = d.net.past
	d.holdDrop(&p)
	return p
}

// spendMerging holds the caps of each counted port that merges segments
// spent in p: every capped send it carries is dropped (ENF-l-16).
// d.fwMu is held.
func (d *Enforcer) spendMerging(p *nft.Drop) {
	if _, ok := d.net.merging[d.cfg.Layout.Core]; ok {
		for i := range p.Groups {
			p.Groups[i].Count = max(p.Groups[i].Count, p.Groups[i].Cap)
		}
	}
	if _, ok := d.net.merging[d.cfg.Layout.Edge]; ok {
		p.EdgeCount = max(p.EdgeCount, p.EdgeCap)
	}
}

// startMDNS runs the pair relay on plan, stopping the one before it.
func (d *Enforcer) startMDNS(plan mdns.Plan) {
	d.net.mdnsMu.Lock()
	defer d.net.mdnsMu.Unlock()
	d.stopMDNSLocked()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.net.mdnsStop, d.net.mdnsDone, d.net.mdnsPlan, d.net.mdnsDown = cancel, done, plan, false
	f := d.net.filter
	go func() {
		defer close(done)
		err := d.dp.MDNS(ctx, plan, f)
		if ctx.Err() != nil {
			return
		}
		d.dp.Logf(fmt.Sprintf("mdns: relay stopped, started again at the next tick: %v", err))
		d.net.mdnsMu.Lock()
		if d.net.mdnsDone == done {
			d.net.mdnsDown = true
		}
		d.net.mdnsMu.Unlock()
	}()
}

func (d *Enforcer) stopMDNSLocked() {
	if d.net.mdnsStop != nil {
		d.net.mdnsStop()
		<-d.net.mdnsDone
	}
}

// tickNetwork is the network side's clock: the pair relay started again
// if it ended, and the byte caps read and the resolver's answers
// refreshed every readEvery.
func (d *Enforcer) tickNetwork(ctx context.Context, now time.Time) {
	d.net.mdnsMu.Lock()
	down, plan := d.net.mdnsDown, d.net.mdnsPlan
	d.net.mdnsMu.Unlock()
	if down {
		d.startMDNS(plan)
	}
	if now.Sub(d.net.lastRead) < readEvery && !now.Before(d.net.lastRead) {
		return
	}
	d.net.lastRead = now
	d.fwMu.Lock()
	unserved := d.servedLocked()
	d.fwMu.Unlock()
	if merging := d.offloads(); merging || unserved {
		if err := d.syncFirewall(ctx); err != nil {
			d.dp.Logf("firewall: " + err.Error())
		}
	}
	if err := d.readCaps(ctx); err != nil {
		d.dp.Logf("byte caps: " + err.Error())
	}
	msg := ""
	if err := d.refreshAnswers(ctx); err != nil {
		msg = err.Error()
	}
	if msg != d.net.refreshErr {
		if msg != "" {
			d.dp.Logf("resolver answers: not refreshed, the answers since the last refresh take new connections until one is, for at most " + fmt.Sprint(nft.AnswerTimeout) + " s from their first answer: " + msg)
		} else {
			d.dp.Logf("resolver answers: refreshed again")
		}
		d.net.refreshErr = msg
	}
}

// refreshAnswers is the resolver's step (nft.Refresh, #4453): every answer
// added since the last step takes new connections for nft.AnswerTimeout
// from now, and no longer unless it is answered again. It holds fwMu, so
// it never runs between a load's reading of the running table and the
// load.
func (d *Enforcer) refreshAnswers(ctx context.Context) error {
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	if d.loaded == "" {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, d.dp.FireWait)
	defer cancel()
	running, err := d.dp.Fire.List(lctx, nft.Table)
	if err != nil {
		return err
	}
	text, err := nft.Refresh(d.loadedDoc, d.cfg.Layout, running)
	if err != nil || text == "" {
		return err
	}
	return d.dp.Fire.Update(lctx, text)
}

// counted are the ports whose received bytes the byte caps count: the
// core's and the edge's.
func (d *Enforcer) counted() []string { return []string{d.cfg.Layout.Core, d.cfg.Layout.Edge} }

// offloads turns merging off on each counted port, at start and again
// before each reading, since a port whose device is made again (a VLAN
// added back) starts with its driver's defaults. A port where it fails
// has its caps held spent until it reads clean; the rest of the daemon
// runs on (ENF-l-16). Each start and end of a failure is logged once. It
// reports whether a port changed, and asks for a full load if one did.
func (d *Enforcer) offloads() bool {
	now := map[string]string{}
	for _, port := range d.counted() {
		if err := d.dp.Offload(port); err != nil {
			now[port] = err.Error()
		}
	}
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	changed := false
	for _, port := range d.counted() {
		was, bad := d.net.merging[port]
		msg, still := now[port]
		switch {
		case still && (!bad || msg != was):
			d.dp.Logf("byte caps: " + port + " merges segments, every capped send it carries is dropped until it stops: " + msg)
		case bad && !still:
			d.dp.Logf("byte caps: " + port + " merges no segments again, its caps count again")
		}
		changed = changed || bad != still
	}
	d.net.merging = now
	d.net.reload = d.net.reload || changed
	return changed
}

// servedLocked sets the served interfaces up again and checks them
// (deps.Served), at every load and every reading, since an interface made
// again starts with the kernel's defaults. A failure is logged when it
// starts or changes, and its end once; it reports whether the result
// changed, and asks for a full load if it did, which stops or starts the
// resolver's instances (ENF-l-21). d.fwMu is held.
func (d *Enforcer) servedLocked() bool {
	msg := ""
	err := d.dp.Served(d.cfg.DNS.Nets)
	if err != nil {
		msg = err.Error()
	}
	d.net.resMu.Lock()
	d.net.stopServed = err
	d.net.resMu.Unlock()
	changed := msg != d.net.unserved
	switch {
	case changed && msg != "":
		d.dp.Logf("dns: a served interface is not as set up, every resolver instance stops until it is: " + msg)
	case changed:
		d.dp.Logf("dns: the served interfaces are as set up again, the resolver starts")
	}
	d.net.unserved = msg
	d.net.reload = d.net.reload || changed
	return changed
}

// strayAddr is an address hold found on a served interface outside its
// network: the page names the interface and the address (#5164 R1).
type strayAddr struct {
	iface string
	addr  netip.Prefix
	nets  string
}

func (s strayAddr) Error() string {
	return fmt.Sprintf("served interface %s holds %s, outside %s", s.iface, s.addr, s.nets)
}

// unsetErr is any other failure hold finds: its cause typed for the page
// (#5284), so the page's words never hang on this error's text, and the
// error as the log shows it.
type unsetErr struct {
	cause page.Unset
	err   error
}

func (u unsetErr) Error() string { return u.err.Error() }
func (u unsetErr) Unwrap() error { return u.err }

// procNet is the kernel's network settings (sysctl net.*).
const procNet = "/proc/sys/net"

// served is deps.Served on the box: hold on /proc/sys/net and the
// kernel's own addresses.
func served(nets []dns.Net) error { return hold(procNet, nets, ifaceAddrs) }

// noRedirects are the per-interface settings hold turns off, under
// procNet: IPv4 and IPv6 redirects and IPv6 router advertisements, each
// with the setting the page names.
var noRedirects = []struct {
	key string
	set page.Setting
}{{"ipv4/conf/%s/accept_redirects", page.Redirects4}, {"ipv6/conf/%s/accept_redirects", page.Redirects6}, {"ipv6/conf/%s/accept_ra", page.RouterAds}}

// allRedirects is the IPv4 redirect setting the kernel combines with
// each interface's own (either one on, or both with forwarding on), so
// hold turns it off too (#5164 item 4). It is the only "all" key: IPv6
// accept_redirects and accept_ra act per interface, the kernel never
// combines "all" with them, and some kernels spread a write of an IPv6
// "all" key to every interface, the WAN included, whose own settings
// hold never writes (ASSUMPTIONS ENF-l-21).
const allRedirects = "ipv4/conf/all/accept_redirects"

// hold turns router advertisements and redirects off (noRedirects, under
// root) on each served interface and on "default", which every interface
// made later starts from, turns allRedirects off, and reads each back;
// then it checks that every address on each served interface lies in its
// Net's prefixes, with a prefix no wider, or is the kernel's IPv6
// link-local one. So no prefix or route the upstream check (dns
// ASSUMPTIONS ENF-f-5) did not see is on a served segment while the
// resolver runs, with or without a ruleset loaded (#4222). An interface
// not there yet is passed: it starts from "default", and the next reading
// sets and checks it. No other interface's own settings are written: the
// WAN, made later, also starts from "default", so its link configuration
// sets its own router advertisements (ASSUMPTIONS ENF-l-21). A kernel
// without IPv6 has no IPv6 settings to turn off.
func hold(root string, nets []dns.Net, addrs func(string) ([]netip.Prefix, error)) error {
	_, err := os.Stat(filepath.Join(root, "ipv6"))
	v6 := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	ifaces := []string{"default"}
	for _, n := range nets {
		if n.Iface == "" || n.Iface == "." || n.Iface == ".." || n.Iface == "all" || n.Iface == "default" || strings.ContainsAny(n.Iface, "/\x00") {
			return unsetErr{page.Unset{Kind: page.UnsetName, Iface: n.Iface}, fmt.Errorf("served interface %q: not an interface name", n.Iface)}
		}
		// Not there yet, it is passed; any other stat error is a there
		// whose settings then fail to set.
		if _, err := os.Stat(filepath.Join(root, "ipv4/conf", n.Iface)); !errors.Is(err, fs.ErrNotExist) {
			ifaces = append(ifaces, n.Iface)
		}
	}
	type setting struct {
		key   string
		cause page.Unset
	}
	keys := []setting{{allRedirects, page.Unset{Kind: page.UnsetSetting, Iface: "all", Setting: page.Redirects4}}}
	for _, iface := range ifaces {
		for _, k := range noRedirects {
			if v6 || !strings.HasPrefix(k.key, "ipv6/") {
				keys = append(keys, setting{fmt.Sprintf(k.key, iface), page.Unset{Kind: page.UnsetSetting, Iface: iface, Setting: k.set}})
			}
		}
	}
	var errs []error
	for _, k := range keys {
		// The value read back must be the one written: a setting that
		// takes the write and reads back anything else fails.
		path := filepath.Join(root, k.key)
		werr := os.WriteFile(path, []byte("0\n"), 0)
		b, rerr := os.ReadFile(path)
		if err := errors.Join(werr, rerr); err != nil || strings.TrimSpace(string(b)) != "0" {
			errs = append(errs, unsetErr{k.cause, fmt.Errorf("%s not set to 0 (reads %q): %v", path, b, err)})
		}
	}
	for _, n := range nets {
		if !slices.Contains(ifaces, n.Iface) {
			continue
		}
		have, err := addrs(n.Iface) // none on an error
		if err != nil {
			// Addresses that changed while read are read again at the
			// next reading; any other failure may last.
			kind := page.UnsetAddrs
			if errors.Is(err, errDumpIntr) || errors.As(err, new(madeAgain)) {
				kind = page.UnsetChanged
			}
			errs = append(errs, unsetErr{page.Unset{Kind: kind, Iface: n.Iface}, fmt.Errorf("served interface %s: addresses: %w", n.Iface, err)})
		}
		for _, p := range have {
			if !inNet(p, n) {
				errs = append(errs, strayAddr{n.Iface, p, netsOf(n)})
			}
		}
	}
	return errors.Join(errs...)
}

// inNet is whether the address p, with its prefix, may be on n's
// interface: inside one of n's prefixes and no wider than it, or the
// kernel's IPv6 link-local address (fe80::/64).
func inNet(p netip.Prefix, n dns.Net) bool {
	a := p.Addr()
	if a.Is6() && a.IsLinkLocalUnicast() {
		return p.Bits() == 64 && linkLocal.Contains(a)
	}
	for _, q := range []netip.Prefix{n.Prefix4, n.Prefix6} {
		if q.IsValid() && q.Contains(a) && p.Bits() >= q.Bits() {
			return true
		}
	}
	return false
}

var linkLocal = netip.MustParsePrefix("fe80::/64")

func netsOf(n dns.Net) string {
	if n.Prefix6.IsValid() {
		return n.Prefix4.String() + " and " + n.Prefix6.String()
	}
	return n.Prefix4.String()
}

// ifaceAddrs is the addresses the kernel holds on iface, each with its
// prefix length, from one dump of every address (RTM_GETADDR).
func ifaceAddrs(iface string) ([]netip.Prefix, error) { return addrsOn(iface, ifaceIndex, addrDump) }

// ifaceIndex is the kernel's number for the interface named name.
func ifaceIndex(name string) (int, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return i.Index, nil
}

// addrsOn is the addresses on the interface named iface in a dump, its
// index looked up before the dump and again after it. An interface made
// again in between has a new index (the kernel numbers each new one past
// the last), and
// fails: its new addresses are not in the dump read for the old index, so
// it is never read as holding none (#5188 item 1).
func addrsOn(iface string, index func(string) (int, error), dump func() ([]byte, error)) ([]netip.Prefix, error) {
	i, err := index(iface)
	if err != nil {
		return nil, err
	}
	out, err := addrsOf(i, dump)
	if err != nil {
		return nil, err
	}
	j, err := index(iface)
	if err != nil {
		return nil, err
	}
	if j != i {
		return nil, madeAgain{iface, i, j}
	}
	return out, nil
}

// madeAgain is an interface made again while its addresses were read:
// its old index, then its new one.
type madeAgain struct {
	iface string
	i, j  int
}

func (m madeAgain) Error() string {
	return fmt.Sprintf("interface %s was made again while its addresses were read (index %d, then %d)", m.iface, m.i, m.j)
}

// addrDump is the kernel's dump of every address, as it sent it.
func addrDump() ([]byte, error) { return syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC) }

// errDumpIntr is an address dump the kernel marked inconsistent
// (NLM_F_DUMP_INTR): the addresses changed while it was read, so one
// could be missing from it.
var errDumpIntr = errors.New("the kernel's address dump was interrupted by a change")

// addrsOf is the addresses on the interface numbered index in a dump. A
// dump marked interrupted is taken once more, and a second one marked so
// fails: an address missing from it is never read as none (#5164
// item 8; offload ENF-gro-3 is the same for links).
func addrsOf(index int, dump func() ([]byte, error)) ([]netip.Prefix, error) {
	out, err := readAddrs(index, dump)
	if errors.Is(err, errDumpIntr) {
		out, err = readAddrs(index, dump)
	}
	return out, err
}

// readAddrs reads one dump: each local and peer address (IFA_LOCAL,
// IFA_ADDRESS) on index, with the message's prefix length. Any message
// that does not parse, an end carrying an error, or no end is an error.
func readAddrs(index int, dump func() ([]byte, error)) ([]netip.Prefix, error) {
	b, err := dump()
	if err != nil {
		return nil, err
	}
	// A dump with a message that does not parse is read as none, so it
	// fails below as one with no end, with the parse's error.
	msgs, perr := syscall.ParseNetlinkMessage(b)
	var out []netip.Prefix
	intr, end := false, false
	for _, m := range msgs {
		intr = intr || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0
		if m.Header.Type == syscall.NLMSG_DONE {
			// The dump's end carries the kernel's error code: one it ended
			// in error is not every address (offload's take, #5103).
			if len(m.Data) < 4 || ne.Uint32(m.Data) != 0 {
				return nil, fmt.Errorf("the kernel's address dump ended in error (%x)", m.Data)
			}
			end = true
		}
		if m.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return nil, errors.New("a short address message")
		}
		if int(ne.Uint32(m.Data[4:8])) != index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			if a.Attr.Type != syscall.IFA_ADDRESS && a.Attr.Type != syscall.IFA_LOCAL {
				continue
			}
			ip, _ := netip.AddrFromSlice(a.Value) // invalid unless 4 or 16 bytes
			p := netip.PrefixFrom(ip, int(m.Data[1]))
			if !p.IsValid() {
				return nil, fmt.Errorf("an unreadable address %x/%d", a.Value, m.Data[1])
			}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	if intr {
		return nil, errDumpIntr
	}
	if !end {
		return nil, errors.Join(errors.New("the kernel's address dump has no end"), perr)
	}
	return out, nil
}

// ne is the kernel's byte order for netlink's integers.
var ne = binary.NativeEndian

// readCaps takes one reading of the byte caps' counters (#4376 wiring
// note): it adds it to the day's counts, trips the core or flags the edge
// for each cap passed, loads the in-kernel drop from the new counts and
// saves the day. A cap passed again at the next reading trips again,
// which a tripped core takes at no cost (cut.Trip).
func (d *Enforcer) readCaps(ctx context.Context) error {
	over, err := d.readCapsLocked(ctx)
	for _, o := range over {
		d.overrun(o)
	}
	return err
}

func (d *Enforcer) readCapsLocked(ctx context.Context) ([]traffic.Overrun, error) {
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	c := d.net.counter
	if c == nil || d.loaded == "" {
		return nil, nil
	}
	lctx, cancel := context.WithTimeout(ctx, d.dp.FireWait)
	defer cancel()
	listing, err := d.dp.Fire.List(lctx, nft.Table)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	over, err := d.addReading(d.loadedDoc, listing)
	if err != nil {
		return nil, err
	}
	p := c.Drop()
	p.Past, p.Read = d.net.past, listing
	d.holdDrop(&p)
	running, err := d.dp.Fire.List(lctx, nft.Table)
	if err != nil {
		return over, fmt.Errorf("drop: %w", err)
	}
	text, err := nft.Drops(d.loadedDoc, d.cfg.Layout, running, p)
	if err != nil {
		return over, fmt.Errorf("drop: %w", err)
	}
	if err := d.dp.Fire.Update(lctx, text); err != nil {
		return over, fmt.Errorf("drop: %w", err)
	}
	return over, nil
}

// addReading adds the reading in listing, the running table compiled
// from doc, to the day's counts and saves the day; d.fwMu is held and the
// counter is not nil. The day is saved before the drop moves: a power cut after it
// loses no counted byte.
func (d *Enforcer) addReading(doc policy.Document, listing []byte) ([]traffic.Overrun, error) {
	r, err := traffic.ReadingOf(doc, d.cfg.Layout, d.net.boot, listing)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	c := d.net.counter
	over := c.Add(r)
	if err := d.store(fileTraffic).Save(c.Save()); err != nil {
		d.dp.Logf("byte caps: day not saved: " + err.Error())
	}
	return over, nil
}

// overrun is one cap passed: the core's cuts the core (KRN-12), the
// edge's cuts the edge (edgecut.go, ENF-l-15).
func (d *Enforcer) overrun(o traffic.Overrun) {
	why := fmt.Sprintf("byte cap passed: %d of %d bytes today", o.Count, o.Cap)
	if len(o.Dests) > 0 {
		why += " to " + strings.Join(o.Dests, ", ")
	} else if o.Box == traffic.BoxCore {
		why = fmt.Sprintf("%d bytes today to an address no listed name resolved to", o.Count)
	}
	switch o.Box {
	case traffic.BoxCore:
		d.cut.Trip(why)
	default:
		d.tripEdge(why)
	}
}

// trafficRead is the channel's traffic read (traffic ASSUMPTIONS
// ENF-i-5): a device's summary from the running table, read against the
// document it was compiled from.
func (d *Enforcer) trafficRead(device string) ([]byte, error) {
	d.fwMu.Lock()
	doc := d.loadedDoc
	d.fwMu.Unlock()
	r := traffic.Reader{
		Policy: func() policy.Document { return doc },
		List: func() ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), d.dp.FireWait)
			defer cancel()
			return d.dp.Fire.List(ctx, nft.Table)
		},
	}
	return r.Read(device)
}

// counts is the channel's byte-cap read: the counts after a reading taken
// at the request (#4174), so they hold every byte the firewall counted
// before it. With the saved day unreadable it is refused.
func (d *Enforcer) counts() (wire.Counts, error) {
	if d.net.counter == nil {
		return wire.Counts{}, errors.New("byte caps: saved day unreadable")
	}
	// The channel asks from its read loop: a cap passed is tripped off it,
	// since a trip raises an alert, which the channel sends.
	over, err := d.readCapsLocked(context.Background())
	if len(over) > 0 {
		go func() {
			for _, o := range over {
				d.overrun(o)
			}
		}()
	}
	if err != nil {
		return wire.Counts{}, err
	}
	return d.net.counter.Counts(), nil
}

// closeNetwork takes a last reading of the byte caps, so a clean stop
// loses none of the day's bytes, and stops the pair relay and the
// resolver's instances.
func (d *Enforcer) closeNetwork() {
	if d.net.counter != nil {
		if err := d.readCaps(context.Background()); err != nil {
			d.dp.Logf("byte caps: at close: " + err.Error())
		}
	}
	d.net.mdnsMu.Lock()
	d.stopMDNSLocked()
	d.net.mdnsMu.Unlock()
	if d.dp.DNS != nil {
		d.dp.DNS.Close()
	}
}
