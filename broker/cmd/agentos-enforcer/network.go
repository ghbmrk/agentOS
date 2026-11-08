package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/dns"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/enforcer/wol"
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

	edgeMu  sync.Mutex
	edgeDay uint32 // the day the edge's overrun was last logged

	// offloadErr is the last failure to keep the counted ports from
	// merging, logged once while it lasts ("" while they merge nothing).
	offloadErr string

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
	// merges segments counts one IP header for several, so the daemon
	// does not start while the core's or the edge's port merges
	// (ASSUMPTIONS ENF-l-16).
	if err := d.dp.Offload(d.counted()...); err != nil {
		return fmt.Errorf("byte caps: %w", err)
	}
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
		if d.net.counter, err = traffic.Restore(d.dp.Now, caps, b); err != nil {
			if !errors.Is(err, traffic.ErrState) {
				return fmt.Errorf("byte caps: %w", err)
			}
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
func (d *Enforcer) loadNetwork(ctx context.Context, doc policy.Document) error {
	l := d.cfg.Layout
	paths, err := nft.Paths(doc, l)
	if err != nil {
		return err
	}
	ann, err := nft.Announces(doc, l)
	if err != nil {
		return err
	}
	hears, err := nft.Hears(doc, l)
	if err != nil {
		return err
	}
	files, err := dns.Generate(doc, l, d.cfg.DNS)
	if err != nil {
		// A document the resolver cannot serve still loads, so a
		// tightening is never held back; every instance stops, so no
		// list resolves at all until one can be served (ENF-l-11).
		d.dp.Logf("dns: the policy in force cannot be served, every resolver instance stops: " + err.Error())
		files = dns.Files{}
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
			// Tripped off this goroutine: the load holds fwMu, and a trip
			// must never wait on it (cut.Trip takes no firewall lock; an
			// edge cut that does must keep it so).
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
	return p
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
// if it ended, and the byte caps read every readEvery.
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
	d.keepOffloadsOff()
	if err := d.readCaps(ctx); err != nil {
		d.dp.Logf("byte caps: " + err.Error())
	}
}

// counted are the ports whose received bytes the byte caps count: the
// core's and the edge's.
func (d *Enforcer) counted() []string { return []string{d.cfg.Layout.Core, d.cfg.Layout.Edge} }

// keepOffloadsOff turns merging off again on the counted ports before each
// reading, since a port whose device is made again (a VLAN added back)
// starts with its driver's defaults. A failure is logged when it starts
// or changes, and the end of one once.
func (d *Enforcer) keepOffloadsOff() {
	msg := ""
	if err := d.dp.Offload(d.counted()...); err != nil {
		msg = err.Error()
	}
	if msg == d.net.offloadErr {
		return
	}
	if msg != "" {
		d.dp.Logf("byte caps: a counted port merges segments, its bytes count short: " + msg)
	} else {
		d.dp.Logf("byte caps: the counted ports merge no segments again")
	}
	d.net.offloadErr = msg
}

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

// overrun is one cap passed: the core's cuts the core (KRN-12); the
// edge's is held by the in-kernel drop, and raised and logged, since no
// edge cut is built yet (ENF-l-15).
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
		// No edge cut exists yet (#5014), so no alert: its text would
		// name steps the edge does not have, and nothing would clear it
		// (UX 6656586767). The drop holds the edge at its cap; the log
		// says so once a day.
		day := traffic.Day(d.dp.Now())
		d.net.edgeMu.Lock()
		first := d.net.edgeDay != day
		d.net.edgeDay = day
		d.net.edgeMu.Unlock()
		if first {
			d.dp.Logf("byte caps: edge: " + why + "; held at its cap by the drop until the day ends")
		}
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
