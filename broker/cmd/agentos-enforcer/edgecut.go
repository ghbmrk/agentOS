package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
)

// edgeDevice is the name the enforcer's alerts give the edge box.
const edgeDevice = "edge"

// edgeCut is the edge's cut (#5014, ASSUMPTIONS ENF-l-15): the edge past
// its daily byte cap reaches nothing through the enforcer, on any path,
// until the owner lifts the cut on the page with the passkey. The record
// is edgecut.json; the firewall's half is the drop's cut chain
// (nft.Drop.EdgeCut), which every drop the daemon writes carries from
// this record, so a restart's first load is already cut. It takes only
// its own lock and never the firewall's.
type edgeCut struct {
	store  fileStore
	alerts *alert.Alerts
	logf   func(string)

	mu sync.Mutex
	st edgeCutState
	// unsaved: a trip decided here whose write failed. Persist retries it
	// each tick and at Close; the cut is in force meanwhile.
	unsaved bool
}

type edgeCutState struct {
	Cut    bool   `json:"cut"`
	Reason string `json:"reason,omitempty"`
	// Day is the enforcer day (traffic.Day) of the overrun that cut.
	Day uint32 `json:"day,omitempty"`
	// Lifted is that day when the owner lifted the cut on it. The rest of
	// that day's overrun does not cut again: the edge stays past its cap
	// all day, and the drop holds its internet bytes there, so a lift
	// would otherwise last only until the next reading. A lift on a later
	// day leaves it 0: the new day's count starts from nothing, and its
	// overrun cuts.
	Lifted uint32 `json:"lifted,omitempty"`
}

// openEdgeCut reads the record. One that does not read back is a cut:
// the edge stays cut, the log says why, and the owner's lift writes the
// record whole again (fails closed, P5).
func openEdgeCut(store fileStore, alerts *alert.Alerts, logf func(string)) (*edgeCut, error) {
	c := &edgeCut{store: store, alerts: alerts, logf: logf}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &c.st); err != nil {
			c.st = edgeCutState{Cut: true, Reason: "the record of the edge's cut does not read back"}
			logf("edge cut: " + fileEdgeCut + " unreadable, the edge stays cut until you lift it on the page: " + err.Error())
		}
	}
	return c, nil
}

// Cut reports whether the edge is cut, and why.
func (c *edgeCut) Cut() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Cut, c.st.Reason
}

// Trip cuts the edge for an overrun on day and reports whether it was
// not cut before. An edge already cut, or lifted on day, costs nothing.
// The cut is in force before the write; a failed write leaves it unsaved
// and Persist retries it. The trip alert is raised outside the lock.
func (c *edgeCut) Trip(day uint32, reason string) bool {
	c.mu.Lock()
	if c.st.Cut || (c.st.Lifted != 0 && c.st.Lifted == day) {
		c.mu.Unlock()
		return false
	}
	c.st = edgeCutState{Cut: true, Reason: reason, Day: day}
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		c.logf("edge cut: trip not saved, retried each tick; the edge is cut meanwhile: " + err.Error())
	}
	if _, err := c.alerts.Raise(alert.Trip, edgeDevice); err != nil {
		c.logf("edge cut: trip alert: " + err.Error())
	}
	return true
}

func (c *edgeCut) saveLocked() error {
	b, _ := json.Marshal(c.st)
	err := c.store.Save(b)
	c.unsaved = err != nil
	return err
}

// Persist retries an unsaved trip's write.
func (c *edgeCut) Persist() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.unsaved {
		return nil
	}
	if err := c.saveLocked(); err != nil {
		return err
	}
	c.logf("edge cut: trip saved")
	return nil
}

// Lift lifts the cut on day. The page calls it only after the owner's
// passkey assertion on the page's own lift challenge; nothing on the
// channel reaches it. A lift that is not saved does not happen.
func (c *edgeCut) Lift(day uint32) error {
	c.mu.Lock()
	if !c.st.Cut {
		c.mu.Unlock()
		return nil
	}
	next := edgeCutState{}
	if c.st.Day == day {
		next.Lifted = day
	}
	b, _ := json.Marshal(next)
	if err := c.store.Save(b); err != nil {
		c.mu.Unlock()
		return err
	}
	c.st, c.unsaved = next, false
	c.mu.Unlock()
	return c.alerts.Lifted(edgeDevice)
}

// tripEdge cuts the edge for an overrun and puts the cut in force at once.
func (d *Enforcer) tripEdge(why string) {
	if d.edge.Trip(traffic.Day(d.dp.Now()), why) {
		d.dp.Logf("byte caps: edge: " + why + "; the edge is cut until you lift it on the enforcer's page")
		d.loadCut()
	}
}

// pageEdge is the edge's cut as the page shows and lifts it (page.Edge).
type pageEdge struct{ d *Enforcer }

func (p pageEdge) Cut() (bool, string) { return p.d.edge.Cut() }

// LiftEdge is the page's lift, after the owner's tap: the record first,
// then the firewall.
func (p pageEdge) LiftEdge() error {
	d := p.d
	if err := d.edge.Lift(traffic.Day(d.dp.Now())); err != nil {
		return err
	}
	d.loadCut()
	return nil
}

// holdDrop holds in p what the counts do not say: the caps of a port that
// merges segments spent (ENF-l-16), and the edge's cut as recorded.
// d.fwMu is held.
func (d *Enforcer) holdDrop(p *nft.Drop) {
	d.spendMerging(p)
	p.EdgeCut, _ = d.edge.Cut()
}

// loadCut writes the drop again with the edge's cut as recorded now, so a
// trip or a lift is in force at once rather than at the next reading. A
// write that fails asks for a full load at the next tick, which carries
// the cut in the same transaction (syncFirewall). Before the first load
// it does nothing: that load carries it.
func (d *Enforcer) loadCut() {
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	if d.loaded == "" {
		return
	}
	if err := d.loadCutLocked(); err != nil {
		d.net.reload = true
		d.dp.Logf("edge cut: firewall not updated, a full load follows at the next tick: " + err.Error())
	}
}

func (d *Enforcer) loadCutLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), d.dp.FireWait)
	defer cancel()
	running, err := d.dp.Fire.List(ctx, nft.Table)
	if err != nil {
		return err
	}
	text, err := nft.Drops(d.loadedDoc, d.cfg.Layout, running, d.drop(traffic.CapsOf(d.loadedDoc)))
	if err != nil {
		return fmt.Errorf("drop: %w", err)
	}
	return d.dp.Fire.Update(ctx, text)
}
