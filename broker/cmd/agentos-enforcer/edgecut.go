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

// tamperAdvice ends the reason of a cut whose record is missing or does
// not read back: the fault is in the enforcer's state, not the edge.
const tamperAdvice = ". Someone may have tampered with the enforcer: check it before you lift the cut."

// trustAdvice ends the reason of a cut the edge's own bytes caused.
const trustAdvice = ". Lift the cut once you trust the edge again."

// openEdgeCut reads the record. One that is missing or does not read back
// is a cut: provisioning wrote it (provisionState) and nothing removes it,
// so its loss means root on the enforcer or lost state (#5399). The edge
// stays cut, the log says why, the alert for a missing record turns the
// light red, and the owner's lift writes the record whole again and
// resolves the alert (fails closed, P5). Such a cut carries no day.
func openEdgeCut(store fileStore, alerts *alert.Alerts, logf func(string)) (*edgeCut, error) {
	c := &edgeCut{store: store, alerts: alerts, logf: logf}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		c.st = edgeCutState{Cut: true, Reason: "the record of the edge's cut is missing" + tamperAdvice}
		logf("edge cut: " + fileEdgeCut + " missing, the edge stays cut until you lift it on the page")
		recordMissing(alerts, edgeDevice, logf)
	} else if err := json.Unmarshal(b, &c.st); err != nil {
		c.st = edgeCutState{Cut: true, Reason: "the record of the edge's cut does not read back" + tamperAdvice}
		logf("edge cut: " + fileEdgeCut + " unreadable, the edge stays cut until you lift it on the page: " + err.Error())
		recordMissing(alerts, edgeDevice, logf)
	}
	return c, nil
}

// Cut reports whether the edge is cut, and why.
func (c *edgeCut) Cut() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Cut, c.st.Reason
}

// held reports whether the edge is cut, and whether the owner lifted a cut
// on day, which holds for the rest of it.
func (c *edgeCut) held(day uint32) (cut, lifted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Cut, c.st.Lifted != 0 && c.st.Lifted == day
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
// channel reaches it. A lift that is not saved does not happen. A lift of
// a cut on its overrun's day, or of one with no day (a record missing or
// unreadable, whose overrun day is unknown), holds for the rest of day,
// so an edge already past its cap is not cut again at the next reading
// (#5399 item 4).
func (c *edgeCut) Lift(day uint32) error {
	c.mu.Lock()
	if !c.st.Cut {
		c.mu.Unlock()
		return nil
	}
	next := edgeCutState{}
	if c.st.Day == day || c.st.Day == 0 {
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

// tripEdge cuts the edge for why, a cause of its own bytes, and puts the
// cut in force at once.
func (d *Enforcer) tripEdge(why string) {
	if d.edge.Trip(traffic.Day(d.dp.Now()), why+trustAdvice) {
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
	err := d.edge.Lift(traffic.Day(d.dp.Now()))
	if cut, _ := d.edge.Cut(); !cut {
		d.loadCut() // lifted, though resolving its trips may have failed
	}
	return err
}

// holdDrop holds in p what the counts do not say: the caps of a port that
// merges segments spent (ENF-l-16), and the edge's cut as recorded. The
// kernel cuts the edge at the first byte past its cap (nft.TripSet) unless
// the edge is held: while its quota is not its count (the edge's port
// merged segments since the last full load the firewall took, or the day
// is unreadable and every cap spent, ENF-l-14), so an edge within its cap
// is never cut, and on the day the owner lifted its cut. The hold for a
// merge lasts until a full load starts the quota and TripSet afresh:
// a refused one leaves the spent quota running, which would fill the set
// (#5399 item 5). d.fwMu is held.
func (d *Enforcer) holdDrop(p *nft.Drop) {
	d.spendMerging(p)
	cut, lifted := d.edge.held(p.Day)
	p.EdgeCut, p.EdgeHold = cut, lifted || d.net.edgeMerged || d.net.counter == nil
}

// loadCut writes the drop again with the edge's cut as recorded now, so a
// trip or a lift is in force at once rather than at the next reading. The
// kernel already cut an edge whose quota stopped a byte (nft.TripSet), so
// a write that fails after a trip leaves the edge cut; it asks for a full
// load at the next tick, which carries the cut in the same transaction
// (syncFirewall), and a refused load shows on the page. Before the first
// load it does nothing: that load carries it.
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
