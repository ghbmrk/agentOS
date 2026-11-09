package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/heads"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The page's view of the daemon's own state (#4750, #4751): the alerts
// and the core's channel sub-key, each as the page's interface
// (page/status.go), so the page links neither alert nor heads
// (ASSUMPTIONS ENF-l-17, ENF-l-18).

// pageAlerts is the alert log as the page shows and clears it.
type pageAlerts struct{ a *alert.Alerts }

func (p pageAlerts) Status() page.Status {
	st := p.a.Status()
	out := page.Status{CoreDown: st.CoreDown, Red: st.Colour == alert.Red}
	for _, r := range st.Open {
		out.Open = append(out.Open, page.Alert{ID: r.ID, Text: r.Text, At: r.At, Count: r.Count, Sent: r.Sent,
			Fixed: r.Kind == alert.ChannelPaused, Revoke: r.Kind == alert.HeadFork})
	}
	return out
}

func (p pageAlerts) Resolve(id uint64) error { return p.a.Resolve(id) }

// pageCore is the pinned core's channel sub-key as the page revokes it.
type pageCore struct{ d *Enforcer }

var errRevokeUnsaved = errors.New("the enforcer refuses the core's key until it restarts, but the revocation was not saved: revoke it again")

func (p pageCore) RevokeMsg(owner key.PublicKey) []byte {
	return key.RootMsg(heads.SubKeyRoot(owner, p.d.core))
}

// Revoke is RevokeCore on the pinned key. A revocation the head store
// keeps in force but could not save says so, so the owner taps again: a
// restart may not keep it. A tap answered done is a whole journal line,
// since the store appends nothing after a fragment it could not cut back
// (heads ENF-h-5).
func (p pageCore) Revoke(sig []byte) error {
	err := p.d.RevokeCore(p.d.core, sig)
	switch {
	case err == nil:
		p.d.revokeUnsaved.Store(false)
		p.d.dp.Logf("core: the owner revoked the core's channel key on the page")
	case p.d.heads.Revoked(p.d.core):
		p.d.revokeUnsaved.Store(true)
		p.d.dp.Logf("core: the owner's revocation is in force but not saved: " + err.Error())
		return errRevokeUnsaved
	}
	return err
}

// Revoked is a revocation the head store saved: one in force but not
// saved is offered again, so the owner's next tap saves it.
func (p pageCore) Revoked() bool { return p.d.heads.Revoked(p.d.core) && !p.d.revokeUnsaved.Load() }

// The byte caps' fresh day (#5013, ASSUMPTIONS ENF-l-19). While the saved
// day does not read back (ENF-l-14), traffic.json is also the one record
// of the owner's fresh day, and each step writes it whole, once:
//
//	the unreadable day, or a cancelled record  --approve-->  {"fresh_day":{"due":T}}
//	{"fresh_day":{"due":T}}                    --cancel--->  {"fresh_day":{}}
//	{"fresh_day":{"due":T}}, T passed          --start---->  a day from zero (traffic.State)
//
// A record is no saved day (traffic.Restore: it has none), so every cap
// stays spent while one is on disk, and an approval lives only inside the
// spent day it was approved for: a day that reads back, written by the
// start or by hand, has none. The run never takes up the start's day in
// place: once its save returns, the daemon stops so the service manager
// starts it again, and openNetwork reads the day as it reads every saved
// one. The page, the run and a restart therefore agree with the disk by
// construction; a step whose save errs stays in force for the run and is
// saved again every second until a save returns nil.

// freshRecord is the fresh day's record in traffic.json.
type freshRecord struct {
	FreshDay *freshStep `json:"fresh_day"`
}

type freshStep struct {
	Due int64 `json:"due,omitempty"` // Unix ms; 0: cancelled
}

func freshBytes(due int64) []byte {
	b, _ := json.Marshal(freshRecord{FreshDay: &freshStep{Due: due}})
	return b
}

// freshDay is the run's side of the fresh day; mu (taken after fwMu)
// holds it.
type freshDay struct {
	mu  sync.Mutex
	due int64 // the approved start, Unix ms; 0: none waits
	// unsaved is the last approval or cancel record while no Save of it
	// has returned nil: in force for the run, saved again every tick.
	unsaved []byte
	// starting: the wait is over, so the start is committed for the run
	// (a cancel is refused) and its day is saved again every tick, every
	// cap spent meanwhile. started: that save returned nil, so the run
	// stops to take it up.
	starting, started bool
	lastErr           string // the last save failure logged, "" after a save
}

var (
	errReadsBack  = errors.New("the byte caps' day reads back")
	errFreshWaits = errors.New("a fresh day is already waiting")
	errNoFreshDay = errors.New("no fresh day is waiting")
	errStarting   = errors.New("the fresh day is starting, so it can no longer be cancelled")
	errFreshDay   = errors.New("byte caps: the fresh day the owner started is saved; the enforcer stops so it starts again on it")
)

// pageCaps is the byte caps' day as the page shows it and the owner's
// fresh start of it.
type pageCaps struct{ d *Enforcer }

func (p pageCaps) Day() page.CapsDay {
	f := &p.d.fresh
	f.mu.Lock()
	defer f.mu.Unlock()
	return page.CapsDay{Spent: p.d.net.spent, DueMS: f.due, Starting: f.starting || f.started,
		Retrying: f.starting, Unsaved: f.unsaved != nil}
}

// Fresh approves a fresh day that starts policy.Wait after nowMS.
func (p pageCaps) Fresh(nowMS int64) (int64, bool, error) {
	f := &p.d.fresh
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case !p.d.net.spent:
		return 0, false, errReadsBack
	case f.starting || f.started:
		return 0, false, errStarting
	case f.due != 0:
		return 0, false, errFreshWaits
	}
	f.due = nowMS + policy.Wait
	p.d.dp.Logf("byte caps: the owner approved a fresh day, which starts at " + time.UnixMilli(f.due).In(p.d.cfg.zone).Format("2006-01-02 15:04 MST"))
	return f.due, p.d.saveFresh(freshBytes(f.due)), nil
}

// CancelFresh cancels a fresh day still waiting. A start under way has
// committed it, so the cancel says it lost.
func (p pageCaps) CancelFresh() (bool, error) {
	f := &p.d.fresh
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.starting || f.started:
		return false, errStarting
	case f.due == 0:
		return false, errNoFreshDay
	}
	f.due = 0
	p.d.dp.Logf("byte caps: the owner cancelled the fresh day")
	return p.d.saveFresh(freshBytes(0)), nil
}

// saveFresh saves an approval or cancel record, the step already in
// force for the run; d.fresh.mu is held. Only a Save that returns nil
// (written, synced, renamed, directory synced) confirms it; any error,
// whatever the file then holds, leaves it to be saved again.
func (d *Enforcer) saveFresh(b []byte) bool {
	f := &d.fresh
	if err := d.store(fileTraffic).Save(b); err != nil {
		f.unsaved = b
		d.freshErr("byte caps: the fresh day's step is in force but not confirmed on disk, saved again every second: " + err.Error())
		return false
	}
	f.unsaved, f.lastErr = nil, ""
	return true
}

// freshErr logs msg when it differs from the last one logged.
func (d *Enforcer) freshErr(msg string) {
	if msg != d.fresh.lastErr {
		d.fresh.lastErr = msg
		d.dp.Logf(msg)
	}
}

// openFresh restores the wait a spent day's record holds; anything else
// beside a spent day (the unreadable bytes, a cancel) starts nothing, and
// a day that reads back restores none, even one that also carries a
// fresh_day key.
func (d *Enforcer) openFresh() {
	if !d.net.spent {
		return // a day that reads back holds no approval, whatever keys it also has
	}
	b, err := d.store(fileTraffic).Load()
	var r freshRecord
	switch {
	case err != nil || json.Unmarshal(b, &r) != nil || r.FreshDay == nil:
		// the unreadable day itself, which no owner has acted on
		// (openNetwork refused a file it cannot read)
	case r.FreshDay.Due > 0:
		d.fresh.due = r.FreshDay.Due
		d.dp.Logf("byte caps: the fresh day the owner approved starts at " + time.UnixMilli(r.FreshDay.Due).In(d.cfg.zone).Format("2006-01-02 15:04 MST"))
	default:
		d.dp.Logf("byte caps: the owner cancelled the fresh day; every cap stays spent until a new one")
	}
}

// tickFresh starts the fresh day once its wait is over, and saves again
// a step not yet confirmed. The start saves a day from zero whose first
// reading is the running table as it is now (freshState), so nothing the
// spent drop dropped counts against it; once that save returns nil the
// daemon stops (errFreshDay) to take it up. It holds fwMu, then
// d.fresh.mu, across the check, the reading, the save and the commit, so
// a cancel either wins before it or is refused.
func (d *Enforcer) tickFresh(ctx context.Context, now time.Time) {
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	f := &d.fresh
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case !f.starting && f.due != 0 && now.UnixMilli() >= f.due:
		f.starting, f.due, f.unsaved = true, 0, nil
		d.dp.Logf("byte caps: the fresh day's wait is over, so it starts")
	case !f.starting:
		if f.unsaved != nil {
			d.saveFresh(f.unsaved)
		}
		return
	}
	b, err := d.freshState(ctx, now)
	if err == nil {
		err = d.store(fileTraffic).Save(b)
	}
	if err != nil {
		d.freshErr("byte caps: the fresh day was not saved, every cap stays spent and the start is tried again every second: " + err.Error())
		return
	}
	f.starting, f.started, f.lastErr = false, true, ""
	d.dp.Logf("byte caps: a fresh day from zero is saved, as the owner approved")
	d.stopForFresh()
}

// freshState is a day from zero whose last reading is the running table
// now: the next reading counts only bytes after it. With no ruleset
// loaded it holds no reading, and the first load's counters are new.
// fwMu is held.
func (d *Enforcer) freshState(ctx context.Context, now time.Time) ([]byte, error) {
	st := traffic.State{Day: traffic.Day(now)}
	if d.loaded != "" {
		lctx, cancel := context.WithTimeout(ctx, d.dp.FireWait)
		defer cancel()
		var r traffic.Reading
		listing, err := d.dp.Fire.List(lctx, nft.Table)
		if err == nil {
			r, err = traffic.ReadingOf(d.loadedDoc, d.cfg.Layout, d.net.boot, listing)
		}
		if err != nil {
			return nil, fmt.Errorf("reading: %w", err)
		}
		st.Gen, st.Seen, st.Last, st.LastEdge = r.Gen, true, r.Core, r.Edge
	}
	b, _ := json.Marshal(st) // every field is a plain value
	return b, nil
}

// stopForFresh asks the daemon's loop to stop. A run starts at most one
// fresh day (Fresh refuses once one started), so the buffered send never
// waits.
func (d *Enforcer) stopForFresh() { d.freshStop <- errFreshDay }

// closeFresh saves once more a step not yet confirmed, at a clean stop.
func (d *Enforcer) closeFresh() {
	f := &d.fresh
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unsaved != nil {
		d.saveFresh(f.unsaved)
	}
}
