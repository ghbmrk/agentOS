package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/heads"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The page's view of the daemon's own state (#4750, #4751, #5013): the
// alerts, the core's channel sub-key and an unreadable byte-cap day, each
// as the page's interface (page/status.go), so the page links none of
// alert, heads or traffic (ASSUMPTIONS ENF-l-17 to ENF-l-19).

// fileFresh holds when a fresh byte-cap day the owner approved starts:
// {"due": ms}, or {} with none waiting.
const fileFresh = "fresh-day.json"

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
// keeps in force but could not save says so, so the owner taps again.
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

// pageCaps is the byte caps' day as the page shows it when it did not
// read back (ENF-l-14), and the owner's fresh start of it.
type pageCaps struct{ d *Enforcer }

type freshState struct {
	Due int64 `json:"due,omitempty"`
	// Day is the SHA-256 (hex) of the unreadable traffic.json the owner
	// approved a fresh day for: the approval holds for that day alone.
	Day string `json:"day,omitempty"`
}

var (
	errFreshUnsaved  = errors.New("the fresh day was not saved, so nothing is waiting: try again")
	errCancelUnsaved = errors.New("the cancel was not saved, so the fresh day still waits: cancel it again")
	errReadsBack     = errors.New("the byte caps' day reads back")
	errNoFreshDay    = errors.New("no fresh day is waiting")
)

func (p pageCaps) Spent() (bool, int64) {
	n := &p.d.net
	n.freshMu.Lock()
	defer n.freshMu.Unlock()
	return n.spent, n.freshDue
}

// Fresh starts the day afresh after policy.Wait from nowMS: saved, bound
// to the unreadable day it is for, before it waits, so a restart keeps
// the wait it had.
func (p pageCaps) Fresh(nowMS int64) (int64, error) {
	n := &p.d.net
	n.freshMu.Lock()
	defer n.freshMu.Unlock()
	if !n.spent {
		return 0, errReadsBack
	}
	due := nowMS + policy.Wait
	b, _ := json.Marshal(freshState{Due: due, Day: n.spentDay})
	if err := p.d.save(fileFresh, b); err != nil {
		p.d.dp.Logf("byte caps: fresh day not saved: " + err.Error())
		return 0, errFreshUnsaved
	}
	n.freshDue = due
	p.d.dp.Logf("byte caps: the owner approved a fresh day, which starts at " + time.UnixMilli(due).In(p.d.cfg.zone).Format("2006-01-02 15:04 MST"))
	return due, nil
}

// CancelFresh cancels a fresh day still waiting, checked under the lock
// tickFresh starts it under, so a cancel that lost to the start says so;
// one not saved still waits.
func (p pageCaps) CancelFresh() error {
	n := &p.d.net
	n.freshMu.Lock()
	defer n.freshMu.Unlock()
	if !n.spent || n.freshDue == 0 {
		return errNoFreshDay
	}
	b, _ := json.Marshal(freshState{})
	if err := p.d.save(fileFresh, b); err != nil {
		p.d.dp.Logf("byte caps: fresh day's cancel not saved: " + err.Error())
		return errCancelUnsaved
	}
	n.freshDue = 0
	p.d.dp.Logf("byte caps: the owner cancelled the fresh day")
	return nil
}

// save saves b to the state file name, and the file decides: a Save that
// fails once the new file is in place (its directory sync) still put b
// there, so it counts as saved, and every step here acts on what the
// file holds, never on the error alone (Security on #5101). A Save
// that fails before that changed nothing.
func (d *Enforcer) save(name string, b []byte) error {
	err := d.store(name).Save(b)
	if err == nil {
		return nil
	}
	if got, lerr := d.store(name).Load(); lerr == nil && bytes.Equal(got, b) {
		d.dp.Logf("byte caps: " + name + " saved, but not confirmed on disk: " + err.Error())
		return nil
	}
	return err
}

// openFresh restores a fresh day waiting only for the unreadable day it
// was approved for (freshState.Day). Beside a day that reads back, a
// fresh-day file, readable or not, is erased, and the daemon does not
// start while that erase is unsaved. Beside a spent day, one that does not
// read back, is for another day, or cannot be read, starts nothing and
// does not stop the start.
func (d *Enforcer) openFresh() error {
	b, err := d.store(fileFresh).Load()
	var st freshState
	switch {
	case err != nil && d.net.spent:
		d.dp.Logf("byte caps: " + fileFresh + " unreadable, no fresh day waits: " + err.Error())
	case err == nil && (b == nil || !d.net.spent && string(b) == "{}"):
	case !d.net.spent: // read or not, nothing may outlive the day it was for
		if err := d.save(fileFresh, []byte("{}")); err != nil {
			return fmt.Errorf("byte caps: a stale %s is not erased: %w", fileFresh, err)
		}
		d.dp.Logf("byte caps: erased a stale " + fileFresh + " beside a day that reads back")
	case json.Unmarshal(b, &st) != nil || st.Due < 0:
		d.dp.Logf("byte caps: " + fileFresh + " unreadable, no fresh day waits")
	case st.Due != 0 && st.Day != d.net.spentDay:
		d.dp.Logf("byte caps: " + fileFresh + " was approved for another unreadable day, no fresh day waits")
	default:
		d.net.freshDue = st.Due
	}
	return nil
}

// tickFresh starts the fresh day once its wait is over: the approval
// erased, then a new day from zero for the ruleset in force saved, both
// before it counts; the reading that
// follows in the same tick counts the running table's bytes and moves the
// drop to it. A day not saved is tried again at the next tick. It runs on
// Tick's goroutine, as tickNetwork does.
func (d *Enforcer) tickFresh(now time.Time) {
	n := &d.net
	n.freshMu.Lock()
	due := n.freshDue
	n.freshMu.Unlock()
	if due == 0 || now.UnixMilli() < due {
		return
	}
	d.fwMu.Lock()
	defer d.fwMu.Unlock()
	// The check, both saves and the start under freshMu (after fwMu), so
	// a cancel either wins before or answers that nothing is waiting.
	n.freshMu.Lock()
	defer n.freshMu.Unlock()
	if n.freshDue != due {
		return // cancelled meanwhile
	}
	// The approval is spent before the new day is saved: a day not
	// saved then leaves no approval on disk, so a restart in between
	// needs a new tap, and a cancel meanwhile stops the retry.
	if err := d.save(fileFresh, []byte("{}")); err != nil {
		d.dp.Logf("byte caps: " + fileFresh + " not cleared, the fresh day tried again at the next tick: " + err.Error())
		return
	}
	c := traffic.NewCounter(d.dp.Now, traffic.CapsOf(d.loadedDoc))
	if err := d.save(fileTraffic, c.Save()); err != nil {
		d.dp.Logf("byte caps: the fresh day was not saved, tried again at the next tick: " + err.Error())
		return
	}
	n.counter, n.spent, n.freshDue = c, false, 0
	d.dp.Logf("byte caps: a fresh day started, as the owner approved")
	n.lastRead = time.Time{} // tickNetwork, next in this tick, reads at once
}
