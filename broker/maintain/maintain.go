// Package maintain is Loop 3, the maintenance loop (SPEC §11A, LOOP-11): in
// spare time it checks the box's update mirrors for a newer AgentOS
// release and sends what it finds through the one change pipeline (§11).
//
// Loop 3 is a loops.Source for the shared scheduler, so it runs only in
// spare capacity, yields to foreground work, and makes no model calls.
// Each check reads TUF metadata through update.Store.Check (UPD-8): a
// release reaches the pipeline only as the update.Verified value that
// package builds, so nothing here can vouch for a release.
//
// Security fixes come first: one waiting for its independent attestation
// (UPD-8, Mark's D6) is looked at again within the hour, skips the soak
// that ordinary stable releases wait out (UPD-5), and counts for more in
// the scheduler's measured return (LOOP-3). A pinned box (UPD-4) installs
// nothing automatically but is still told of security fixes.
//
// The box never says it is up to date unless an online check succeeded
// recently and found nothing newer: offline, an unreachable or frozen
// mirror, a stale check, or a drive install not yet checked online all
// read as "not checked" (LOOP-11, UPD-8).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package maintain

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/update"
)

// ChannelPinned is UPD-4's pinned channel: no automatic updates, security
// notices only. Stable and fast are update.ChannelStable and ChannelFast.
const ChannelPinned = "pinned"

// Proposer is the part of the change pipeline Loop 3 uses.
type Proposer interface {
	ProposeRelease(ctx context.Context, v update.Verified) (change.Report, error)
}

// Config configures New.
type Config struct {
	// Store is the box's update state (trusted root, installed release).
	Store *update.Store
	// Mirrors are the owner's configured mirrors, tried in order until one
	// passes every check. Nil or empty: no mirror, which reads as offline.
	Mirrors func() []update.Source
	// Online reports network access. No mirror is contacted while it is
	// false, and the box is never reported current. Nil: always online.
	Online func() bool
	// Channel is the owner's update channel: update.ChannelStable (the
	// default), update.ChannelFast, or ChannelPinned (UPD-4).
	Channel func() string
	// Attestations fetches attestations for a release manifest path (for
	// example releases/12.json). They arrive from anyone and are checked
	// by update. Nil: none are known.
	Attestations func(ctx context.Context, release string) ([][]byte, error)
	// OwnKey is this box's attestation key, which never counts as
	// independent. Nil: none.
	OwnKey ed25519.PublicKey
	// Pipeline is the change pipeline (§11).
	Pipeline Proposer
	// State persists Loop 3's own state.
	State change.Store
	// MinThreshold is passed to update.Options (default 2 there).
	MinThreshold int
	// Interval is how often to check (UPD-5: daily). Default 24 hours.
	Interval time.Duration
	// Retry is how soon to look again after a failed check, or for a
	// security fix waiting for its attestation. Default 1 hour.
	Retry time.Duration
	// Soak is how long a stable box waits after first seeing an ordinary
	// stable release before proposing it (UPD-5). Default 7 days.
	Soak time.Duration
	// MinPasses is how many independent passing fast-channel attestations
	// an ordinary stable release needs (UPD-5's "sufficient"). Default 1.
	MinPasses int
	Now       func() time.Time
}

// Values a check reports to the scheduler (LOOP-3): a qualified update is
// Loop 3's product, and a security fix counts double.
const (
	valueRelease  = 1.0
	valueSecurity = 2.0
)

// Why a found release has not been proposed yet.
const (
	waitAttestation = "attestation"
	waitSoak        = "soak"
	waitPinned      = "pinned"
	waitPropose     = "propose"
)

// Failure kinds of a check, for the owner's line.
const (
	failExpired   = "expired"
	failSigned    = "signatures"
	failRollback  = "rollback"
	failReach     = "unreachable"
	failNoMirrors = "no-mirrors"
	failState     = "state"
)

type pending struct {
	Version  int64     `json:"version"`
	Security bool      `json:"security,omitempty"`
	Why      string    `json:"why"`
	Until    time.Time `json:"until,omitempty"`
}

// state is what Loop 3 persists.
type state struct {
	// LastOnline is the last check that passed every update check.
	LastOnline  time.Time `json:"last_online,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	// Next is when the next check is due.
	Next time.Time `json:"next,omitempty"`
	// Failure is why the last attempt failed; empty when it passed.
	Failure      string    `json:"failure,omitempty"`
	OfflineSince time.Time `json:"offline_since,omitempty"`
	// Newest is the newest release above the installed one the last good
	// check found on the box's channel, or 0.
	Newest   int64                  `json:"newest,omitempty"`
	Pending  *pending               `json:"pending,omitempty"`
	Seen     map[int64]time.Time    `json:"seen,omitempty"`
	Proposed map[int64]change.State `json:"proposed,omitempty"`
	// Confirmed: an online check cleared a drive install's pending
	// freshness check; the digest says so once.
	Confirmed bool `json:"confirmed,omitempty"`
}

// Loop3 is the maintenance loop's scheduler source.
type Loop3 struct {
	cfg Config

	mu sync.Mutex
	st state
}

var (
	_ loops.Source   = (*Loop3)(nil)
	_ loops.Digester = (*Loop3)(nil)
)

// New loads Loop 3's state. Proposals the pipeline was holding for the
// owner are forgotten across a restart (change C9), so Loop 3 proposes
// them again at its next check.
func New(cfg Config) (*Loop3, error) {
	if cfg.Store == nil || cfg.Pipeline == nil || cfg.State == nil {
		return nil, errors.New("maintain: Store, Pipeline and State are required")
	}
	if cfg.Mirrors == nil {
		cfg.Mirrors = func() []update.Source { return nil }
	}
	if cfg.Online == nil {
		cfg.Online = func() bool { return true }
	}
	if cfg.Channel == nil {
		cfg.Channel = func() string { return update.ChannelStable }
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.Retry <= 0 {
		cfg.Retry = time.Hour
	}
	if cfg.Soak <= 0 {
		cfg.Soak = 7 * 24 * time.Hour
	}
	if cfg.MinPasses <= 0 {
		cfg.MinPasses = 1
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &Loop3{cfg: cfg}
	b, err := cfg.State.Load()
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &l.st); err != nil {
			return nil, fmt.Errorf("maintain: saved state: %v", err)
		}
	}
	for v, s := range l.st.Proposed {
		if s == change.StateAwaitingOwner {
			delete(l.st.Proposed, v)
			l.st.Next = time.Time{}
		}
	}
	return l, nil
}

// Loop is loops.Maintain.
func (l *Loop3) Loop() loops.Loop { return loops.Maintain }

// Next offers a check when one is due: daily, within the hour after a
// failed check or for a security fix waiting for its attestation, and at
// once when the box comes back online. Nothing is offered while offline.
// Checks make no model calls, so modelOK does not matter.
func (l *Loop3) Next(_ context.Context, _ bool) (loops.Job, bool) {
	online := l.cfg.Online()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	if !online {
		if l.st.OfflineSince.IsZero() {
			l.st.OfflineSince = now
			l.saveLocked()
		}
		return loops.Job{}, false
	}
	if !l.st.OfflineSince.IsZero() {
		l.st.OfflineSince, l.st.Next = time.Time{}, time.Time{}
		l.saveLocked()
	}
	if !l.st.LastAttempt.IsZero() && now.Before(l.st.Next) {
		return loops.Job{}, false
	}
	return loops.Job{Name: "update-check", Run: l.check}, true
}

func (l *Loop3) saveLocked() error {
	b, err := json.Marshal(l.st)
	if err != nil {
		return err
	}
	return l.cfg.State.Save(b)
}

// check is one unit of Loop 3's work: check the mirrors and decide what to
// do with the newest release found. Network reads and the pipeline run
// without the lock, so Status and Digest answer at once meanwhile.
func (l *Loop3) check(ctx context.Context) loops.Result {
	if err := ctx.Err(); err != nil {
		return loops.Result{Err: err}
	}
	channel := l.cfg.Channel()
	opts := update.Options{Channel: channel, MinThreshold: l.cfg.MinThreshold, Now: l.cfg.Now}
	if channel == ChannelPinned {
		// Checked as stable, for security notices only (UPD-4).
		opts.Channel = update.ChannelStable
	}
	res, failure, err := l.checkMirrors(opts)
	if cerr := ctx.Err(); cerr != nil {
		// Preempted: nothing is recorded, and the check is offered again.
		return loops.Result{Err: cerr}
	}
	installed, ierr := l.cfg.Store.Installed()
	if ierr != nil {
		failure, err = failState, ierr
	}
	now := l.cfg.Now()

	l.mu.Lock()
	l.st.LastAttempt = now
	if failure != "" {
		l.st.Failure = failure
		l.st.Next = now.Add(l.cfg.Retry)
		l.saveLocked()
		l.mu.Unlock()
		return loops.Result{Err: err}
	}
	l.st.LastOnline, l.st.Failure = now, ""
	if res.FreshnessConfirmed {
		l.st.Confirmed = true
	}
	for v := range l.st.Seen {
		if v <= installed.Version {
			delete(l.st.Seen, v)
		}
	}
	for v := range l.st.Proposed {
		if v <= installed.Version {
			delete(l.st.Proposed, v)
		}
	}
	l.st.Newest, l.st.Pending = 0, nil
	l.st.Next = now.Add(l.cfg.Interval)
	if res.Release == nil {
		l.saveLocked()
		l.mu.Unlock()
		return loops.Result{}
	}
	rel := res.Release
	m, err := rel.Manifest()
	if err != nil {
		l.saveLocked()
		l.mu.Unlock()
		return loops.Result{Err: err}
	}
	v := m.Version
	l.st.Newest = v
	if l.st.Seen == nil {
		l.st.Seen = map[int64]time.Time{}
	}
	if _, ok := l.st.Seen[v]; !ok {
		l.st.Seen[v] = now
	}
	seen := l.st.Seen[v]
	_, proposed := l.st.Proposed[v]
	if channel == ChannelPinned {
		l.st.Pending = &pending{Version: v, Security: m.Security, Why: waitPinned}
	}
	l.saveLocked()
	l.mu.Unlock()
	if channel == ChannelPinned || proposed {
		// Pinned: a notice only. Proposed: the pipeline has it, or
		// rejected it.
		return loops.Result{}
	}

	o := l.decide(ctx, rel, m, channel, seen, now)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.st.Newest != v {
		return loops.Result{Value: o.value, Err: o.err} // superseded meanwhile
	}
	switch {
	case o.proposed != "":
		if l.st.Proposed == nil {
			l.st.Proposed = map[int64]change.State{}
		}
		l.st.Proposed[v] = o.proposed
	case o.wait == nil:
		// Preempted before proposing: offered again.
		l.st.Next = time.Time{}
	default:
		l.st.Pending = o.wait
		switch o.wait.Why {
		case waitAttestation, waitPropose:
			// Security first: look again within the hour.
			l.st.Next = now.Add(l.cfg.Retry)
		case waitSoak:
			if o.wait.Until.After(now) && o.wait.Until.Before(l.st.Next) {
				l.st.Next = o.wait.Until
			}
		}
	}
	l.saveLocked()
	return loops.Result{Value: o.value, Err: o.err}
}

// checkMirrors tries each mirror in turn and returns the first full pass.
// When all fail it reports the most telling failure: a mirror serving
// expired, badly signed or rolled-back metadata matters more than one that
// could not be reached.
func (l *Loop3) checkMirrors(opts update.Options) (update.Result, string, error) {
	mirrors := l.cfg.Mirrors()
	if len(mirrors) == 0 {
		return update.Result{}, failNoMirrors, errors.New("maintain: no update mirror configured")
	}
	failure, rank := "", -1
	var last error
	for _, m := range mirrors {
		res, err := l.cfg.Store.Check(m, opts)
		if err == nil {
			return res, "", nil
		}
		kind, r := classify(err)
		if r > rank {
			failure, rank, last = kind, r, err
		}
	}
	return update.Result{}, failure, last
}

func classify(err error) (string, int) {
	switch {
	case errors.Is(err, update.ErrSignatures), errors.Is(err, update.ErrWeakThreshold):
		return failSigned, 3
	case errors.Is(err, update.ErrRollback):
		return failRollback, 3
	case errors.Is(err, update.ErrExpired):
		return failExpired, 2
	}
	return failReach, 1
}

// outcome is what decide did with a release: proposed it (proposed is the
// pipeline's state), is waiting (wait), or was preempted (neither).
type outcome struct {
	proposed change.State
	wait     *pending
	value    float64
	err      error
}

// decide applies UPD-8 and UPD-5 to a verified release newer than the
// installed one and proposes it when they allow.
func (l *Loop3) decide(ctx context.Context, rel *update.Checked, m update.Manifest, channel string, seen, now time.Time) outcome {
	mf, err := rel.ManifestFile()
	if err != nil {
		return outcome{wait: &pending{Version: m.Version, Security: m.Security, Why: waitPropose}, err: err}
	}
	atts, aerr := l.attestations(ctx, mf.Path)
	if m.Security {
		// UPD-8, D6: a security fix waits for one independent attestation.
		if err := rel.SecurityAutoStage(atts, l.cfg.OwnKey); err != nil {
			return outcome{wait: &pending{Version: m.Version, Security: true, Why: waitAttestation}, err: aerr}
		}
	} else if channel != update.ChannelFast {
		// UPD-5: an ordinary stable release soaks, and needs independent
		// passing attestations, before it is offered.
		until := seen.Add(l.cfg.Soak)
		if now.Before(until) || rel.IndependentPasses(atts, l.cfg.OwnKey) < l.cfg.MinPasses {
			return outcome{wait: &pending{Version: m.Version, Why: waitSoak, Until: until}, err: aerr}
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome{err: err}
	}
	rep, err := l.cfg.Pipeline.ProposeRelease(ctx, rel.Verified(atts, l.cfg.OwnKey))
	if err != nil {
		if ctx.Err() != nil {
			return outcome{err: err}
		}
		return outcome{wait: &pending{Version: m.Version, Security: m.Security, Why: waitPropose}, err: err}
	}
	o := outcome{proposed: rep.State}
	switch {
	case rep.State == change.StateRejected:
	case m.Security:
		o.value = valueSecurity
	default:
		o.value = valueRelease
	}
	return o
}

func (l *Loop3) attestations(ctx context.Context, release string) ([][]byte, error) {
	if l.cfg.Attestations == nil {
		return nil, nil
	}
	return l.cfg.Attestations(ctx, release)
}

// Status is what the box says about updates when asked (STATUS, the local
// page).
type Status struct {
	// Current is true only when an online check passed within twice the
	// check interval, found nothing newer on the box's channel, and the
	// box is online now (LOOP-11).
	Current bool
	// Line is one plain sentence for the owner.
	Line string
}

const when = "Mon 2 Jan 15:04"

var failText = map[string]string{
	failExpired:   "the update server's data has expired, so it may be hiding newer updates",
	failSigned:    "the update data was not properly signed",
	failRollback:  "the update server offered older data than this box already has",
	failReach:     "the update server could not be reached",
	failNoMirrors: "no update server is set up",
	failState:     "this box's update record could not be read",
}

// Status reports whether the box is up to date, and says why not.
func (l *Loop3) Status() Status {
	online := l.cfg.Online()
	installed, ierr := l.cfg.Store.Installed()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.statusLocked(online, installed, ierr)
}

func (l *Loop3) statusLocked(online bool, in update.Installed, ierr error) Status {
	now := l.cfg.Now()
	st := l.st
	last := "never"
	if !st.LastOnline.IsZero() {
		last = st.LastOnline.Format(when)
	}
	drive := ""
	if in.UnconfirmedFreshness {
		drive = " The last update was installed from a drive and has not been checked online yet."
	}
	switch {
	case ierr != nil:
		return Status{Line: "Updates: could not read this box's update state."}
	case !online && st.LastOnline.IsZero():
		return Status{Line: "Updates: not checked yet, because the box is offline." + drive}
	case !online:
		return Status{Line: fmt.Sprintf("Updates: not checked since %s, because the box is offline.", last) + drive}
	case st.Failure != "":
		return Status{Line: fmt.Sprintf("Updates: could not check: %s. Last good check: %s.", failText[st.Failure], last) + drive}
	case st.LastOnline.IsZero():
		return Status{Line: "Updates: not checked yet." + drive}
	case in.UnconfirmedFreshness:
		return Status{Line: "Updates: the last update was installed from a drive and has not been checked online yet."}
	case now.Sub(st.LastOnline) > 2*l.cfg.Interval:
		return Status{Line: fmt.Sprintf("Updates: last checked %s.", last)}
	}
	if p := st.Pending; p != nil {
		return Status{Line: pendingLine(p)}
	}
	if st.Newest > in.Version {
		switch st.Proposed[st.Newest] {
		case change.StateRejected:
			return Status{Line: fmt.Sprintf("Update %d did worse on this box's tests and was not installed.", st.Newest)}
		case change.StateAdopted:
			return Status{Line: fmt.Sprintf("Update %d is ready and installs at the next quiet time.", st.Newest)}
		}
		return Status{Line: fmt.Sprintf("Update %d is waiting for your approval.", st.Newest)}
	}
	return Status{Current: true, Line: fmt.Sprintf("Updates: up to date (checked %s).", last)}
}

func pendingLine(p *pending) string {
	switch {
	case p.Why == waitPinned && p.Security:
		return fmt.Sprintf("Security update %d is out, but this box is pinned, so it will not install it on its own.", p.Version)
	case p.Why == waitPinned:
		return "Updates: this box is pinned, so it does not install updates on its own."
	case p.Why == waitAttestation:
		return fmt.Sprintf("Security update %d is waiting for an independent test report before it installs.", p.Version)
	case p.Why == waitSoak:
		return fmt.Sprintf("Update %d is out. The box will offer it after %s, once other boxes have tested it.", p.Version, p.Until.Format("Mon 2 Jan"))
	case p.Security:
		return fmt.Sprintf("Security update %d was found but could not be tested yet. The box will try again within the hour.", p.Version)
	}
	return fmt.Sprintf("Update %d was found but could not be tested yet.", p.Version)
}

// Digest is Loop 3's lines for the owner's digest: the update status, and
// once, that a drive install has been confirmed online.
func (l *Loop3) Digest() []string {
	online := l.cfg.Online()
	installed, ierr := l.cfg.Store.Installed()
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []string{l.statusLocked(online, installed, ierr).Line}
	if l.st.Confirmed {
		out = append(out, "The update installed from a drive is now confirmed as the latest by the update server.")
		l.st.Confirmed = false
		l.saveLocked()
	}
	return out
}
