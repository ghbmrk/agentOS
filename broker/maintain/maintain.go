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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/update"
)

// ChannelPinned is UPD-4's pinned channel: no automatic updates, security
// notices only. Stable and fast are update.ChannelStable and ChannelFast.
const ChannelPinned = loops.ChannelPinned

// Proposer is the part of the change pipeline Loop 3 uses.
type Proposer interface {
	ProposeRelease(ctx context.Context, v *update.Verified) (change.Report, error)
}

// Config configures New.
type Config struct {
	// Store is the box's update state (trusted root, installed release).
	Store *update.Store
	// Mirrors are the owner's configured mirrors, tried in order until one
	// passes every check. Nil or empty: no mirror, which reads as offline.
	Mirrors func() []update.Source
	// Online reports network access. No mirror is contacted while it is
	// false, and the box is never reported current. Required.
	Online func() bool
	// Attestations fetches attestations for a release manifest path (for
	// example releases/12.json). They arrive from anyone and are checked
	// by update. Nil: none are known.
	Attestations func(ctx context.Context, release string) ([][]byte, error)
	// Attestors is the allow-list of attestor keys whose passing reports
	// count (D6, arbitrator ruling on #53): pinned in the installed image
	// and the owner's configuration, changed only by an update the current
	// list attested, or by the owner with a code-generator code and local
	// confirmation. Empty: no attestor yet, so security fixes go to the
	// owner (CH-3) and ordinary releases rest on their soak.
	Attestors []ed25519.PublicKey
	// InterimAttestors are the project's own test box keys pinned in the
	// image (D6 interim, Mark 2026-10-05), passed to update as
	// Options.InterimAttestors; update decides when they count.
	InterimAttestors []ed25519.PublicKey
	// AttestWait is how long a security fix waits for a listed attestor
	// before it goes to the owner instead. Default 24 hours.
	AttestWait time.Duration
	// OwnKey is this box's attestation key, which never counts as
	// independent. Nil: none.
	OwnKey ed25519.PublicKey
	// Settings reads the owner's loop settings (the scheduler's
	// Settings): whether update checks are on, and the owner's update
	// channel and cadence (UPD-4, UPD-5; loops.UpdateSettings), read at
	// each check. Nil: every loop on, and the spec defaults.
	Settings func() loops.Settings
	// Pipeline is the change pipeline (§11).
	Pipeline Proposer
	// State persists Loop 3's own state.
	State change.Store
	// Interval is how often to check (UPD-5: daily). Default 24 hours.
	Interval time.Duration
	// Retry is how soon to look again after a failed check, or for a
	// security fix waiting for its attestation. Default 1 hour.
	Retry time.Duration
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
	waitPreempted   = "preempted"
)

// Failure kinds of a check, for the owner's line.
const (
	failExpired   = "expired"
	failSigned    = "signatures"
	failRollback  = "rollback"
	failReach     = "unreachable"
	failNoMirrors = "no-mirrors"
	failState     = "state"
	failRelease   = "release"
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
	Newest int64 `json:"newest,omitempty"`
	// NewestSecurity: the newest release is marked a security fix.
	NewestSecurity bool     `json:"newest_security,omitempty"`
	Pending        *pending `json:"pending,omitempty"`
	// Seen is when the box first saw each release image, on any channel,
	// keyed by imageKey: a release promoted from fast to stable keeps its
	// image, so its soak counts from first sight on fast (UPD-5).
	Seen       map[string]time.Time   `json:"seen,omitempty"`
	Proposed   map[int64]change.State `json:"proposed,omitempty"`
	ProposedAt map[int64]time.Time    `json:"proposed_at,omitempty"`
	// DigestCurrent: the last digest already said the box is up to date,
	// so the next stays quiet while it still is.
	DigestCurrent bool `json:"digest_current,omitempty"`
	// Confirmed: an online check cleared a drive install's pending
	// freshness check; the digest says so once.
	Confirmed bool `json:"confirmed,omitempty"`
	// FreshFailed: an online check did not find the drive install in the
	// signed release list (update U4); it stays unconfirmed.
	FreshFailed bool `json:"fresh_failed,omitempty"`
	// RootRotatedTo: a check accepted new signing keys; the digest says
	// so once (security R3 on #46).
	RootRotatedTo int64 `json:"root_rotated_to,omitempty"`
	// TestedBy says, per proposed version, whose report let a security fix
	// stage on its own: testedProject (D6 interim, the project's own test
	// box) or testedIndependent; absent when the owner approves it.
	TestedBy map[int64]string `json:"tested_by,omitempty"`
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
	_ loops.Urgent   = (*Loop3)(nil)
)

// New loads Loop 3's state. Proposals the pipeline was holding for the
// owner are forgotten across a restart (change C9), so Loop 3 proposes
// them again at its next check.
func New(cfg Config) (*Loop3, error) {
	if cfg.Store == nil || cfg.Pipeline == nil || cfg.State == nil || cfg.Online == nil {
		return nil, errors.New("maintain: Store, Pipeline, State and Online are required")
	}
	if cfg.Mirrors == nil {
		cfg.Mirrors = func() []update.Source { return nil }
	}
	if cfg.Settings == nil {
		cfg.Settings = func() loops.Settings { return loops.Settings{} }
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.Retry <= 0 {
		cfg.Retry = time.Hour
	}
	if cfg.AttestWait <= 0 {
		cfg.AttestWait = 24 * time.Hour
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
			delete(l.st.ProposedAt, v)
			delete(l.st.TestedBy, v)
			l.st.Next = time.Time{}
		}
	}
	return l, nil
}

// Loop is loops.Maintain.
func (l *Loop3) Loop() loops.Loop { return loops.Maintain }

// Urgent reports work that must not wait out a dry-run park (LOOP-11,
// security first; arbitrator ruling on #53): a security fix waiting for
// its attestation or a retry, a failed check being retried, or a box
// back online since its last offer.
func (l *Loop3) Urgent() bool {
	online := l.cfg.Online()
	l.mu.Lock()
	defer l.mu.Unlock()
	// The scheduler asks a parked loop only this, so going offline is
	// noted here too, and coming back online makes a check due at once
	// (M3).
	if !online {
		l.noteOfflineLocked()
		return false
	}
	if !l.st.OfflineSince.IsZero() || l.st.Failure != "" {
		return true
	}
	p := l.st.Pending
	return p != nil && p.Security && p.Why != waitPinned
}

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
		l.noteOfflineLocked()
		return loops.Job{}, false
	}
	// Back online: due at once until a check runs, which clears
	// OfflineSince, so a box that turns busy first does not lose it. A
	// clock that went back behind the last attempt is not trusted to say
	// a check is not due.
	if l.st.OfflineSince.IsZero() && !l.st.LastAttempt.IsZero() && now.Before(l.st.Next) && !now.Before(l.st.LastAttempt) {
		return loops.Job{}, false
	}
	return loops.Job{Name: "update-check", Run: l.check}, true
}

func (l *Loop3) noteOfflineLocked() {
	if l.st.OfflineSince.IsZero() {
		l.st.OfflineSince = l.cfg.Now()
		l.saveLocked()
	}
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
	set := l.cfg.Settings().Updates
	channel := set.ChannelName()
	opts := update.Options{Channel: channel, Now: l.cfg.Now, Attestors: l.cfg.Attestors, InterimAttestors: l.cfg.InterimAttestors}
	if channel == ChannelPinned {
		// Checked as stable, for security notices only (UPD-4).
		opts.Channel = update.ChannelStable
	}
	res, failure, err := l.checkMirrors(opts)
	var sighted string
	if failure == "" && opts.Channel == update.ChannelStable {
		// Note when an image first reaches fast, without taking it, so a
		// later promotion to stable is not soaked twice (UPD-5).
		fopts := opts
		fopts.Channel = update.ChannelFast
		if fres, f, _ := l.checkMirrors(fopts); f == "" && fres.Release != nil {
			sighted, _ = imageKey(fres.Release)
		}
	}
	if cerr := ctx.Err(); cerr != nil {
		// Preempted: nothing is recorded, and the check is offered again.
		return loops.Result{Err: cerr}
	}
	installed, ierr := l.cfg.Store.Installed()
	if failure == "" && ierr != nil {
		failure, err = failState, ierr
	}
	var (
		rel *update.Verified
		m   update.Manifest
		key string
	)
	if failure == "" && res.Release != nil {
		rel = res.Release
		m, err = rel.Manifest()
		if err == nil {
			key, err = imageKey(rel)
		}
		if err != nil {
			// Fail closed: a release the box cannot read is not "current".
			failure = failRelease
		}
	}
	now := l.cfg.Now()

	l.mu.Lock()
	l.st.LastAttempt, l.st.OfflineSince = now, time.Time{}
	if failure != "" {
		l.st.Failure = failure
		l.st.Next = now.Add(l.cfg.Retry)
		serr := l.saveLocked()
		l.mu.Unlock()
		return loops.Result{Err: errors.Join(err, serr)}
	}
	l.st.LastOnline, l.st.Failure = now, ""
	l.st.FreshFailed = res.FreshnessFailed
	if res.RootRotatedTo > 0 {
		l.st.RootRotatedTo = res.RootRotatedTo
	}
	if res.FreshnessConfirmed && rel == nil {
		// Only when nothing newer is out: the drive install is then
		// confirmed current, not just checked (UPD-8).
		l.st.Confirmed = true
	}
	if l.st.Seen == nil {
		l.st.Seen = map[string]time.Time{}
	}
	for k, t := range l.st.Seen {
		if now.Sub(t) > seenKeep {
			delete(l.st.Seen, k)
		}
	}
	if _, ok := l.st.Seen[sighted]; sighted != "" && !ok {
		l.st.Seen[sighted] = now
	}
	for v := range l.st.Proposed {
		if v <= installed.Version {
			delete(l.st.Proposed, v)
			delete(l.st.ProposedAt, v)
			delete(l.st.TestedBy, v)
		}
	}
	l.st.Newest, l.st.NewestSecurity, l.st.Pending = 0, false, nil
	l.st.Next = now.Add(l.cfg.Interval)
	if rel == nil {
		serr := l.saveLocked()
		l.mu.Unlock()
		return loops.Result{Err: serr}
	}
	v := m.Version
	// A newer ordinary release carries an earlier security fix (update
	// SecurityFix), so it is handled as one (M5).
	security := m.Security || res.SecurityFix != 0
	l.st.Newest, l.st.NewestSecurity = v, security
	if _, ok := l.st.Seen[key]; !ok {
		l.st.Seen[key] = now
	}
	seen := l.st.Seen[key]
	_, proposed := l.st.Proposed[v]
	if channel == ChannelPinned {
		l.st.Pending = &pending{Version: v, Security: security, Why: waitPinned}
	}
	serr := l.saveLocked()
	l.mu.Unlock()
	if channel == ChannelPinned || proposed {
		// Pinned: a notice only. Proposed: the pipeline has it, or
		// rejected it.
		return loops.Result{Err: serr}
	}

	o := l.decide(ctx, rel, m, security, set, seen, now)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.st.Newest != v {
		return loops.Result{Value: o.value, Err: errors.Join(o.err, serr)} // superseded meanwhile
	}
	switch {
	case o.proposed != "":
		if l.st.Proposed == nil {
			l.st.Proposed = map[int64]change.State{}
		}
		l.st.Proposed[v] = o.proposed
		if l.st.ProposedAt == nil {
			l.st.ProposedAt = map[int64]time.Time{}
		}
		l.st.ProposedAt[v] = now
		if o.tested != "" {
			if l.st.TestedBy == nil {
				l.st.TestedBy = map[int64]string{}
			}
			l.st.TestedBy[v] = o.tested
		}
	case o.wait == nil:
		// Preempted before proposing: offered again.
		l.st.Pending = &pending{Version: v, Security: security, Why: waitPreempted}
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
	return loops.Result{Value: o.value, Err: errors.Join(o.err, serr, l.saveLocked())}
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

// seenKeep is how long a first sighting is remembered.
const seenKeep = 90 * 24 * time.Hour

// imageKey identifies a release's image: its /usr verity root hash and
// every file's signed path and hash. A promotion that republishes the same
// image under a new version has the same key.
func imageKey(rel *update.Verified) (string, error) {
	m, err := rel.Manifest()
	if err != nil {
		return "", err
	}
	files, err := rel.Files()
	if err != nil {
		return "", err
	}
	parts := []string{m.UsrRootHash}
	for _, f := range files {
		parts = append(parts, f.Path+"="+f.SHA256)
	}
	sort.Strings(parts[1:])
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Whose report let a security fix stage on its own (State.TestedBy).
const (
	testedProject     = "project"
	testedIndependent = "independent"
)

// outcome is what decide did with a release: proposed it (proposed is the
// pipeline's state), is waiting (wait), or was preempted (neither).
type outcome struct {
	proposed change.State
	tested   string
	wait     *pending
	value    float64
	err      error
}

// decide applies UPD-8 and UPD-5 to a verified release newer than the
// installed one and proposes it when they allow.
func (l *Loop3) decide(ctx context.Context, rel *update.Verified, m update.Manifest, security bool, set loops.UpdateSettings, seen, now time.Time) outcome {
	mf, err := rel.ManifestFile()
	if err != nil {
		return outcome{wait: &pending{Version: m.Version, Security: security, Why: waitPropose}, err: err}
	}
	// update counts only reports from the allow-list (Options.Attestors).
	atts, aerr := l.attestations(ctx, mf.Path)
	if security && set.SecurityAsk {
		// SECURITY UPDATES ASK: every security fix goes to the owner at
		// once, never staged on its own (UPD-5).
		atts = nil
	} else if security {
		// UPD-8, D6: a security fix auto-stages only with a passing report
		// from a listed attestor. Without one it waits a day for one, then
		// goes to the owner (CH-3); with no attestor listed it goes to the
		// owner at once.
		// A newer release carrying the fix but not marked security itself
		// cannot auto-stage (update judges the newest), so it goes to the
		// owner at once.
		if err := rel.SecurityAutoStage(atts, l.cfg.OwnKey); err != nil && m.Security &&
			len(l.cfg.Attestors) > 0 && now.Before(seen.Add(l.cfg.AttestWait)) {
			return outcome{wait: &pending{Version: m.Version, Security: true, Why: waitAttestation}, err: aerr}
		}
	} else if set.ChannelName() != update.ChannelFast {
		// UPD-5: an ordinary stable release soaks, and needs passing
		// reports from listed attestors when any exist, before it is
		// offered.
		until := seen.Add(time.Duration(set.Soak()) * 24 * time.Hour)
		if now.Before(until) || (len(l.cfg.Attestors) > 0 && rel.IndependentPasses(atts, l.cfg.OwnKey) < l.cfg.MinPasses) {
			return outcome{wait: &pending{Version: m.Version, Why: waitSoak, Until: until}, err: aerr}
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome{err: err}
	}
	rep, err := l.cfg.Pipeline.ProposeRelease(ctx, rel.WithAttestations(atts, l.cfg.OwnKey))
	if err != nil {
		if ctx.Err() != nil {
			return outcome{err: err}
		}
		return outcome{wait: &pending{Version: m.Version, Security: security, Why: waitPropose}, err: err}
	}
	o := outcome{proposed: rep.State}
	if security && rel.SecurityAutoStage(atts, l.cfg.OwnKey) == nil {
		o.tested = testedIndependent
		if rel.InterimAttestation() {
			o.tested = testedProject
		}
	}
	switch {
	case rep.State == change.StateRejected:
	case security:
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
	failExpired:   "the update source's data has expired, or this box's clock is wrong, so newer updates may be hidden",
	failSigned:    "the update data was not properly signed",
	failRollback:  "the update source offered older data than this box already has",
	failReach:     "the update source could not be reached",
	failNoMirrors: "no update source is set up",
	failState:     "this box's update record could not be read",
	failRelease:   "the newest release could not be read",
}

// Status reports whether the box is up to date, and says why not.
func (l *Loop3) Status() Status {
	online, set := l.cfg.Online(), l.cfg.Settings()
	installed, ierr := l.cfg.Store.Installed()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.statusLocked(online, set, installed, ierr)
}

func (l *Loop3) statusLocked(online bool, set loops.Settings, in update.Installed, ierr error) Status {
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
	case set.Off:
		return Status{Line: fmt.Sprintf("Updates: last checked %s, but update checks are off. Reply LOOPS ON to restart them.", last) + drive}
	case !set.On(loops.Maintain):
		return Status{Line: fmt.Sprintf("Updates: last checked %s, but update checks are off. Reply UPDATE CHECKS ON to restart them.", last) + drive}
	case st.Failure != "":
		return Status{Line: fmt.Sprintf("Updates: could not check: %s. Last good check: %s.", failText[st.Failure], last) + drive}
	case st.LastOnline.IsZero():
		return Status{Line: "Updates: not checked yet." + drive}
	case now.Before(st.LastOnline):
		return Status{Line: fmt.Sprintf("Updates: this box's clock is behind its last check (%s), so it will check again.", last)}
	case in.UnconfirmedFreshness && st.FreshFailed:
		return Status{Line: update.NotConfirmedNotice}
	case in.UnconfirmedFreshness:
		return Status{Line: "Updates: the last update was installed from a drive and has not been checked online yet."}
	case now.Sub(st.LastOnline) > 2*l.cfg.Interval:
		// Loop 3 runs only in spare time (LOOP-1), and makes no model
		// calls, so a busy box is the only other reason.
		return Status{Line: fmt.Sprintf("Updates: last checked %s. The box has been busy and will check again soon.", last)}
	}
	if p := st.Pending; p != nil {
		return Status{Line: pendingLine(p)}
	}
	if st.Newest > in.Version {
		switch st.Proposed[st.Newest] {
		case change.StateRejected:
			return Status{Line: fmt.Sprintf("Update %d did worse on this box's tests and was not installed.", st.Newest)}
		case change.StateAdopted:
			ready := fmt.Sprintf("update %d is ready and installs at the next quiet time.", st.Newest)
			switch {
			case st.NewestSecurity && st.TestedBy[st.Newest] == testedProject:
				return Status{Line: "Security " + ready + " It was tested by the AgentOS project's own test box, not an independent tester."}
			case st.NewestSecurity && st.TestedBy[st.Newest] == testedIndependent:
				return Status{Line: "Security " + ready + " An independent tester's report passed."}
			}
			return Status{Line: "U" + ready[1:]}
		}
		if at, ok := st.ProposedAt[st.Newest]; ok && st.NewestSecurity && st.TestedBy[st.Newest] != "" {
			return Status{Line: fmt.Sprintf("Security update %d has been waiting for your approval since %s.", st.Newest, at.Format("Mon 2 Jan"))}
		}
		if at, ok := st.ProposedAt[st.Newest]; ok && st.NewestSecurity {
			return Status{Line: fmt.Sprintf("Security update %d needs your approval: no trusted independent test report yet. Asked %s.", st.Newest, at.Format("Mon 2 Jan"))}
		}
		if at, ok := st.ProposedAt[st.Newest]; ok {
			return Status{Line: fmt.Sprintf("Update %d has been waiting for your approval since %s.", st.Newest, at.Format("Mon 2 Jan"))}
		}
		return Status{Line: fmt.Sprintf("Update %d is waiting for your approval.", st.Newest)}
	}
	return Status{Current: true, Line: fmt.Sprintf("Updates: up to date (checked %s).", last)}
}

func pendingLine(p *pending) string {
	switch {
	case p.Why == waitPinned && p.Security:
		return fmt.Sprintf("Security update %d is out, but this box is pinned, so it will not install it on its own. Reply UPDATES STABLE to take it.", p.Version)
	case p.Why == waitPinned:
		return "Updates: this box is pinned, so it does not install updates on its own. Reply UPDATES STABLE to take them."
	case p.Why == waitAttestation:
		return fmt.Sprintf("Security update %d is waiting for an independent test report before it installs.", p.Version)
	case p.Why == waitSoak:
		return fmt.Sprintf("Update %d is out. The box will offer it after %s, once other boxes have tested it.", p.Version, p.Until.Format("Mon 2 Jan"))
	case p.Why == waitPreempted:
		return fmt.Sprintf("Update %d was found. The box will look at it again soon.", p.Version)
	case p.Security:
		return fmt.Sprintf("Security update %d was found but could not be tested yet. The box will try again within the hour.", p.Version)
	}
	return fmt.Sprintf("Update %d was found but could not be tested yet.", p.Version)
}

// Digest is Loop 3's lines for the owner's digest: the update status,
// except while the box stays up to date (said once when it becomes so),
// and once, that a drive install has been confirmed online.
func (l *Loop3) Digest() []string {
	online, set := l.cfg.Online(), l.cfg.Settings()
	installed, ierr := l.cfg.Store.Installed()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.statusLocked(online, set, installed, ierr)
	var out []string
	if !st.Current || !l.st.DigestCurrent {
		out = append(out, st.Line)
	}
	if st.Current != l.st.DigestCurrent {
		l.st.DigestCurrent = st.Current
		l.saveLocked()
	}
	if l.st.Confirmed {
		out = append(out, "The update installed from a drive has now been checked online.")
		l.st.Confirmed = false
		l.saveLocked()
	}
	if l.st.RootRotatedTo > 0 {
		out = append(out, fmt.Sprintf("Update signing keys changed to version %d.", l.st.RootRotatedTo))
		l.st.RootRotatedTo = 0
		l.saveLocked()
	}
	return out
}
