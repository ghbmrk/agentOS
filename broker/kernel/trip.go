package kernel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/decoy/match"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Trips (KRN-12 Trips, Response; D-232). The box's decoy table reaches the
// kernel as one logged event at first boot (decoy.EventType), so a replay
// gives the same trips (KRN-6). A plan is a trip when its key is a honey key
// or extends one (a key signed by no root, which the key check refuses like
// any other, KEY-1), or when its steps carry a table value or name a table
// destination: the kernel's outbound path, checked when the plan is decided,
// before any step can leave. An exit outside the kernel, such as the core's
// egress, reports a connection it refused at a decoy address (CallTrip).
//
// A trip narrows at once with no owner step (KEY-3, KEY-6), in one of three
// responses. A honey key, a table destination, and a value placed in the
// planner sandbox or its view that a planner session sends stop only that
// session: the plan is refused and its task ends, and planning goes on. A
// refused connection at an exit stops only that call. Any other value, one
// placed on the host, the edge or in the sealed store, or sent with no
// planner session behind it, gets the full response: the keys of its scope
// are paused and planning stops, until the owner resumes with a passkey on
// the owner page (ResumeTrip), never a texted RESUME (KEY-4, CH-11). Every
// trip is logged and queues one fixed-template security text (CH-15).

// Trip entry types.
const (
	TDecoyTable  = decoy.EventType // the table, once, at first boot
	TTrip        = "trip"
	TTripResumed = "trip.resumed"
)

// Refusal codes of a trip.
const (
	CTrip    = "trip"    // the plan is a trip: refused, and the trip logged
	CTripped = "tripped" // planning is stopped after a trip until the owner resumes
)

// A trip's cause, exit and response, each from a closed list.
const (
	CauseHoneyKey = "honey-key"
	CauseValue    = "value"
	CauseDest     = "destination"

	ExitKernel = "kernel"
	ExitEgress = "egress"

	RespSession = "session" // the step refused and its session stopped
	RespCall    = "call"    // the call refused, nothing else
	RespFull    = "full"    // the scope's keys paused and planning stopped
)

var (
	ErrDecoysSet = errors.New("kernel: the decoy table is logged once, at first boot")
	ErrNoDecoy   = errors.New("kernel: that address is not a decoy destination")
	// ErrTripResume is the fixed wording for a texted RESUME, or an unpause,
	// while a trip's pause is in force (KRN-12 Response).
	ErrTripResume = errors.New("A decoy was used, so I paused what it touched. Only your passkey on the owner page lifts that pause; a texted RESUME does not.")
	ErrTripSig    = errors.New("kernel: a trip resume is a live passkey's signature over TripResumeHash")
)

// Trip is one logged trip: what tripped, where, and what it stopped. Seq and
// At are the fold's. A trip names its table entry by index, never by value.
type Trip struct {
	Cause    string   `json:"cause"`
	Exit     string   `json:"exit"`
	Entry    int      `json:"entry"`
	Response string   `json:"response"`
	Plan     string   `json:"plan,omitempty"`
	Session  string   `json:"session,omitempty"` // the planner session (task) it stops
	Scopes   []key.ID `json:"scopes,omitempty"`  // the keys a full response pauses
	Seq      uint64   `json:"-"`
	At       int64    `json:"-"`
}

type tripResumed struct {
	N    int        `json:"n"`
	Last uint64     `json:"last"` // the newest trip it lifts
	By   key.Cosign `json:"by"`
}

// trips is the decoy part of the state.
type trips struct {
	set     bool
	entries []decoy.Entry
	m       *match.Matcher
	honey   map[key.ID]int // a honey key's ID -> its entry
	log     []Trip         // every trip, in order
	// paused is the keys a trip paused, which only ResumeTrip lifts, each
	// to whether the owner had paused it before: that pause stays.
	paused  map[key.ID]bool
	stopped bool // planning stopped by a trip
	resumes int
}

// HoneyKey makes a honey key from r, for decoy.Generate (decoy.Own): a root
// key in the format of every other (KEY-1), issued by a passkey no box
// enrolled, so the key check refuses it. Its value is the key's JSON, as a
// plan carries it.
func HoneyKey(r io.Reader) (string, error) {
	seed := make([]byte, ed25519.SeedSize+4)
	if _, err := io.ReadFull(r, seed); err != nil {
		return "", err
	}
	owner := key.Ed25519Signer(ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]))
	k := key.Issue(owner, key.Root{Clerk: "bank", Verbs: []key.Verb{key.Buy, key.Send, key.Share},
		Serial: hex.EncodeToString(seed[ed25519.SeedSize:])})
	b, err := json.Marshal(k)
	return string(b), err
}

// HoneyKeys is the planner view's honey key generator for decoy.Generate.
var HoneyKeys = decoy.Own{Kind: decoy.KHoneyKey, Place: decoy.PPlannerView, Make: HoneyKey}

// LogDecoyTable logs the box's decoy table, once, at first boot (KRN-1).
func (k *Kernel) LogDecoyTable(now int64, t decoy.Table) error {
	if k.s.decoys.set {
		return ErrDecoysSet
	}
	if t.Len() == 0 {
		return decoy.ErrBadTable
	}
	_, err := k.emit(now, TDecoyTable, decoy.Event(t))
	return err
}

// CallTrip logs a trip an exit reports: a connection it refused because its
// address at connect time, after any redirect, was a table destination
// (KRN-12 Trips). Only that call stopped.
func (k *Kernel) CallTrip(now int64, exit string, a netip.Addr) error {
	if exit == ExitKernel || exit == "" || len(exit) > 32 || !utf8.ValidString(exit) {
		return errors.New("kernel: a call trip names its exit")
	}
	if !k.s.decoys.set {
		return ErrNoDecoy
	}
	id, ok := k.s.decoys.m.Dest(a)
	if !ok {
		return ErrNoDecoy
	}
	_, err := k.emit(now, TTrip, Trip{Cause: CauseDest, Exit: exit, Entry: id, Response: RespCall})
	return err
}

// TripResumeHash names the n-th trip resume, lifting every trip up to the
// one logged at last, so a signature never replays and never lifts a trip
// logged after it was made.
func TripResumeHash(n int, last uint64) [32]byte {
	b := binary.BigEndian.AppendUint64([]byte("agentos.trip.resume.v1\x00"), uint64(n))
	return sha256.Sum256(binary.BigEndian.AppendUint64(b, last))
}

// TripResume is what the owner page asks the passkey to sign: the resume's
// number and the newest trip; ok is false when no trip's pause is in force.
func (s *State) TripResume() (n int, last uint64, ok bool) {
	d := &s.decoys
	if !d.held() {
		return 0, 0, false
	}
	return d.resumes, d.log[len(d.log)-1].Seq, true
}

// ResumeTrip lifts every trip's pause and planning stop on the owner's
// passkey (KEY-4): a live passkey's co-signature over TripResumeHash. It
// widens, so it anchors.
func (k *Kernel) ResumeTrip(now int64, by key.Cosign) error {
	n, last, ok := k.s.TripResume()
	if !ok {
		return errors.New("kernel: no trip's pause is in force")
	}
	b := tripResumed{n, last, by}
	if !k.s.resumeOK(b) {
		return ErrTripSig
	}
	return k.owner(now, TTripResumed, b)
}

// Tripped reports whether a trip's pause or planning stop is in force.
func (s *State) Tripped() bool { return s.decoys.held() }

// Trips lists the logged trips, oldest first.
func (s *State) Trips() []Trip { return slices.Clone(s.decoys.log) }

// SecurityText is one queued security text: the trip it reports and its
// fixed wording, which names no value, key or address (CH-15).
type SecurityText struct {
	Trip uint64
	Text string
}

var tripTexts = map[string]string{
	RespFull:    "Security: a decoy was used, so something in me is breached. I paused the keys it came from and stopped planning. Nothing resumes until you open my owner page and use your passkey.",
	RespSession: "Security: a planner session reached for a decoy, as injected content can make it. I refused that step and stopped only that session; planning goes on.",
	RespCall:    "Security: one of my services tried to connect to a decoy address. I refused that one connection; nothing else stopped.",
}

// SecurityTexts is one text per trip, oldest first, for the owner line to
// send.
func (s *State) SecurityTexts() []SecurityText {
	out := make([]SecurityText, len(s.decoys.log))
	for i, t := range s.decoys.log {
		out[i] = SecurityText{t.Seq, tripTexts[t.Response]}
	}
	return out
}

func (d *trips) held() bool { return d.stopped || len(d.paused) > 0 }

// tripOf is the trip plan p is, or nil: pure over the state, so Admit, the
// trip entry decide logs after it, and Rederive agree (KRN-6). The checks run
// in order: a honey key, a table value in the steps, a table destination.
func (s *State) tripOf(p Plan) *Trip {
	d := &s.decoys
	if !d.set {
		return nil
	}
	t := &Trip{Exit: ExitKernel, Plan: p.ID, Response: RespSession}
	ky := key.Key{Root: p.Key.Root}
	for i := 0; i <= len(p.Key.Links); i++ {
		ky.Links = p.Key.Links[:i]
		if id, ok := d.honey[ky.Tip()]; ok {
			t.Cause, t.Entry, t.Session = CauseHoneyKey, id, key.TaskOf(p.Key)
			return t
		}
	}
	v, err := VerifyPlan(p, s.owners(p.Key))
	if err == nil {
		t.Session = v.Limits.Task
	}
	steps, _ := json.Marshal(p.Steps)
	if r := d.m.Scan(append([]byte(p.ID+"\n"), steps...)); len(r.Trips) > 0 {
		t.Cause, t.Entry = CauseValue, r.Trips[0]
		if pl := d.entries[t.Entry].Place; t.Session == "" || pl != decoy.PSandboxEnv && pl != decoy.PPlannerView {
			t.Response, t.Session = RespFull, ""
			if err == nil {
				t.Scopes = v.Scopes()
			}
		}
		return t
	}
	for _, st := range p.Steps {
		names := make([]string, 0, len(st.Args))
		for n := range st.Args {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if a, ok := destOf(st.Args[n]); ok {
				if id, ok := d.m.Dest(a); ok {
					t.Cause, t.Entry = CauseDest, id
					return t
				}
			}
		}
	}
	return nil
}

// destOf reads an address a step names literally: a bare address, an
// address and port, or a URL whose host is one. A name is checked where it
// is resolved, at connect time (decoy.match).
func destOf(v string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(v); err == nil {
		return a, true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr(), true
	}
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		a, err := netip.ParseAddr(u.Hostname())
		return a, err == nil
	}
	return netip.Addr{}, false
}

// tripped is the trip decide logs after refusing plan id with CTrip.
func (k *Kernel) tripped(now int64, id string) error {
	t := k.s.tripOf(k.s.Plans[id].Plan)
	if t == nil {
		return nil
	}
	_, err := k.emit(now, TTrip, *t)
	return err
}

// resumeOK checks a trip resume as a fold must: the next resume, over the
// newest trip, signed by a live passkey.
func (s *State) resumeOK(b tripResumed) bool {
	n, last, ok := s.TripResume()
	return ok && b.N == n && b.Last == last && key.In(s.Passkeys(), b.By.By) && b.By.Over(TripResumeHash(n, last))
}

// tripOK checks a trip entry's shape: known cause, exit and response, a
// table entry, and a session or scopes only where its response stops them.
func (d *trips) tripOK(t Trip) bool {
	if !d.set || t.Entry < 0 || t.Entry >= len(d.entries) || t.Exit == "" {
		return false
	}
	switch t.Cause {
	case CauseHoneyKey, CauseValue, CauseDest:
	default:
		return false
	}
	switch t.Response {
	case RespSession:
		return len(t.Scopes) == 0
	case RespFull:
		return t.Session == ""
	case RespCall:
		return t.Exit != ExitKernel && t.Session == "" && len(t.Scopes) == 0 && t.Plan == ""
	}
	return false
}

// applyTrip folds a decoy entry. One that fails its check changes nothing.
func (s *State) applyTrip(e Entry) error {
	d := &s.decoys
	switch e.Type {
	case TDecoyTable:
		if d.set {
			return nil
		}
		t, err := decoy.FromEvent(e.V, e.Body)
		if err != nil {
			return fmt.Errorf("entry %d %s: %w", e.Seq, e.Type, ErrCorrupt)
		}
		d.set, d.entries, d.m, d.honey = true, t.Entries(), t.Matcher(), map[key.ID]int{}
		for i, en := range d.entries {
			var hk key.Key
			if en.Kind == decoy.KHoneyKey && json.Unmarshal([]byte(en.Value), &hk) == nil {
				d.honey[hk.Tip()] = i
			}
		}
	case TTrip:
		t, err := body[Trip](e)
		if err != nil {
			return err
		}
		if !d.tripOK(t) {
			return nil
		}
		t.Seq, t.At = e.Seq, e.At
		d.log = append(d.log, t)
		if t.Response == RespFull {
			d.stopped = true
			if d.paused == nil {
				d.paused = map[key.ID]bool{}
			}
			for _, id := range t.Scopes {
				if _, ok := d.paused[id]; !ok {
					d.paused[id] = s.Changes.Paused[id]
				}
				s.Changes.Paused[id] = true
			}
		}
		if t.Session != "" {
			s.stopSession(t.Session)
		}
	case TTripResumed:
		b, err := body[tripResumed](e)
		if err != nil {
			return err
		}
		if !s.resumeOK(b) {
			return nil
		}
		for id, before := range d.paused {
			if !before {
				delete(s.Changes.Paused, id)
			}
		}
		d.paused, d.stopped = nil, false
		d.resumes++
	}
	return nil
}

// stopSession ends a planner session: its task, and its plans still active,
// cancelled as a cancel entry cancels them. Reconciliation of a step already
// sent outlives it (KRN-8).
func (s *State) stopSession(task string) {
	if t := s.tasks[task]; t != nil {
		t.ended = true
	}
	for _, id := range s.Order {
		p := s.Plans[id]
		if p.Status != SActive || p.Plan.Task() != task {
			continue
		}
		p.Status, p.Cancel, p.CancelDetail = SCancelled, CTrip, ""
		if st := &p.Steps[p.Next]; sendable(st.Phase) {
			s.cancelUnsent(p, st)
		}
	}
}
