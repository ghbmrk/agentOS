package kernel

import (
	"bytes"
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
	"github.com/ghbmrk/agentos/broker/kernel/ipform"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Trips (KRN-12 Trips, Response; D-232). The box's decoy table reaches the
// kernel as one logged event at first boot (decoy.EventType), so a replay
// gives the same trips (KRN-6). A plan is a trip when its key is a honey key
// or extends one (a key signed by no root, which the key check refuses like
// any other, KEY-1), or when its steps carry a table value or name a table
// destination: the kernel's outbound path, checked when the plan is decided,
// before any step can leave. Its trip is logged in its rejection's entry, so
// no crash parts them. A honey key cited at the kernel's other key checks,
// Extend and Issue, trips too. An exit outside the kernel, such as the core's
// egress, reports a connection it refused at a decoy address (CallTrip).
//
// A trip narrows at once with no owner step (KEY-3, KEY-6), in one of three
// responses. A honey key, a table destination, and a value placed in the
// planner sandbox or its view that a planner session sends stop only that
// session: the plan is refused and its task ends, and planning goes on. A
// refused connection at an exit stops only that call. Any other value, one
// placed on the host, the edge or in the sealed store, or sent with no
// planner session behind it, and a honey key at Extend or Issue, which only
// the owner side calls, get the full response: the keys of its scope
// are paused and planning stops, until the owner resumes with a passkey on
// the owner page (ResumeTrip), never a texted RESUME (KEY-4, CH-11). A trip
// while that holds still narrows: its session stops and its scope pauses.
// Only a full trip none of whose IDs (root, links, account) is already
// paused moves what the resume signs; a key a session derives shares its
// root and account, so deriving fresh keys cannot void it. Every trip is logged with a fixed-template
// security text (CH-15); a full trip sharing an ID already paused, and
// repeats of a session or call trip within TextWindow, send none.

// Trip entry types.
const (
	TDecoyTable  = decoy.EventType // the table, once, at first boot
	TTrip        = "trip"
	TTripResumed = "trip.resumed"
	TTripOwner   = "trip.owner" // a honey key cited at Extend or Issue
)

// The owner-side calls that check a key outside Admit.
const (
	OpExtend = "extend"
	OpIssue  = "issue"
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

// TextWindow is how long after a session or call trip's text a repeat of its
// response sends none (CH-15): a hostile session cannot flood the owner line.
const TextWindow = key.DayMS / 24

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
	fresh    bool     // a full trip that set what the resume signs
}

type tripResumed struct {
	N    int        `json:"n"`
	Last uint64     `json:"last"` // the full trip that set the pause it lifts
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
	stopped bool   // planning stopped by a trip
	full    uint64 // the newest full trip, which set the pause
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
// (KRN-12 Trips). Only that call stopped. It is an input, so it neither
// waits on nor moves a pause's resume.
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

// TripResumeHash names the n-th trip resume, lifting every pause up to the
// full trip logged at last, so a signature never replays and never lifts a
// key a later trip paused under a root and account not paused before. A
// full trip sharing any ID already paused, and every session or call trip,
// leaves last as it is: a hostile session can derive keys but never a root,
// so repeats cannot void the owner's signature.
func TripResumeHash(n int, last uint64) [32]byte {
	b := binary.BigEndian.AppendUint64([]byte("agentos.trip.resume.v1\x00"), uint64(n))
	return sha256.Sum256(binary.BigEndian.AppendUint64(b, last))
}

// TripResume is what the owner page asks the passkey to sign: the resume's
// number and the newest full trip sharing no ID already paused; ok is
// false when no trip's pause is in force.
func (s *State) TripResume() (n int, last uint64, ok bool) {
	d := &s.decoys
	if !d.held() {
		return 0, 0, false
	}
	return d.resumes, d.full, true
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

// tripTexts are the security texts, each one SMS segment (CH-12).
var tripTexts = map[string]string{
	RespFull:    "Security: a decoy was used, so something in me is breached. I paused the keys it came from and stopped planning until you use your passkey on my owner page.",
	RespSession: "Security: a planner session reached for a decoy, as injected content can make it. I stopped only that session. Repeats this hour are logged, not texted.",
	RespCall:    "Security: one of my services reached for a decoy. I refused that one request; nothing else stopped. Repeats this hour are logged, not texted.",
}

// SecurityTexts is the texts for the owner line to send, oldest first: one
// per full trip sharing no ID already paused, and one per session or call trip
// unless one of its response was texted within TextWindow before it.
func (s *State) SecurityTexts() []SecurityText {
	var out []SecurityText
	sent := map[string]int64{}
	for _, t := range s.decoys.log {
		if at, ok := sent[t.Response]; t.Response == RespFull && !t.fresh || t.Response != RespFull && ok && t.At-at < TextWindow {
			continue
		}
		sent[t.Response] = t.At
		out = append(out, SecurityText{t.Seq, tripTexts[t.Response]})
	}
	return out
}

func (d *trips) held() bool { return d.stopped || len(d.paused) > 0 }

// honeyOf is the table entry of the honey key ky is or extends.
func (d *trips) honeyOf(ky key.Key) (int, bool) {
	for _, id := range chain(ky) {
		if e, ok := d.honey[id]; ok {
			return e, true
		}
	}
	return 0, false
}

// chain is the IDs of ky's root and each link, verified or not.
func chain(ky key.Key) []key.ID {
	ids := make([]key.ID, 0, len(ky.Links)+1)
	k := key.Key{Root: ky.Root}
	for i := 0; i <= len(ky.Links); i++ {
		k.Links = ky.Links[:i]
		ids = append(ids, k.Tip())
	}
	return ids
}

// tripOf is the trip plan p is, or nil: pure over the state, so Admit, the
// rejection decide logs, and Rederive agree (KRN-6). A table value that
// needs the full response gives it whatever else the plan cites (KRN-12);
// otherwise the first of a honey key, a table value in the steps and a table
// destination names the session-only trip. The planner session is the task
// the key's well-formed links name, verified or not: a forged claim can stop
// only the session it names. A key with no such claim (no task, or a
// malformed chain) has no session, so a sandbox or view value under it gets
// the full response.
func (s *State) tripOf(p Plan) *Trip {
	d := &s.decoys
	if !d.set {
		return nil
	}
	var hit *Trip
	session := key.TaskOf(p.Key)
	if id, ok := d.honeyOf(p.Key); ok {
		hit = &Trip{Cause: CauseHoneyKey, Exit: ExitKernel, Entry: id, Response: RespSession, Plan: p.ID, Session: session}
	}
	v, err := VerifyPlan(p, s.owners(p.Key))
	steps, _ := json.Marshal(p.Steps)
	for _, id := range d.m.Scan(append([]byte(p.ID+"\n"), steps...)).Trips {
		if pl := d.entries[id].Place; session == "" || pl != decoy.PSandboxEnv && pl != decoy.PPlannerView {
			t := &Trip{Cause: CauseValue, Exit: ExitKernel, Entry: id, Response: RespFull, Plan: p.ID}
			if err == nil {
				t.Scopes = v.Scopes()
			}
			return t
		}
		if hit == nil {
			hit = &Trip{Cause: CauseValue, Exit: ExitKernel, Entry: id, Response: RespSession, Plan: p.ID, Session: session}
		}
	}
	if hit != nil {
		return hit
	}
	t := &Trip{Exit: ExitKernel, Plan: p.ID, Response: RespSession, Session: session}
	for _, st := range p.Steps {
		names := make([]string, 0, len(st.Args))
		for n := range st.Args {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if a, ok := destOf(st.Args[n]); ok {
				for _, f := range ipform.Forms(a) {
					if id, ok := d.m.Dest(f); ok {
						t.Cause, t.Entry = CauseDest, id
						return t
					}
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

// ownerTrip is the entry for an owner-side call (Extend, Issue) that cites
// a honey key: the call and the key, as given, and the trip they are. Its
// fold and Rederive derive the trip again from the key, so no recorded input
// pauses a key without carrying a honey key (KRN-6).
type ownerTrip struct {
	Op   string  `json:"op"`
	Key  key.Key `json:"key"`
	Trip Trip    `json:"trip"` // its Plan is Extend's
}

// honeyTrip refuses an owner-side call (Extend, Issue) that cites a honey
// key, and logs its trip. Planner-view content reached the owner path, so
// it gets the full response (KRN-12 Response).
func (k *Kernel) honeyTrip(now int64, op, plan string, keys ...key.Key) error {
	for _, ky := range keys {
		if t := k.s.ownerTripOf(op, plan, ky); t != nil {
			if _, err := k.emit(now, TTripOwner, ownerTrip{op, ky, *t}); err != nil {
				return err
			}
			return &key.Refusal{Code: CTrip, Detail: CauseHoneyKey}
		}
	}
	return nil
}

// again derives b's trip from the state alone; ok only when b logged it.
func (b ownerTrip) again(s *State) (Trip, bool) {
	t := s.ownerTripOf(b.Op, b.Trip.Plan, b.Key)
	if t == nil {
		return Trip{}, false
	}
	x, _ := json.Marshal(t)
	y, _ := json.Marshal(b.Trip)
	return *t, bytes.Equal(x, y)
}

// ownerTripOf is the trip of owner call op citing ky, or nil: pure over the
// state. It pauses the honey key's own IDs and, at Extend, the held plan's
// scope and its funding key's chain, an earlier extension's included.
func (s *State) ownerTripOf(op, plan string, ky key.Key) *Trip {
	d := &s.decoys
	if !d.set || op != OpExtend && op != OpIssue || op == OpIssue && plan != "" {
		return nil
	}
	id, ok := d.honeyOf(ky)
	if !ok {
		return nil
	}
	var scopes []key.ID
	add := func(ids ...key.ID) {
		for _, i := range ids {
			if !slices.Contains(scopes, i) {
				scopes = append(scopes, i)
			}
		}
	}
	add(chain(ky)...)
	if h, held := s.SpendHeld[plan]; held && op == OpExtend {
		if p := s.Plans[plan]; p != nil {
			add(p.Scopes...)
		}
		if ext, ok := s.Extended[plan]; ok {
			add(chain(ext)...)
		}
		add(h.Funding)
	}
	return &Trip{Cause: CauseHoneyKey, Exit: ExitKernel, Entry: id, Response: RespFull, Plan: plan, Scopes: scopes}
}

// rejection is decide's entry for refusing plan p with r: a trip refusal
// carries its trip, so both are one append (CH-15).
func (s *State) rejection(p *PlanState, r *key.Refusal) planRejected {
	b := planRejected{Plan: p.Plan.ID, Cause: p.Seq, Code: r.Code, Detail: r.Detail}
	if r.Code == CTrip {
		b.Trip = s.tripOf(p.Plan)
	}
	return b
}

// resumeOK checks a trip resume as a fold must: the next resume, over the
// full trip that set the pause, signed by a live passkey.
func (s *State) resumeOK(b tripResumed) bool {
	n, last, ok := s.TripResume()
	return ok && b.N == n && b.Last == last && key.In(s.Passkeys(), b.By.By) && b.By.Over(TripResumeHash(n, last))
}

// tripOK checks a trip's shape: known cause, exit and response, a table
// entry, and a session or scopes only where its response stops them. A
// plan's trip comes only in the rejection of that plan (rejected is its ID);
// a trip entry is an input, an exit's call trip only. So no recorded input,
// such as a spend.held, lets one stop a session or pause a key; a honey key
// at Extend or Issue is a trip.owner entry, derived again from its key.
func (s *State) tripOK(t Trip, rejected string) bool {
	d := &s.decoys
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
		return t.Plan != "" && t.Plan == rejected && len(t.Scopes) == 0
	case RespFull:
		return t.Plan != "" && t.Plan == rejected && t.Session == ""
	case RespCall:
		return rejected == "" && t.Session == "" && len(t.Scopes) == 0 && t.Plan == "" && t.Exit != ExitKernel
	}
	return false
}

// addTrip folds trip t, logged in entry e.
func (s *State) addTrip(t Trip, e Entry) {
	d := &s.decoys
	t.Seq, t.At = e.Seq, e.At
	if t.Response == RespFull {
		t.fresh = !d.stopped
		if d.paused == nil {
			d.paused = map[key.ID]bool{}
		}
		seen := false // any ID of the chain or its account already paused
		for _, id := range t.Scopes {
			_, ok := d.paused[id]
			seen = seen || ok
		}
		t.fresh = t.fresh || len(t.Scopes) > 0 && !seen
		for _, id := range t.Scopes {
			if _, ok := d.paused[id]; !ok {
				d.paused[id] = s.Changes.Paused[id]
			}
			s.Changes.Paused[id] = true
		}
		d.stopped = true
		if t.fresh {
			d.full = e.Seq
		}
	}
	d.log = append(d.log, t)
	if t.Session != "" {
		s.stopSession(t.Session)
	}
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
		if s.tripOK(t, "") {
			s.addTrip(t, e)
		}
	case TTripOwner:
		b, err := body[ownerTrip](e)
		if err != nil {
			return err
		}
		if t, ok := b.again(s); ok {
			s.addTrip(t, e)
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
