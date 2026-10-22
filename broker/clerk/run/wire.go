package run

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The wire between the kernel process and a clerk process: one connection per
// call, one JSON call from the kernel, one JSON answer from the clerk. The
// call carries the request and the log's view of it, so the clerk checks the
// step itself (CLK-2) and sees the log only through the kernel (STO-3), with
// no further I/O to the kernel while it acts. Each side admits only the
// other's uid (SO_PEERCRED).

const (
	opDo    = "do"
	opProbe = "probe"

	maxCall   = 4 << 20
	maxAnswer = 64 << 10
	maxDetail = 256

	// Kernel-side details for a call that never reached a clerk.
	DUnreachable = "unreachable" // no clerk listening, or the wrong uid on the socket; nothing sent
	DLost        = "lost"        // the call was sent and no answer came back
	DView        = "view"        // the call's view does not cover the step; nothing sent
	DTooLarge    = "too-large"   // the call is past what a clerk reads (maxCall); nothing sent
)

type call struct {
	Op   string         `json:"op"`
	Req  kernel.Request `json:"req"`
	View snapshot       `json:"view"`
}

type answer struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Covered string `json:"covered,omitempty"` // the kernel's fold bounds it (kernel.MaxShown)
}

// snapshot is the log's view of one request, as of the call: everything
// clerk.Check reads, for this request's chain only.
type snapshot struct {
	Dispatch   *kernel.Dispatch     `json:"dispatch"` // nil: the step is not in flight
	Grants     map[key.ID]int64     `json:"grants"`   // grant live-from, per chain ID granted
	Enrolled   []key.Enrollment     `json:"enrolled"`
	Unenrolled []ed25519.PublicKey  `json:"unenrolled"`
	Changes    key.Changes          `json:"changes"`
	Ledger     map[key.ID][]key.Use `json:"ledger"` // uses before the dispatch, per scope
	// OneOffLines is the most a one-off under the chain's root may spend
	// alone, as of the call on the kernel's clock (kernel.OneOff). A root it
	// does not name has line 0: any spend needs a second passkey.
	OneOffLines map[key.ID]int64 `json:"one_off_lines"`
	// Served is the task the chain serves, live as of the call (nil: none or
	// ended); the clerk judges its timeout on its own clock (KRN-5).
	Served *kernel.Task `json:"task"`
}

// view is the kernel's side: what v says of r. A plan that does not verify
// gets no grants, and a step not in flight no dispatch or uses; the clerk
// refuses either. It shares nothing with v, since Tick sends it outside the
// kernel's lock while STOP, a revoke or a pause changes v.
func view(v kernel.View, anchors []ed25519.PublicKey, r kernel.Request, now int64) snapshot {
	c := v.ChangesView()
	s := snapshot{Grants: map[key.ID]int64{}, Ledger: map[key.ID][]key.Use{}, OneOffLines: map[key.ID]int64{},
		Changes: key.Changes{Revoked: maps.Clone(c.Revoked), Paused: maps.Clone(c.Paused), Stopped: c.Stopped}}
	es, un := v.Enrollments()
	s.Enrolled, s.Unenrolled = slices.Clone(es), slices.Clone(un)
	ver, err := kernel.VerifyPlan(r.Plan, kernel.PlanOwners(v, anchors, r.Plan.Key))
	if err != nil {
		return s
	}
	for _, id := range ver.IDs {
		if from, ok := v.Granted(id); ok {
			s.Grants[id] = from
		}
	}
	s.OneOffLines[ver.Root()] = v.OneOffLine(ver.Root(), now)
	if t, ok := v.Task(ver.Limits.Task, now); ok {
		s.Served = &t
	}
	d, ok := v.Dispatched(r)
	if !ok {
		return s
	}
	s.Dispatch = &d
	led := v.LedgerBefore(d.Seq)
	for _, id := range ver.Scopes() {
		s.Ledger[id] = needed(led.Uses(id), ver.Limits.Caps, id, r.Step().Task, now)
	}
	return s
}

// viewSkew is how far the clerk's clock may run behind the kernel's within
// one call and still find every use its day window counts.
const viewSkew = 10 * 60_000

// needed bounds a scope's uses to those the chain's caps on it can count at
// now (#2700 item 3): a day cap's day, with viewSkew to spare, a task cap's
// task, and a use cap's newest N, which is all of them while fewer than N
// exist. Each cap filters its own uses again in the clerk's check, so the
// check reads the same as on the whole ledger, and the view grows with the
// caps, not with the log's age. A scope with no cap gets an empty list,
// which still covers it.
func needed(all []key.Use, caps []key.Cap, scope key.ID, task string, now int64) []key.Use {
	keep := make([]bool, len(all))
	for _, cp := range caps {
		if cp.Scope != scope {
			continue
		}
		for i, u := range all {
			switch cp.Kind {
			case key.KSpendDay, key.KRateDay, key.KRateRecipient:
				keep[i] = keep[i] || u.At > now-key.DayMS-viewSkew
			case key.KSpendTask:
				keep[i] = keep[i] || u.Task == task
			case key.KUses:
				keep[i] = keep[i] || int64(len(all)-i) <= cp.N
			}
		}
	}
	out := []key.Use{}
	for i, u := range all {
		if keep[i] {
			out = append(out, u)
		}
	}
	return out
}

// The clerk's side: snapshot is a kernel.View.

func (s *snapshot) Granted(id key.ID) (int64, bool) { from, ok := s.Grants[id]; return from, ok }
func (s *snapshot) Enrollments() ([]key.Enrollment, []ed25519.PublicKey) {
	return s.Enrolled, s.Unenrolled
}
func (s *snapshot) ChangesView() *key.Changes { return &s.Changes }

// OneOffLine answers as of the call, whatever now the clerk asks at.
func (s *snapshot) OneOffLine(root key.ID, _ int64) int64 { return s.OneOffLines[root] }

// Task answers for the chain's task only, while now is before its timeout.
func (s *snapshot) Task(id string, now int64) (kernel.Task, bool) {
	if s.Served == nil || s.Served.ID != id || now >= s.Served.Until {
		return kernel.Task{}, false
	}
	return *s.Served, true
}

// LedgerBefore answers only for the dispatch the snapshot was taken at.
func (s *snapshot) LedgerBefore(seq uint64) key.Ledger {
	if s.Dispatch == nil || seq != s.Dispatch.Seq {
		return uses(nil)
	}
	return uses(s.Ledger)
}

func (s *snapshot) Dispatched(kernel.Request) (kernel.Dispatch, bool) {
	if s.Dispatch == nil {
		return kernel.Dispatch{}, false
	}
	return *s.Dispatch, true
}

type uses map[key.ID][]key.Use

func (u uses) Uses(id key.ID) []key.Use { return u[id] }

// covers reports whether s carries the ledger for every scope the request's
// chain charges, checked the way clerk.Check verifies it. A view that leaves
// one out would read as unspent, so the clerk refuses rather than act on it.
// A plan that does not verify here fails clerk.Check anyway.
func (s *snapshot) covers(anchors []ed25519.PublicKey, r kernel.Request) bool {
	if s.Dispatch == nil {
		return true
	}
	ver, err := kernel.VerifyPlan(r.Plan, kernel.PlanOwners(s, anchors, r.Plan.Key))
	if err != nil {
		return true
	}
	for _, id := range ver.Scopes() {
		if _, ok := s.Ledger[id]; !ok {
			return false
		}
	}
	return true
}

// Remote is how the kernel process reaches one clerk process.
type Remote struct {
	Socket  string        // the clerk's socket
	UID     int           // the clerk's uid: the only peer the kernel sends to
	Timeout time.Duration // for the whole call; 0 is five minutes
}

// remote is a Remote as a kernel.Clerk.
type remote struct {
	Remote
	anchors []ed25519.PublicKey
}

func (c remote) Do(r kernel.Request, v kernel.View) kernel.Result {
	return c.do(r, view(v, c.anchors, r, time.Now().UnixMilli()))
}

func (c remote) Probe(r kernel.Request, v kernel.View) kernel.Result {
	return c.probe(r, view(v, c.anchors, r, time.Now().UnixMilli()))
}

// do and probe make a call with a view taken under the kernel's lock, so the
// call itself runs without it (KRN-7).
func (c remote) do(r kernel.Request, s snapshot) kernel.Result {
	a, sent, big := c.call(opDo, r, s)
	switch {
	case big:
		// The clerk would read only part of it, so it was never sent and
		// nothing happened: a typed failure, not a lost answer.
		return kernel.Result{Outcome: "failed", Detail: DTooLarge}
	case !sent:
		// Nothing reached the clerk, so nothing happened: the kernel sends
		// it again after a wait (kernel.OUnsent).
		return kernel.Result{Outcome: kernel.OUnsent, Detail: DUnreachable}
	case a == nil:
		return kernel.Result{Outcome: "unknown", Detail: DLost}
	}
	return kernel.Result{Outcome: one(a.Outcome, "ok", "failed"), Detail: detail(a.Detail), Covered: a.Covered}
}

func (c remote) probe(r kernel.Request, s snapshot) kernel.Result {
	a, sent, big := c.call(opProbe, r, s)
	switch {
	case big:
		// The view outgrew what the clerk reads: no probe can ever be
		// sent, so each counts a check and the step parks with its
		// warning, rather than probing forever (#2742 item 8).
		return kernel.Result{Outcome: "unknown"}
	case !sent:
		return kernel.Result{Outcome: kernel.OUnreached} // no check was made, so none counts
	case a == nil:
		return kernel.Result{Outcome: "unknown"}
	}
	return kernel.Result{Outcome: one(a.Outcome, "done", "notdone"), Covered: a.Covered}
}

// call sends one call and reads its answer. sent is false only when no byte
// of the call can have reached the clerk. big is true for a call past
// maxCall, which the clerk would read only part of, so it is not sent
// (#2708 item 1).
func (c remote) call(op string, r kernel.Request, s snapshot) (a *answer, sent, big bool) {
	b, err := json.Marshal(call{op, r, s})
	if err != nil {
		return nil, false, false
	}
	if len(b)+1 > maxCall {
		return nil, false, true
	}
	d := c.Timeout
	if d == 0 {
		d = 5 * time.Minute
	}
	conn, err := net.DialTimeout("unix", c.Socket, 10*time.Second)
	if err != nil {
		return nil, false, false
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != c.UID {
		return nil, false, false
	}
	conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, true, false
	}
	var ans answer
	if json.NewDecoder(io.LimitReader(conn, maxAnswer)).Decode(&ans) != nil {
		return nil, true, false
	}
	return &ans, true, false
}

// one is outcome when it is one of ok, else unknown.
func one(outcome string, ok ...string) string {
	for _, o := range ok {
		if outcome == o {
			return o
		}
	}
	return "unknown"
}

// detail is what the kernel logs of a clerk's detail: bounded, valid UTF-8
// with no control characters, since STATUS shows it to the owner.
func detail(s string) string {
	if len(s) > maxDetail || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return "malformed"
	}
	return s
}

// ListenClerk opens a clerk's socket, admitting only the kernel's uid.
func ListenClerk(path string, kernelUID int) (net.Listener, error) {
	return sockets.ListenPeers(path, kernelUID)
}

// ServeClerk answers the kernel's calls to c on ln, one at a time, until ln
// closes. anchors are the clerk's own (D-146).
func ServeClerk(ln net.Listener, c kernel.Clerk, anchors []ed25519.PublicKey) error {
	return serveConns(ln, 1, func(conn net.Conn) { serve(conn, c, anchors) })
}

func serve(conn net.Conn, c kernel.Clerk, anchors []ed25519.PublicKey) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var in call
	if json.NewDecoder(io.LimitReader(conn, maxCall)).Decode(&in) != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	var out answer
	switch {
	case in.Op == opProbe:
		res := c.Probe(in.Req, &in.View)
		out = answer{Outcome: res.Outcome, Covered: res.Covered}
	case in.Op != opDo:
		return
	case !in.View.covers(anchors, in.Req):
		out = answer{Outcome: "failed", Detail: DView}
	default:
		res := c.Do(in.Req, &in.View)
		out = answer{res.Outcome, res.Detail, res.Covered}
	}
	b, _ := json.Marshal(out)
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(append(b, '\n'))
}
