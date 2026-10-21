package run

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
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
)

type call struct {
	Op   string         `json:"op"`
	Req  kernel.Request `json:"req"`
	View snapshot       `json:"view"`
}

type answer struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
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
}

// view is the kernel's side: what v says of r. A plan that does not verify
// gets no grants, and a step not in flight no dispatch or uses; the clerk
// refuses either.
func view(v kernel.View, anchors []ed25519.PublicKey, r kernel.Request) snapshot {
	s := snapshot{Grants: map[key.ID]int64{}, Ledger: map[key.ID][]key.Use{}, Changes: *v.ChangesView()}
	s.Enrolled, s.Unenrolled = v.Enrollments()
	ver, err := kernel.VerifyPlan(r.Plan, kernel.PlanOwners(v, anchors, r.Plan.Key))
	if err != nil {
		return s
	}
	for _, id := range ver.IDs {
		if from, ok := v.Granted(id); ok {
			s.Grants[id] = from
		}
	}
	d, ok := v.Dispatched(r)
	if !ok {
		return s
	}
	s.Dispatch = &d
	led := v.LedgerBefore(d.Seq)
	for _, id := range ver.Scopes() {
		s.Ledger[id] = led.Uses(id)
	}
	return s
}

// The clerk's side: snapshot is a kernel.View.

func (s *snapshot) Granted(id key.ID) (int64, bool) { from, ok := s.Grants[id]; return from, ok }
func (s *snapshot) Enrollments() ([]key.Enrollment, []ed25519.PublicKey) {
	return s.Enrolled, s.Unenrolled
}
func (s *snapshot) ChangesView() *key.Changes { return &s.Changes }

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
	a, sent := c.call(opDo, r, v)
	switch {
	case !sent:
		// Nothing reached a clerk, so nothing happened: the step fails as it
		// does at a clerk the kernel does not have.
		return kernel.Result{Outcome: "failed", Detail: DUnreachable}
	case a == nil:
		return kernel.Result{Outcome: "unknown", Detail: DLost}
	}
	return kernel.Result{Outcome: one(a.Outcome, "ok", "failed"), Detail: detail(a.Detail)}
}

func (c remote) Probe(r kernel.Request, v kernel.View) string {
	if a, _ := c.call(opProbe, r, v); a != nil {
		return one(a.Outcome, "done", "notdone")
	}
	return "unknown"
}

// call sends one call and reads its answer. sent is false only when no byte
// of the call can have reached the clerk.
func (c remote) call(op string, r kernel.Request, v kernel.View) (a *answer, sent bool) {
	b, err := json.Marshal(call{op, r, view(v, c.anchors, r)})
	if err != nil {
		return nil, false
	}
	d := c.Timeout
	if d == 0 {
		d = 5 * time.Minute
	}
	conn, err := net.DialTimeout("unix", c.Socket, 10*time.Second)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != c.UID {
		return nil, false
	}
	conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, true
	}
	var ans answer
	if json.NewDecoder(io.LimitReader(conn, maxAnswer)).Decode(&ans) != nil {
		return nil, true
	}
	return &ans, true
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		serve(conn, c, anchors)
	}
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
		out.Outcome = c.Probe(in.Req, &in.View)
	case in.Op != opDo:
		return
	case !in.View.covers(anchors, in.Req):
		out = answer{"failed", DView}
	default:
		res := c.Do(in.Req, &in.View)
		out = answer{res.Outcome, res.Detail}
	}
	b, _ := json.Marshal(out)
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(append(b, '\n'))
}
