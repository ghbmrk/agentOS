package run

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The kernel process's sockets (MIG-4-run slice 3): the frozen seam
// (docs/LANES.md) served to the processes outside it. Each socket admits one
// uid and serves one side's closed table of calls, so the owner side cannot
// meter spend and the model clerk cannot STOP, issue or extend: a call a
// side's table lacks is refused and logs nothing. One connection carries one
// call, {op, args}, answered {result} or {refusal} or {error}. Every call
// runs under the kernel's one lock at the kernel process's own clock, never
// a time the caller gives, so no caller can date a use outside a cap's
// window. A read is encoded under the lock, so what crosses the socket is a
// copy and the caller holds nothing of the live state (#2706 Security).

const maxKernelAnswer = 4 << 20

// Side is one caller's closed table of the seam's calls.
type Side struct {
	name string
	ops  map[string]op
}

type op func(k *kernel.Kernel, now int64, args json.RawMessage) (any, error)

type kernelCall struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

type kernelAnswer struct {
	Result  json.RawMessage `json:"result,omitempty"`
	Refusal *key.Refusal    `json:"refusal,omitempty"`
	Error   string          `json:"error,omitempty"`
	Is      string          `json:"is,omitempty"` // the wireErrors sentinel Error wraps, if any
}

// act is a call that changes the log, made with its decoded arguments.
func act[A any](f func(k *kernel.Kernel, now int64, a A) error) op {
	return func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, errArgs
		}
		return nil, f(k, now, a)
	}
}

// read is a call that changes nothing.
func read[A, R any](f func(s *kernel.State, now int64, a A) R) op {
	return func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, errArgs
		}
		return f(k.State(), now, a), nil
	}
}

// refusal is r as an error, nil when r is.
func refusal(r *key.Refusal) error {
	if r == nil {
		return nil
	}
	return r
}

var errArgs = errors.New("run: the call's arguments do not decode")

type (
	stepArgs struct {
		Plan  string `json:"plan"`
		Index int    `json:"index"`
	}
	issueArgs struct {
		Cosigns []key.Cosign `json:"cosigns"`
		Keys    []key.Key    `json:"keys"`
	}
	lineArgs struct {
		Percent int64        `json:"percent"`
		Cosigns []key.Cosign `json:"cosigns"`
	}
	extendArgs struct {
		Ext  key.Key `json:"ext"`
		Plan string  `json:"plan"`
	}
	poolArgs struct {
		Pool    string `json:"pool"`
		Reserve int64  `json:"reserve,omitempty"`
		Used    int64  `json:"used,omitempty"`
		ResetAt int64  `json:"reset_at,omitempty"`
	}
	approveArgs struct {
		Task     string              `json:"task"`
		Approval kernel.TaskApproval `json:"approval"`
	}
	spendArgs struct {
		Plan   string       `json:"plan"`
		Seq    uint64       `json:"seq,omitempty"` // the admission a meter settles
		Route  string       `json:"route,omitempty"`
		Amount int64        `json:"amount"`
		Source string       `json:"source,omitempty"`
		Rf     *key.Refusal `json:"refusal,omitempty"`
	}
	enrolled struct {
		Enrolled   []key.Enrollment    `json:"enrolled"`
		Unenrolled []ed25519.PublicKey `json:"unenrolled"`
	}
	taskRead struct {
		Task *kernel.Task `json:"task"` // nil: not live
	}
	planRead struct {
		Status string   `json:"status"` // "": no such plan
		Phases []string `json:"phases"`
	}
	grantRead struct {
		From int64 `json:"from"`
		OK   bool  `json:"ok"`
	}
	none struct{}
)

// OwnerSide is the owner side's table (sub B: owner, localui, localsrv,
// control, question, cmd/agentosd): the owner seam's actions and its reads.
var OwnerSide = Side{"owner", map[string]op{
	"submit": act(func(k *kernel.Kernel, now int64, p kernel.Plan) error { return k.Submit(now, p) }),
	"retry":  act(func(k *kernel.Kernel, now int64, a stepArgs) error { return k.Retry(now, a.Plan, a.Index) }),
	"cancel": act(func(k *kernel.Kernel, now int64, a stepArgs) error { return k.Cancel(now, a.Plan) }),
	"undo":   act(func(k *kernel.Kernel, now int64, a stepArgs) error { return k.Undo(now, a.Plan, a.Index) }),
	"enroll": act(func(k *kernel.Kernel, now int64, e key.Enrollment) error { return k.Enroll(now, e) }),
	"unenroll": act(func(k *kernel.Kernel, now int64, pk ed25519.PublicKey) error {
		return k.Unenroll(now, pk)
	}),
	"extend":  act(func(k *kernel.Kernel, now int64, a extendArgs) error { return k.Extend(now, a.Ext, a.Plan) }),
	"setline": act(func(k *kernel.Kernel, now int64, a lineArgs) error { return k.SetLine(now, a.Percent, a.Cosigns...) }),
	"reserve": act(func(k *kernel.Kernel, now int64, a poolArgs) error { return k.Reserve(now, a.Pool, a.Reserve) }),
	"issue":   act(func(k *kernel.Kernel, now int64, a issueArgs) error { return k.Issue(now, a.Cosigns, a.Keys...) }),
	"approvetask": act(func(k *kernel.Kernel, now int64, a approveArgs) error {
		return k.ApproveTask(now, a.Task, a.Approval)
	}),
	"revoke":  act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Revoke(now, id) }),
	"pause":   act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Pause(now, id) }),
	"unpause": act(func(k *kernel.Kernel, now int64, id key.ID) error { return k.Unpause(now, id) }),
	"stop":    act(func(k *kernel.Kernel, now int64, _ none) error { return k.Stop(now) }),
	"resume":  act(func(k *kernel.Kernel, now int64, _ none) error { return k.Resume(now) }),

	"status":      read(func(s *kernel.State, _ int64, _ none) []kernel.Unsettled { return s.Status() }),
	"linechanges": read(func(s *kernel.State, _ int64, _ none) int { return s.LineChanges() }),
	"spendheld":   read(func(s *kernel.State, _ int64, _ none) map[string]kernel.SpendHold { return s.SpendHeld }),
	"pools":       read(func(s *kernel.State, _ int64, _ none) map[string]kernel.Pool { return s.Pools }),
	"enrollments": read(func(s *kernel.State, _ int64, _ none) enrolled {
		es, un := s.Enrollments()
		return enrolled{es, un}
	}),
	"changes": read(func(s *kernel.State, _ int64, _ none) key.Changes { return *s.ChangesView() }),
	"plan": read(func(s *kernel.State, _ int64, id string) planRead {
		p := s.Plans[id]
		if p == nil {
			return planRead{}
		}
		r := planRead{Status: p.Status}
		for _, st := range p.Steps {
			r.Phases = append(r.Phases, st.Phase)
		}
		return r
	}),
	"granted": read(func(s *kernel.State, _ int64, id key.ID) grantRead {
		from, ok := s.Granted(id)
		return grantRead{from, ok}
	}),
	"task": read(func(s *kernel.State, now int64, id string) taskRead {
		if t, ok := s.Task(id, now); ok {
			return taskRead{&t}
		}
		return taskRead{}
	}),
}}

// MeterSide is the model clerk's table (clerk/model, #2572): the metering
// seam and nothing else.
var MeterSide = Side{"meter", map[string]op{
	"admitspend": func(k *kernel.Kernel, now int64, raw json.RawMessage) (any, error) {
		var a spendArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, errArgs
		}
		ad, r := k.AdmitSpend(now, a.Plan, a.Amount)
		if r != nil {
			return nil, r
		}
		return ad, nil
	},
	"meter": act(func(k *kernel.Kernel, now int64, a spendArgs) error {
		return k.Meter(now, kernel.Admitted{Plan: a.Plan, Seq: a.Seq}, a.Route, a.Amount, a.Source)
	}),
	"hold":      act(func(k *kernel.Kernel, now int64, a spendArgs) error { return k.Hold(now, a.Plan, a.Rf) }),
	"admitpool": act(func(k *kernel.Kernel, now int64, a poolArgs) error { return refusal(k.AdmitPool(now, a.Pool)) }),
	"readpool": act(func(k *kernel.Kernel, now int64, a poolArgs) error {
		return k.ReadPool(now, a.Pool, a.Used, a.ResetAt)
	}),
}}

// ListenKernel opens one side's socket on the kernel process, admitting only
// that side's uid.
func ListenKernel(path string, uid int) (net.Listener, error) {
	return sockets.ListenPeers(path, uid)
}

// ServeKernel answers side's calls to h on ln until ln closes, each on its
// own connection, so a slow caller never delays STOP; the kernel's lock
// orders them. clock is the kernel process's.
func ServeKernel(ln net.Listener, h *Kernel, side Side, clock func() int64) error {
	return serveConns(ln, maxConns, func(conn net.Conn) { serveKernel(conn, h, side, clock) })
}

// maxConns bounds the calls one socket serves at once. More wait in the
// listener's backlog, holding none of the process's descriptors, so a side
// that floods its own socket cannot starve another side's (KRN-7).
const maxConns = 16

// serveConns runs handle on each connection ln accepts, at most n at once,
// until ln closes. Any other accept error (no descriptor free, a connection
// aborted) is waited out, never the end of the socket, so the owner's STOP
// still lands once a flood ends.
func serveConns(ln net.Listener, n int, handle func(net.Conn)) error {
	slots := make(chan struct{}, n)
	wait := 5 * time.Millisecond
	for {
		slots <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(wait)
			wait = min(2*wait, time.Second)
			continue
		}
		wait = 5 * time.Millisecond
		go func() {
			defer func() { <-slots }()
			handle(conn)
		}()
	}
}

func serveKernel(conn net.Conn, h *Kernel, side Side, clock func() int64) {
	serveOne(conn, func(name string, args json.RawMessage) (out json.RawMessage, err error) {
		f, ok := side.ops[name]
		if !ok {
			return nil, errors.New("run: the " + side.name + " socket has no call " + name)
		}
		err = h.With(func(k *kernel.Kernel) error {
			res, err := f(k, clock(), args)
			if err == nil && res != nil {
				// Encoded under the lock: the caller gets a copy.
				out, err = json.Marshal(res)
			}
			return err
		})
		return out, err
	})
}

// serveOne answers the one call on conn with handle's result.
func serveOne(conn net.Conn, handle func(op string, args json.RawMessage) (json.RawMessage, error)) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var in kernelCall
	if json.NewDecoder(io.LimitReader(conn, maxCall)).Decode(&in) != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	var out kernelAnswer
	res, err := handle(in.Op, in.Args)
	var rf *key.Refusal
	switch {
	case err == nil:
		out.Result = res
	case errors.As(err, &rf):
		out.Refusal = rf
		if rf == nil || rf.Code == "" {
			out.Refusal, out.Error = nil, "run: a refusal with no code"
		}
	case err.Error() != "":
		out.Error = err.Error()
		for _, e := range wireList {
			if errors.Is(err, e) {
				out.Is = e.Error()
				break
			}
		}
	default:
		// Never an empty answer, which would read as success.
		out.Error = "run: an error with no text"
	}
	b, _ := json.Marshal(out)
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(append(b, '\n'))
}

// ErrLost is a call whose answer never came: it may or may not have taken
// effect. The owner side reads the state the call would change (Changes,
// Plan, Granted, SpendHeld, LineChanges, Pools, Enrollments, Task) before
// acting again; a read can simply be made again.
var ErrLost = errors.New("run: the answer was lost; it may or may not have taken effect")

// ErrUnreachable is a call that was never sent: no process listens on the
// socket, or another uid holds it.
var ErrUnreachable = errors.New("run: the socket could not be reached; nothing was sent")

// ErrTooLarge is a call past what the socket reads (maxCall): it was never
// sent.
var ErrTooLarge = errors.New("run: the call is too large for the socket; nothing was sent")

// wireErrors are the errors a socket's answer names by their text, so the
// caller gets the same value back and errors.Is works across the socket,
// also for an error that wraps one (kernel.ErrRetryRefused with its code):
// that crosses with its own text, naming the sentinel it wraps. Any other
// error crosses as its text alone.
var (
	wireList   []error
	wireErrors = map[string]error{}
)

func init() {
	wireList = []error{
		kernel.ErrDuplicatePlan, kernel.ErrRetryRefused, kernel.ErrNeedsCosign, kernel.ErrLine, kernel.ErrNotEnrolled, kernel.ErrNotParked,
		kernel.ErrNotText, kernel.ErrNotAGrant, kernel.ErrLife, kernel.ErrTask, kernel.ErrTaskOpen, kernel.ErrTaskApproval,
		kernel.ErrBroken, kernel.ErrNotAdmitted, key.ErrMalformed, key.ErrWrongOwner, key.ErrBadSig, key.ErrLoosens, key.ErrNotHolder,
		key.ErrUnknownKind, key.ErrUncaveated, errArgs, ErrModelCall, ErrNoMailAccount,
		ErrMailAddress, ErrMailServer, ErrMailUser, ErrWeakMailPassword, ErrBadGrant, ErrNoReconnect,
	}
	for _, e := range wireList {
		wireErrors[e.Error()] = e
	}
}

// wrapped is an error that crossed a socket wrapping a wireErrors sentinel.
type wrapped struct {
	text string
	is   error
}

func (w wrapped) Error() string { return w.text }
func (w wrapped) Unwrap() error { return w.is }

// Conn is how a process reaches a socket of the kernel's process or of the
// model clerk's.
type Conn struct {
	Socket  string
	UID     int           // the serving process's uid: the only peer it calls
	Timeout time.Duration // for the whole call; 0 is one minute
}

// call makes one call; out, when not nil, receives its result.
func (c Conn) call(op string, args, out any) error {
	b, err := json.Marshal(kernelCall{op, mustRaw(args)})
	if err != nil {
		return err
	}
	if len(b)+1 > maxCall {
		// The server would read only part of it, and the call would
		// read as lost though it was never taken (#2742 item 9).
		return ErrTooLarge
	}
	d := c.Timeout
	if d == 0 {
		d = time.Minute
	}
	conn, err := net.DialTimeout("unix", c.Socket, 10*time.Second)
	if err != nil {
		return ErrUnreachable
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != c.UID {
		return ErrUnreachable
	}
	conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrLost
	}
	var a kernelAnswer
	if json.NewDecoder(io.LimitReader(conn, maxKernelAnswer)).Decode(&a) != nil {
		return ErrLost
	}
	switch {
	case a.Refusal != nil:
		return a.Refusal
	case a.Error != "":
		if e, ok := wireErrors[a.Error]; ok {
			return e
		}
		if e, ok := wireErrors[a.Is]; ok {
			return wrapped{a.Error, e}
		}
		return errors.New(a.Error)
	case out != nil:
		return json.Unmarshal(a.Result, out)
	}
	return nil
}

func mustRaw(v any) json.RawMessage {
	if v == nil {
		v = none{}
	}
	b, _ := json.Marshal(v)
	return b
}

// asRefusal is err as the *key.Refusal it carries, nil when it carries none
// (a lost answer or a broken socket refuses with CBroken, so no metered call
// starts on a ledger it could not reach).
func asRefusal(err error) *key.Refusal {
	if err == nil {
		return nil
	}
	var rf *key.Refusal
	if errors.As(err, &rf) {
		return rf
	}
	return &key.Refusal{Code: kernel.CBroken, Detail: err.Error()}
}

// Owner is the owner seam over the kernel process's owner socket.
type Owner struct{ Conn }

func (o Owner) Submit(p kernel.Plan) error { return o.call("submit", p, nil) }
func (o Owner) Retry(plan string, index int) error {
	return o.call("retry", stepArgs{plan, index}, nil)
}
func (o Owner) Cancel(plan string) error { return o.call("cancel", stepArgs{Plan: plan}, nil) }
func (o Owner) Undo(plan string, index int) error {
	return o.call("undo", stepArgs{plan, index}, nil)
}
func (o Owner) Enroll(e key.Enrollment) error       { return o.call("enroll", e, nil) }
func (o Owner) Unenroll(pk ed25519.PublicKey) error { return o.call("unenroll", pk, nil) }
func (o Owner) Extend(ext key.Key, plan string) error {
	return o.call("extend", extendArgs{ext, plan}, nil)
}
func (o Owner) SetLine(percent int64, cos ...key.Cosign) error {
	return o.call("setline", lineArgs{percent, cos}, nil)
}
func (o Owner) Reserve(pool string, reserve int64) error {
	return o.call("reserve", poolArgs{Pool: pool, Reserve: reserve}, nil)
}
func (o Owner) Issue(cos []key.Cosign, keys ...key.Key) error {
	return o.call("issue", issueArgs{cos, keys}, nil)
}
func (o Owner) ApproveTask(id string, a kernel.TaskApproval) error {
	return o.call("approvetask", approveArgs{id, a}, nil)
}
func (o Owner) Revoke(id key.ID) error  { return o.call("revoke", id, nil) }
func (o Owner) Pause(id key.ID) error   { return o.call("pause", id, nil) }
func (o Owner) Unpause(id key.ID) error { return o.call("unpause", id, nil) }
func (o Owner) Stop() error             { return o.call("stop", nil, nil) }
func (o Owner) Resume() error           { return o.call("resume", nil, nil) }

func (o Owner) Status() (u []kernel.Unsettled, err error) { err = o.call("status", nil, &u); return }
func (o Owner) LineChanges() (n int, err error)           { err = o.call("linechanges", nil, &n); return }
func (o Owner) SpendHeld() (m map[string]kernel.SpendHold, err error) {
	err = o.call("spendheld", nil, &m)
	return
}
func (o Owner) Pools() (m map[string]kernel.Pool, err error) { err = o.call("pools", nil, &m); return }
func (o Owner) Enrollments() ([]key.Enrollment, []ed25519.PublicKey, error) {
	var e enrolled
	err := o.call("enrollments", nil, &e)
	return e.Enrolled, e.Unenrolled, err
}

// Changes is the revocations, pauses and STOP in force.
func (o Owner) Changes() (c key.Changes, err error) { err = o.call("changes", nil, &c); return }

// Plan is plan id's status and its steps' phases; ok is false when the log
// has no such plan.
func (o Owner) Plan(id string) (status string, phases []string, ok bool, err error) {
	var r planRead
	err = o.call("plan", id, &r)
	return r.Status, r.Phases, r.Status != "", err
}

// Granted is when key id's grant is live from, if it is granted.
func (o Owner) Granted(id key.ID) (from int64, ok bool, err error) {
	var r grantRead
	err = o.call("granted", id, &r)
	return r.From, r.OK, err
}

// Task is task id while it is live on the kernel's clock.
func (o Owner) Task(id string) (kernel.Task, bool, error) {
	var t taskRead
	if err := o.call("task", id, &t); err != nil || t.Task == nil {
		return kernel.Task{}, false, err
	}
	return *t.Task, true, nil
}

// Meter is the metering seam over the kernel process's meter socket: a
// model.Ledger for the model clerk's process. The now each method takes is
// ignored, since the kernel's clock decides. A lost Meter answer is retried
// by the clerk (model.Clerk owes it); the kernel settles an admission once,
// so a retry of one that landed is refused (kernel.ErrNotAdmitted) and the
// clerk counts it recorded.
type Meter struct{ Conn }

func (m Meter) AdmitSpend(_ int64, plan string, amount int64) (kernel.Admitted, *key.Refusal) {
	var a kernel.Admitted
	if r := asRefusal(m.call("admitspend", spendArgs{Plan: plan, Amount: amount}, &a)); r != nil {
		return kernel.Admitted{}, r
	}
	return a, nil
}
func (m Meter) Meter(_ int64, a kernel.Admitted, route string, amount int64, source string) error {
	return m.call("meter", spendArgs{Plan: a.Plan, Seq: a.Seq, Route: route, Amount: amount, Source: source}, nil)
}
func (m Meter) Hold(_ int64, plan string, rf *key.Refusal) error {
	return m.call("hold", spendArgs{Plan: plan, Rf: rf}, nil)
}
func (m Meter) AdmitPool(_ int64, pool string) *key.Refusal {
	return asRefusal(m.call("admitpool", poolArgs{Pool: pool}, nil))
}
func (m Meter) ReadPool(_ int64, pool string, used, resetAt int64) error {
	return m.call("readpool", poolArgs{Pool: pool, Used: used, ResetAt: resetAt}, nil)
}
