// Package guest serves the broker's guest interface (SPEC v0.12 ARC-6) to
// agent machines, one Unix socket per machine (PLAN P1-7).
//
// Each machine gets a broker-held directory holding one socket,
// broker.sock, which the runtime mounts read-only into that machine's
// sandbox and nowhere else (vm.Services). Identity therefore comes from the
// listener a request arrived on, never from anything the guest sends. The
// socket serves exactly the ARC-6 services:
//
//	/model/<adapter>/...  (a) model access: the OP-8 meter, then model egress
//	/mcp                  (b) broker tools over MCP (streamable HTTP, JSON)
//	/owner/next, /owner/reply
//	                      (c) owner messages into the guest's inbound API,
//	                          fetched by the guest's bridge, replies back
//
// (d), uncredentialed egress by data label, is not served yet: every
// machine is closed to everything else (ASSUMPTIONS.md G6).
//
// Guest configuration is defense in depth only (ARC-7): nothing here trusts
// a header, token, or body field for identity, limits, or routing.
//
// The package is not on the control path (ARC-2): STOP, STATUS, and
// admission never import it.
package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// Socket is the socket's file name inside a machine's services directory.
const Socket = "broker.sock"

// Machines is the part of the machine manager (vm.Manager) the plane uses.
type Machines interface {
	// Step takes the per-step file-system snapshot (REV-1).
	Step(ctx context.Context, id string) error
	// RaisePrivate raises a machine's label to private (REV-5).
	RaisePrivate(id string) error
	// Lineage names the machine id descends from by fork, or id itself.
	Lineage(id string) (string, error)
}

// Effects is the part of the journal engine broker tools use.
type Effects interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Dispatch(ctx context.Context, id string) (journal.Status, error)
	Get(id string) (journal.Status, error)
}

// Config configures New.
type Config struct {
	// Dir holds one directory per machine; created 0700, broker-held, and
	// never mounted whole into any guest.
	Dir      string
	Machines Machines
	Effects  Effects
	// Route picks the executor for an effect on account; false means no
	// adapter is connected for it and the request is refused.
	Route func(account string) (executor string, ok bool)
	// Label reports a machine's data label (REV-5), recorded on each
	// intent it submits. Nil, or an empty answer, records "private": an
	// unknown label is never reported as public.
	Label func(machine string) string
	// Model returns machine's model egress (the egress proxy's handler).
	// Nil answers 503: no model access.
	Model func(machine string) http.Handler
	// Meter meters every model call (OP-8). Required when Model is set:
	// model egress is never served unmetered.
	Meter *meter.Meter
	// OwnerReply receives a guest's reply to an owner message. It is
	// guest-written text: the owner channel filters it before it goes out
	// (CH-19). Nil drops replies.
	OwnerReply func(machine string, rep Reply)
	// Logf reports broker-side faults (a failed snapshot). Nil is silent.
	Logf func(format string, args ...any)
	// MaxConns caps one machine's concurrent requests; default 8.
	MaxConns int
	// MaxOpenConns caps one machine's open connections; default 16. Past
	// it the broker accepts nothing more from that machine until one
	// closes, so a guest cannot spend the broker's file descriptors (CH-2).
	MaxOpenConns int
	// StepInterval is the least time between two per-step snapshots of one
	// machine; requests inside it share one trailing snapshot. Default 2 s.
	StepInterval time.Duration
	// SubmitBurst and SubmitEvery rate-limit one machine's effect
	// requests (a token bucket); excess is refused and not journaled.
	// Defaults 20 and 3 s.
	SubmitBurst int
	SubmitEvery time.Duration
	// InboxPath keeps unanswered owner messages across broker restarts
	// (created 0600). Empty keeps them in memory only.
	InboxPath string
	// GoalQuiet ends a lineage's last owner goal once nothing has served
	// it for this long (G14); default DefaultGoalQuiet. Now is the clock.
	GoalQuiet time.Duration
	Now       func() time.Time
	// Tools are further broker tools beside effect_request and
	// effect_status (the recall tools, CAP-3). Nil offers none.
	Tools Tools
}

// Tools serves broker tools beyond effects. Identity is the machine the
// socket belongs to and its fork lineage, never anything the guest sends.
// Call reports handled=false for a name it does not serve. Its text and
// error strings go to the guest as they are.
type Tools interface {
	List() []map[string]any
	Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (text string, handled bool, err error)
}

// Plane serves every machine's socket. It implements vm.Services.
type Plane struct {
	cfg   Config
	mu    sync.Mutex
	ms    map[string]*machine
	store *store
}

type machine struct {
	id  string
	dir string
	// lineage caches the machine's fork lineage once first read (never
	// in Open: the manager calls Open holding its own lock). It outlives
	// the manager's record, which is gone before Close.
	lineage atomic.Pointer[string]
	srv     *http.Server
	ln      *limitListener
	slot    chan struct{}
	box     *inbox
	steps   stepper
	rate    bucket
	conns   atomic.Int64 // connections the server holds open
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// New checks cfg and creates Dir.
func New(cfg Config) (*Plane, error) {
	if cfg.Dir == "" || cfg.Machines == nil || cfg.Effects == nil {
		return nil, errors.New("guest: Dir, Machines, and Effects are required")
	}
	if cfg.Model != nil && cfg.Meter == nil {
		return nil, errors.New("guest: model egress needs the OP-8 meter")
	}
	if cfg.Route == nil {
		cfg.Route = func(string) (string, bool) { return "", false }
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 8
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 16
	}
	if cfg.StepInterval <= 0 {
		cfg.StepInterval = 2 * time.Second
	}
	if cfg.SubmitBurst <= 0 {
		cfg.SubmitBurst = 20
	}
	if cfg.SubmitEvery <= 0 {
		cfg.SubmitEvery = 3 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.GoalQuiet <= 0 {
		cfg.GoalQuiet = DefaultGoalQuiet
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	st, err := openStore(cfg.InboxPath)
	if err != nil {
		return nil, err
	}
	return &Plane{cfg: cfg, ms: map[string]*machine{}, store: st}, nil
}

// Open starts serving machine id and returns its services directory. It is
// called before every start or restore of the machine, and is idempotent:
// a machine that restarts keeps its socket and its inbox. A restart is a
// new incarnation of the guest, so owner messages it had fetched but not
// answered are handed out again (G5).
func (p *Plane) Open(id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", fmt.Errorf("guest: bad machine id %q", id)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if m := p.ms[id]; m != nil {
		m.box.requeue()
		return m.dir, nil
	}
	dir := filepath.Join(p.cfg.Dir, id)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, Socket))
	if err != nil {
		return "", err
	}
	m := &machine{id: id, dir: dir, slot: make(chan struct{}, p.cfg.MaxConns), box: newInbox(id, p.store)}
	m.rate = bucket{tokens: float64(p.cfg.SubmitBurst), last: time.Now()}
	m.ln = newLimitListener(l, p.cfg.MaxOpenConns)
	m.srv = &http.Server{
		Handler:           p.handler(m),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		IdleTimeout:       15 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.Background() },
		ConnState: func(_ net.Conn, st http.ConnState) {
			switch st {
			case http.StateNew:
				m.conns.Add(1)
			case http.StateClosed, http.StateHijacked:
				m.conns.Add(-1)
			}
		},
	}
	go m.srv.Serve(m.ln)
	p.ms[id] = m
	return dir, nil
}

// Close stops serving machine id, removes its directory, and drops its
// unanswered owner messages: the machine is gone. Idempotent.
func (p *Plane) Close(id string) { p.close(id, true) }

func (p *Plane) close(id string, forget bool) {
	p.mu.Lock()
	m := p.ms[id]
	delete(p.ms, id)
	p.mu.Unlock()
	if m == nil {
		return
	}
	m.steps.stop()
	m.box.close(forget)
	m.srv.Close()
	os.RemoveAll(m.dir)
	if l := m.lineage.Load(); forget && l != nil && !p.lineageOpen(*l) {
		p.store.setGoal(*l, "", time.Time{}) // the lineage is gone; so is its goal
	}
}

// shutdownWait bounds how long Shutdown waits for requests in flight.
const shutdownWait = 5 * time.Second

// Shutdown closes every machine's socket, then waits up to shutdownWait
// for requests already in flight to finish (a metered call settles the
// meter as it ends). Unanswered owner messages stay in the store for the
// next start. Stopping one machine (close) does not wait.
func (p *Plane) Shutdown() {
	p.mu.Lock()
	ms := make([]*machine, 0, len(p.ms))
	for _, m := range p.ms {
		ms = append(ms, m)
	}
	p.mu.Unlock()
	for _, m := range ms {
		p.close(m.id, false)
	}
	deadline := time.After(shutdownWait)
	for _, m := range ms {
		for i := 0; i < cap(m.slot); i++ {
			select {
			case m.slot <- struct{}{}:
			case <-deadline:
				return
			}
		}
	}
}

func (p *Plane) get(id string) *machine {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ms[id]
}

// handler is machine m's whole surface. Anything else is 404.
//
// It routes on the path exactly as the guest sent it, not through
// http.ServeMux, which cleans dot segments and empty segments with a
// redirect (a 307 that keeps the method and body since Go 1.26), so a
// guest that follows it reaches a declared shape from an undeclared one.
// Model paths go to the model chain as sent, escapes and dot segments
// included, so its shape check sees and denies them: on the box the model
// router in the vault process, or the egress proxy (E1) where it is served
// directly. Every other service needs its exact path with nothing escaped
// (ADP-10).
func (p *Plane) handler(m *machine) http.Handler {
	model := p.model(m)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case m.slot <- struct{}{}:
			defer func() { <-m.slot }()
		default:
			http.Error(w, "too many requests in flight", http.StatusTooManyRequests)
			return
		}
		if strings.HasPrefix(r.URL.EscapedPath(), "/model/") {
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/model")
			r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, "/model")
			model.ServeHTTP(w, r2)
			return
		}
		if r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/mcp":
			p.mcp(m, w, r)
		case "/owner/next":
			p.ownerNext(m, w, r)
		case "/owner/reply":
			p.ownerReply(m, w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (p *Plane) model(m *machine) http.Handler {
	if p.cfg.Model == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no model egress is configured", http.StatusServiceUnavailable)
		})
	}
	metered := p.cfg.Meter.Wrap(m.id, p.cfg.Model(m.id))
	// Each call also counts against the goal the lineage serves when it
	// arrives (G14); the meter limits by machine, task, and box only.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metered.ServeHTTP(w, r.WithContext(meter.WithGoal(r.Context(), p.goal(p.lineageOf(m)))))
	})
}

// stepper coalesces one machine's per-step snapshots (REV-1, vm V3).
type stepper struct {
	mu      sync.Mutex
	last    time.Time // when the last snapshot finished
	running bool
	pending bool // a snapshot is owed after the current one or the interval
	timer   *time.Timer
	stopped bool
	// fails counts snapshots failed in a row; reason is the latest
	// failure's; note is the agent's untold note about it (SR2-3s).
	// saved is when the last snapshot succeeded, or else when this run of
	// failures began: the owner is told the actions since then can't be
	// undone. shown is when STATUS first carried the line.
	fails  int
	reason int
	note   string
	saved  time.Time
	shown  time.Time
}

// A failed step snapshot's reason, as the machine manager's adapter
// marks it: the plane cannot import the manager (ARC-2). Anything else
// is a fault the guest learns nothing more about.
var (
	ErrStepNoRoom  = errors.New("guest: step snapshot: no room")
	ErrStepTooDeep = errors.New("guest: step snapshot: folders nest too deep")
)

const (
	stepOther = iota
	stepNoRoom
	stepTooDeep
)

// What the agent and STATUS are told of a failed step snapshot: fixed
// text per reason, never the error, so no host path, errno or size
// reaches either (SR2-3s; security R1 on #174). No room covers the
// machine's own cap and the box's disk alike, so it says nothing about
// other machines.
const (
	stepNoteNoRoom  = "The rollback point after your last effect request was not saved: there is no room for it. Delete files you no longer need; until a rollback point is saved, your steps since then can't be rolled back."
	stepNoteTooDeep = "The rollback point after your last effect request was not saved: folders in your machine nest too deep, or a path in it is too long. Flatten or delete them; until a rollback point is saved, your steps since then can't be rolled back."
	stepNoteOther   = "The rollback point after your last effect request was not saved. The broker tries again after your next effect request; until then your steps since then can't be rolled back."
	// The owner's STATUS lines take the time of the last saved rollback
	// point, in the box's local time (UX-SR23s-1, CH-12): rollback, not UNDO, which still works.
	statusNoRoom  = "Rollback: my files since %s can't be rolled back yet; they're full. I've asked for space to be freed. UNDO still works. Nothing to do unless this lasts."
	statusTooDeep = "Rollback: my files since %s can't be rolled back yet; my folders nest too deep to save. I've asked for them to be flattened. UNDO still works. Nothing to do unless this lasts."
	statusOther   = "Rollback: my files since %s can't be rolled back yet; I couldn't save them. I'll try again after my next action. UNDO still works. Nothing to do unless this lasts."
)

var (
	stepNotes    = [...]string{stepOther: stepNoteOther, stepNoRoom: stepNoteNoRoom, stepTooDeep: stepNoteTooDeep}
	stepStatuses = [...]string{stepOther: statusOther, stepNoRoom: statusNoRoom, stepTooDeep: statusTooDeep}
)

func stepReason(err error) int {
	switch {
	case errors.Is(err, ErrStepTooDeep):
		return stepTooDeep
	case errors.Is(err, ErrStepNoRoom):
		return stepNoRoom
	}
	return stepOther
}

// stepFailsShown is how many step snapshots in a row must fail before
// STATUS carries the line: one failure is told to the agent alone.
const stepFailsShown = 2

// StepNote is STATUS's line while a machine's step snapshots keep
// failing, or "". It names no machine or path (SR2-3s).
func (p *Plane) StepNote() string {
	line, _ := p.StepLine()
	return line
}

// StepLine is StepNote's line and when STATUS first carried it, for the
// digest; "" and the zero time once a snapshot succeeds.
func (p *Plane) StepLine() (string, time.Time) {
	p.mu.Lock()
	ms := make([]*machine, 0, len(p.ms))
	for _, m := range p.ms {
		ms = append(ms, m)
	}
	p.mu.Unlock()
	line, shown, latest := "", time.Time{}, time.Time{}
	for _, m := range ms {
		s := &m.steps
		s.mu.Lock()
		if s.fails >= stepFailsShown && s.last.After(latest) {
			line, shown, latest = fmt.Sprintf(stepStatuses[s.reason], s.saved.Local().Format("15:04")), s.shown, s.last
		}
		s.mu.Unlock()
	}
	return line, shown
}

// takeNote returns machine m's untold note about a failed step snapshot,
// once.
func (m *machine) takeNote() string {
	s := &m.steps
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.note
	s.note = ""
	return n
}

// step snapshots machine m after an effect request reached the journal.
// At most one snapshot runs per StepInterval: a request inside the
// interval, or while one runs, is covered by one trailing snapshot, so a
// looping guest cannot flood the snapshot store (RES-4). A failed
// snapshot is a broker fault: it is reported, and the tool result still
// goes back, since the effect it describes is already journaled.
func (p *Plane) step(m *machine) {
	s := &m.steps
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	if s.running || time.Since(s.last) < p.cfg.StepInterval {
		s.pending = true
		if !s.running && s.timer == nil {
			s.timer = time.AfterFunc(p.cfg.StepInterval-time.Since(s.last), func() { p.trailing(m) })
		}
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	p.snapshot(m)
}

func (p *Plane) trailing(m *machine) {
	s := &m.steps
	s.mu.Lock()
	s.timer = nil
	if s.stopped || s.running || !s.pending {
		s.mu.Unlock()
		return
	}
	s.pending, s.running = false, true
	s.mu.Unlock()
	p.snapshot(m)
}

// snapshot takes one snapshot, then arms the trailing one if owed.
func (p *Plane) snapshot(m *machine) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := p.cfg.Machines.Step(ctx, m.id)
	cancel()
	if err != nil {
		p.cfg.Logf("guest %s: step snapshot after tool call failed: %v", m.id, err)
	}
	s := &m.steps
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.last = false, time.Now()
	if err != nil {
		if s.fails == 0 && s.saved.IsZero() {
			s.saved = s.last // none saved this run: since the first failure
		}
		s.fails++
		if s.fails == stepFailsShown {
			s.shown = s.last
		}
		s.reason = stepReason(err)
		s.note = stepNotes[s.reason]
	} else {
		s.fails, s.saved, s.shown, s.note = 0, s.last, time.Time{}, ""
	}
	if s.pending && !s.stopped && s.timer == nil {
		s.timer = time.AfterFunc(p.cfg.StepInterval, func() { p.trailing(m) })
	}
}

func (s *stepper) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.timer != nil {
		s.timer.Stop()
	}
}

// bucket rate-limits one machine's effect requests.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *bucket) take(burst int, every time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens = min(float64(burst), b.tokens+now.Sub(b.last).Seconds()/every.Seconds())
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limitListener accepts at most n open connections; past that, Accept
// waits until one closes. Connections a guest opens beyond the limit wait
// in the kernel's queue and cost the broker no file descriptor.
type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func newLimitListener(l net.Listener, n int) *limitListener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
