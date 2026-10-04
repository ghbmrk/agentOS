// Package meter is the broker's model-spend meter (SPEC v0.12 OP-8).
//
// Every model call a guest makes passes the meter before it reaches model
// egress. The meter charges the call to the machine it arrived from, which
// the caller knows from the listener the request came in on (never from
// anything the guest sends, CRED-1): to the machine's task reservation when
// a task is bound, otherwise to the machine's rolling cap; and always to the
// box-wide overall cap. Counts are the broker's own observation: one call
// per request, and tokens estimated from the bytes the broker saw going in
// and coming out (Tokens). Provider- or guest-reported usage is never read.
// On exhaustion further calls are refused and the owner is told once
// (Notify); the owner may extend one task within a daily ceiling that the
// extension itself cannot raise. Usage is written to disk on every change,
// so restarting the broker does not reset a looping guest's budget.
//
// The meter holds no credential and makes no network call.
package meter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Limits is an amount of model use: calls and tokens.
type Limits struct {
	Calls  int64 `json:"calls"`
	Tokens int64 `json:"tokens"`
}

func (l Limits) add(o Limits) Limits { return Limits{l.Calls + o.Calls, l.Tokens + o.Tokens} }

// over reports whether charging one more call carrying in tokens to used
// would pass cap.
func over(used, cap Limits, in int64) bool {
	return used.Calls+1 > cap.Calls || used.Tokens+in > cap.Tokens
}

// Scopes a limit applies at.
const (
	ScopeTask    = "task"
	ScopeMachine = "machine"
	ScopeOverall = "overall"
)

// Exhausted tells the owner that a limit stopped a machine's model calls.
// The owner channel renders it in CH-12 form.
type Exhausted struct {
	Scope   string
	Machine string
	Task    string // set for ScopeTask
	Used    Limits
	Limit   Limits
}

var (
	// ErrExhausted: the call would pass a limit; it is refused, not queued.
	ErrExhausted = errors.New("meter: model spend limit reached")
	// ErrCeiling: an extension would pass the owner's daily ceiling.
	ErrCeiling = errors.New("meter: daily extension ceiling reached")
)

// Defaults until the numeric targets are frozen before A4. They are
// deliberately small: a guest that hits them waits for the owner.
var (
	DefaultMachineCap     = Limits{Calls: 300, Tokens: 3_000_000}
	DefaultOverallCap     = Limits{Calls: 1500, Tokens: 15_000_000}
	DefaultDailyExtension = Limits{Calls: 300, Tokens: 3_000_000}
)

// Config configures Open. MachineCap and OverallCap must be set in full:
// there is no unlimited setting.
type Config struct {
	Path           string        // durable state; created 0600
	MachineCap     Limits        // per machine per Window, when no task is bound
	OverallCap     Limits        // whole box per Window
	DailyExtension Limits        // most the owner may extend tasks by per day
	Window         time.Duration // rolling window; default 24 h
	MaxBody        int64         // Wrap's request body cap; default 8 MiB
	Notify         func(Exhausted)
	Now            func() time.Time
}

// slots is how many buckets a window is split into.
const slots = 24

type bucket struct {
	Start int64  `json:"start"` // unix seconds
	Use   Limits `json:"use"`
}

type task struct {
	Reserved Limits `json:"reserved"`
	Extended Limits `json:"extended"`
	Used     Limits `json:"used"`
}

type state struct {
	Machines map[string][]bucket `json:"machines"`
	Overall  []bucket            `json:"overall"`
	Tasks    map[string]*task    `json:"tasks"`
	Bound    map[string]string   `json:"bound"`    // machine -> task
	Ext      map[string]Limits   `json:"ext"`      // UTC day -> extensions granted
	Notified map[string]bool     `json:"notified"` // scope:subject already told
}

// Meter is safe for concurrent use.
type Meter struct {
	cfg  Config
	slot int64
	mu   sync.Mutex
	st   state
}

// Open loads (or creates) the meter's state.
func Open(cfg Config) (*Meter, error) {
	if cfg.Path == "" {
		return nil, errors.New("meter: state path required")
	}
	for _, l := range []Limits{cfg.MachineCap, cfg.OverallCap} {
		if l.Calls <= 0 || l.Tokens <= 0 {
			return nil, errors.New("meter: machine and overall caps must limit both calls and tokens")
		}
	}
	if cfg.Window <= 0 {
		cfg.Window = 24 * time.Hour
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 8 << 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Notify == nil {
		cfg.Notify = func(Exhausted) {}
	}
	m := &Meter{cfg: cfg, slot: int64(cfg.Window/time.Second) / slots}
	if m.slot < 1 {
		m.slot = 1
	}
	b, err := os.ReadFile(cfg.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &m.st); err != nil {
			return nil, fmt.Errorf("meter: %s: %v", cfg.Path, err)
		}
	}
	if m.st.Machines == nil {
		m.st.Machines = map[string][]bucket{}
	}
	if m.st.Tasks == nil {
		m.st.Tasks = map[string]*task{}
	}
	if m.st.Bound == nil {
		m.st.Bound = map[string]string{}
	}
	if m.st.Ext == nil {
		m.st.Ext = map[string]Limits{}
	}
	if m.st.Notified == nil {
		m.st.Notified = map[string]bool{}
	}
	return m, nil
}

// save writes the state atomically. Called with mu held.
func (m *Meter) save() error {
	b, err := json.Marshal(m.st)
	if err != nil {
		return err
	}
	tmp := m.cfg.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.cfg.Path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(m.cfg.Path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// sum totals the buckets inside the window ending now.
func (m *Meter) sum(bs []bucket, now int64) Limits {
	var u Limits
	for _, b := range bs {
		if b.Start > now-int64(m.cfg.Window/time.Second) {
			u = u.add(b.Use)
		}
	}
	return u
}

// charge adds use to the current bucket and drops buckets outside the window.
func (m *Meter) charge(bs []bucket, now int64, use Limits) []bucket {
	start := now - now%m.slot
	keep := bs[:0]
	for _, b := range bs {
		if b.Start > now-int64(m.cfg.Window/time.Second) {
			keep = append(keep, b)
		}
	}
	if n := len(keep); n > 0 && keep[n-1].Start == start {
		keep[n-1].Use = keep[n-1].Use.add(use)
		return keep
	}
	return append(keep, bucket{Start: start, Use: use})
}

func (t *task) limit() Limits { return t.Reserved.add(t.Extended) }

// Call is one admitted model call. Done records the tokens it returned.
type Call struct {
	m       *Meter
	machine string
	task    string
}

// Start admits one model call from machine carrying in tokens, or refuses
// it with ErrExhausted. The call and its input tokens are charged at once,
// so parallel calls cannot pass a limit together.
func (m *Meter) Start(machine string, in int64) (*Call, error) {
	m.mu.Lock()
	now := m.cfg.Now().Unix()
	tid := m.st.Bound[machine]
	ex, err := m.admit(machine, tid, now, in)
	if ex != nil {
		if m.st.Notified[ex.key()] {
			ex = nil // told once per exhaustion
		} else {
			m.st.Notified[ex.key()] = true
			if serr := m.save(); serr != nil {
				err = errors.Join(err, serr)
			}
		}
	}
	m.mu.Unlock()
	if ex != nil {
		m.cfg.Notify(*ex)
	}
	if err != nil {
		return nil, err
	}
	return &Call{m: m, machine: machine, task: tid}, nil
}

func (e Exhausted) key() string {
	switch e.Scope {
	case ScopeTask:
		return ScopeTask + ":" + e.Task
	case ScopeMachine:
		return ScopeMachine + ":" + e.Machine
	}
	return ScopeOverall
}

// admit checks every limit and charges the call. Called with mu held.
func (m *Meter) admit(machine, tid string, now, in int64) (*Exhausted, error) {
	if used := m.sum(m.st.Overall, now); over(used, m.cfg.OverallCap, in) {
		return &Exhausted{Scope: ScopeOverall, Machine: machine, Used: used, Limit: m.cfg.OverallCap}, ErrExhausted
	}
	if t := m.st.Tasks[tid]; t != nil {
		if over(t.Used, t.limit(), in) {
			return &Exhausted{Scope: ScopeTask, Machine: machine, Task: tid, Used: t.Used, Limit: t.limit()}, ErrExhausted
		}
	} else if used := m.sum(m.st.Machines[machine], now); over(used, m.cfg.MachineCap, in) {
		return &Exhausted{Scope: ScopeMachine, Machine: machine, Used: used, Limit: m.cfg.MachineCap}, ErrExhausted
	}
	m.add(machine, tid, now, Limits{Calls: 1, Tokens: in})
	delete(m.st.Notified, ScopeOverall)
	delete(m.st.Notified, ScopeMachine+":"+machine)
	delete(m.st.Notified, ScopeTask+":"+tid)
	return nil, m.save()
}

func (m *Meter) add(machine, tid string, now int64, use Limits) {
	m.st.Overall = m.charge(m.st.Overall, now, use)
	m.st.Machines[machine] = m.charge(m.st.Machines[machine], now, use)
	if t := m.st.Tasks[tid]; t != nil {
		t.Used = t.Used.add(use)
	}
}

// Done charges the tokens the call returned. A call may pass its limit by
// its own output; the next call is then refused. If the state cannot be
// written, the charge still holds in memory and goes to disk with the next
// successful save.
func (c *Call) Done(out int64) {
	m := c.m
	m.mu.Lock()
	defer m.mu.Unlock()
	m.add(c.machine, c.task, m.cfg.Now().Unix(), Limits{Tokens: out})
	_ = m.save()
}

// Bind charges machine's calls to task's reservation from now on. Several
// machines may share one task (a guest and its workers, CAP-8). Binding an
// existing task keeps its usage and extensions; the reservation is replaced.
func (m *Meter) Bind(machine, taskID string, reservation Limits) error {
	if machine == "" || taskID == "" || reservation.Calls <= 0 || reservation.Tokens <= 0 {
		return errors.New("meter: bind needs a machine, a task, and a reservation of calls and tokens")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.st.Tasks[taskID]
	if t == nil {
		t = &task{}
		m.st.Tasks[taskID] = t
	}
	t.Reserved = reservation
	m.st.Bound[machine] = taskID
	return m.save()
}

// Unbind returns machine to its rolling cap.
func (m *Meter) Unbind(machine string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.st.Bound, machine)
	return m.save()
}

// Extend raises one task's reservation by by. It is the owner's answer to
// an exhaustion notice (YES <id> <code>, checked by the owner channel); the
// agent has no path to it. Extensions granted in one UTC day may not pass
// DailyExtension, and the overall cap still applies to every call.
func (m *Meter) Extend(taskID string, by Limits) error {
	if by.Calls < 0 || by.Tokens < 0 {
		return errors.New("meter: negative extension")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.st.Tasks[taskID]
	if t == nil {
		return fmt.Errorf("meter: no task %q", taskID)
	}
	day := m.cfg.Now().UTC().Format(time.DateOnly)
	if g := m.st.Ext[day].add(by); g.Calls > m.cfg.DailyExtension.Calls || g.Tokens > m.cfg.DailyExtension.Tokens {
		return ErrCeiling
	}
	m.st.Ext[day] = m.st.Ext[day].add(by)
	for d := range m.st.Ext {
		if d < m.cfg.Now().UTC().AddDate(0, 0, -7).Format(time.DateOnly) {
			delete(m.st.Ext, d)
		}
	}
	t.Extended = t.Extended.add(by)
	delete(m.st.Notified, ScopeTask+":"+taskID)
	return m.save()
}

// Usage is machine's use in the current window.
func (m *Meter) Usage(machine string) Limits {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sum(m.st.Machines[machine], m.cfg.Now().Unix())
}

// Tokens estimates tokens from bytes the broker observed: one token per 4
// bytes, rounded up. It counts everything on the wire (JSON and stream
// framing included), so it errs high for English text.
func Tokens(n int64) int64 { return (n + 3) / 4 }

// Wrap meters every request to next as one model call from machine. The
// request body is read in full (up to MaxBody) and counted before next
// sees it; the response is counted as it streams. A refused call gets 429
// and never reaches next.
func (m *Meter) Wrap(machine string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, m.cfg.MaxBody+1))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > m.cfg.MaxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		c, err := m.Start(machine, Tokens(int64(len(body))))
		if err != nil {
			code, msg := http.StatusTooManyRequests, "model spend limit reached for this task; the owner has been told and may extend it"
			if !errors.Is(err, ErrExhausted) {
				code, msg = http.StatusServiceUnavailable, "model spend meter unavailable"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
				"message": msg, "type": "insufficient_quota", "code": "agentos_spend_limit",
			}})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		cw := &countingWriter{ResponseWriter: w}
		defer func() { c.Done(Tokens(cw.n)) }()
		next.ServeHTTP(cw, r)
	})
}

type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
