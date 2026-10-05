// Package meter is the broker's model-spend meter (SPEC v0.12 OP-8).
//
// Every model call a guest makes passes the meter before it reaches model
// egress. The meter charges the call to the machine it arrived from, which
// the caller knows from the listener the request came in on (never from
// anything the guest sends, CRED-1): to the machine's task reservation when
// a task is bound, otherwise to the machine's rolling cap; and always to the
// box-wide overall cap.
//
// A call is charged in two steps. Start charges one call, the request's
// input estimated from its size, and a reservation for its output: the
// request's own output limit, clamped, which is also the limit the
// provider is sent (inserted when the request has none), so parallel calls
// cannot pass a limit together. Done settles the charge: a response that
// completed and carries the provider's usage is charged that usage (hidden
// reasoning included, cached input at the provider's cached weight);
// otherwise the content strings counted set the output charge, and on a
// response cut off early they are the least output charged. The usage
// comes from the handler that served the call when it reports it (Report;
// the model router does), else from the response itself. Wrap runs the
// call to the end even if the guest hangs up, so hanging up does not stop
// the charge.
//
// On exhaustion further calls are refused and the owner is told once
// (Notify); the owner may extend one task within a daily ceiling that the
// extension itself cannot raise. Usage is written to disk on every change,
// so restarting the broker does not reset a looping guest's budget.
//
// A call may also be counted against the goal its machine serves
// (StartFor, WithGoal), for accounting only: GoalUsage is a task's model
// use for the loops, and limits nothing.
//
// The meter holds no credential and makes no network call.
package meter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limits is an amount of model use: calls and tokens.
type Limits struct {
	Calls  int64 `json:"calls"`
	Tokens int64 `json:"tokens"`
}

func (l Limits) add(o Limits) Limits { return Limits{l.Calls + o.Calls, l.Tokens + o.Tokens} }

// over reports whether charging one more call carrying in tokens (input
// and reserved output) to used would pass cap.
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

// DefaultMaxReserve is the default ceiling on one call's output tokens.
const DefaultMaxReserve = 32000

// Config configures Open. MachineCap and OverallCap must be set in full:
// there is no unlimited setting.
type Config struct {
	Path           string        // durable state; created 0600
	MachineCap     Limits        // per machine per Window, when no task is bound
	OverallCap     Limits        // whole box per Window
	DailyExtension Limits        // most the owner may extend tasks by per day
	Window         time.Duration // rolling window; default 24 h
	MaxBody        int64         // Wrap's request body cap; default 8 MiB
	// MaxReserve is the most output one call may ask for: every forwarded
	// output limit is clamped to it and it is reserved at Start. Default
	// 32000, the model router's ceiling (route.DefaultMaxOutputTokens);
	// set it to the router's MaxOutputTokens. DefaultReserve is the limit
	// inserted when a request sets none; default MaxReserve. Done settles
	// the reservation to actual use.
	DefaultReserve, MaxReserve int64
	// CallTimeout bounds one call, which Wrap runs to the end even if the
	// guest hangs up; default 10 minutes.
	CallTimeout time.Duration
	Notify      func(Exhausted)
	Now         func() time.Time
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
	Shares   map[string][]bucket `json:"shares"`   // share prefix -> use
	Goals    map[string]*goalUse `json:"goals"`    // goal -> use, for accounting only
}

// goalUse is one goal's model use. It limits nothing: caps stay per
// machine, task, and box. It is kept until the goal has been idle for
// GoalKeep, so the map stays bounded by recent work.
type goalUse struct {
	Used Limits `json:"used"`
	Last int64  `json:"last"` // unix seconds of the last charge
}

// GoalKeep is how long an idle goal's usage is kept.
const GoalKeep = 7 * 24 * time.Hour

// Meter is safe for concurrent use.
type Meter struct {
	cfg    Config
	slot   int64
	mu     sync.Mutex
	st     state
	shares []Share
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
	if cfg.MaxReserve <= 0 {
		cfg.MaxReserve = DefaultMaxReserve
	}
	if cfg.DefaultReserve <= 0 || cfg.DefaultReserve > cfg.MaxReserve {
		cfg.DefaultReserve = cfg.MaxReserve
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Minute
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
	if m.st.Shares == nil {
		m.st.Shares = map[string][]bucket{}
	}
	if m.st.Goals == nil {
		m.st.Goals = map[string]*goalUse{}
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

// Call is one admitted model call. Done settles what it used.
type Call struct {
	m       *Meter
	machine string
	task    string
	goal    string
	charged int64 // tokens charged at Start
	at      int64 // start of the bucket they were charged to
	once    sync.Once
}

// Start admits one model call from machine carrying in input tokens and
// reserving reserve output tokens, or refuses it with ErrExhausted. The
// call and both amounts are charged at once, so parallel calls cannot pass
// a limit together.
func (m *Meter) Start(machine string, in, reserve int64) (*Call, error) {
	return m.StartFor(machine, "", in, reserve)
}

// StartFor is Start for a call made while machine serves goal (the owner
// message its lineage is working on, chosen by the broker). The call is
// also counted against goal, for accounting only (GoalUsage); an empty
// goal counts nowhere.
func (m *Meter) StartFor(machine, goal string, in, reserve int64) (*Call, error) {
	if in < 0 || reserve < 0 {
		return nil, errors.New("meter: negative charge")
	}
	// Share activity is read before taking the lock: Active is the
	// caller's function and must not run under the meter's lock.
	m.mu.Lock()
	shares := m.shares
	m.mu.Unlock()
	active := make([]bool, len(shares))
	for i, sh := range shares {
		active[i] = sh.Active == nil || sh.Active()
	}
	m.mu.Lock()
	now := m.cfg.Now().Unix()
	tid := m.st.Bound[machine]
	if err := m.admitShares(shares, active, machine, now, in+reserve); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	ex, err := m.admit(machine, tid, goal, now, in+reserve)
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
	return &Call{m: m, machine: machine, task: tid, goal: goal, charged: in + reserve, at: now - now%m.slot}, nil
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
func (m *Meter) admit(machine, tid, goal string, now, in int64) (*Exhausted, error) {
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
	m.add(machine, tid, goal, now, Limits{Calls: 1, Tokens: in})
	// A task's notice stays sent until the owner extends it (Extend), so
	// the owner is asked at most once per task. Rolling caps re-arm once
	// a call gets through again.
	delete(m.st.Notified, ScopeOverall)
	delete(m.st.Notified, ScopeMachine+":"+machine)
	return nil, m.save()
}

func (m *Meter) add(machine, tid, goal string, now int64, use Limits) {
	m.st.Overall = m.charge(m.st.Overall, now, use)
	m.st.Machines[machine] = m.charge(m.st.Machines[machine], now, use)
	if p, ok := m.shareOf(machine); ok {
		m.st.Shares[p] = m.charge(m.st.Shares[p], now, use)
	}
	if t := m.st.Tasks[tid]; t != nil {
		t.Used = t.Used.add(use)
	}
	m.chargeGoal(goal, now, use)
}

// chargeGoal counts use against goal and forgets goals idle past
// GoalKeep. Called with mu held.
func (m *Meter) chargeGoal(goal string, now int64, use Limits) {
	for g, u := range m.st.Goals {
		if u.Last <= now-int64(GoalKeep/time.Second) {
			delete(m.st.Goals, g)
		}
	}
	if goal == "" {
		return
	}
	u := m.st.Goals[goal]
	if u == nil {
		u = &goalUse{}
		m.st.Goals[goal] = u
	}
	u.Used = Limits{Calls: u.Used.Calls + use.Calls, Tokens: max(0, u.Used.Tokens+use.Tokens)}
	u.Last = now
}

// GoalUsage is the model use counted against goal: every call started
// for it, settled, while it was used in the last GoalKeep.
func (m *Meter) GoalUsage(goal string) Limits {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u := m.st.Goals[goal]; u != nil && u.Last > m.cfg.Now().Unix()-int64(GoalKeep/time.Second) {
		return u.Used
	}
	return Limits{}
}

// Done settles the call to used, the tokens it actually used (input and
// output). More than was charged at Start is added now; less is refunded
// from the bucket Start charged, if it is still in the window. A call may
// pass its limit by its own output; the next call is then refused. If the
// state cannot be written, the charge still holds in memory and goes to
// disk with the next successful save. Only the first Done counts.
func (c *Call) Done(used int64) {
	c.once.Do(func() { c.m.settle(c, used) })
}

func (m *Meter) settle(c *Call, used int64) {
	if used < 0 {
		used = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch d := used - c.charged; {
	case d > 0:
		m.add(c.machine, c.task, c.goal, m.cfg.Now().Unix(), Limits{Tokens: d})
	case d < 0:
		refund(m.st.Overall, c.at, -d)
		refund(m.st.Machines[c.machine], c.at, -d)
		if p, ok := m.shareOf(c.machine); ok {
			refund(m.st.Shares[p], c.at, -d)
		}
		if t := m.st.Tasks[c.task]; t != nil {
			t.Used.Tokens = max(0, t.Used.Tokens+d)
		}
		if u := m.st.Goals[c.goal]; u != nil {
			u.Used.Tokens = max(0, u.Used.Tokens+d)
		}
	default:
		return
	}
	_ = m.save()
}

// refund takes up to n tokens back from the bucket starting at at.
func refund(bs []bucket, at, n int64) {
	for i := range bs {
		if bs[i].Start == at {
			bs[i].Use.Tokens = max(0, bs[i].Use.Tokens-n)
			return
		}
	}
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
	// Compared by subtraction: granted never exceeds the ceiling, so this
	// cannot overflow the way granted+by can.
	if g, c := m.st.Ext[day], m.cfg.DailyExtension; by.Calls > c.Calls-g.Calls || by.Tokens > c.Tokens-g.Tokens {
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

// Overall is the whole box's use in the current window, against its cap.
func (m *Meter) Overall() (used, limit Limits) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sum(m.st.Overall, m.cfg.Now().Unix()), m.cfg.OverallCap
}

// SetOverallCap changes the overall cap, for a meter whose cap is an owner
// setting (the spare budget, LOOP-2). Calls already started keep their
// charge; the next Start is checked against the new cap. Like Open, it
// refuses a cap that does not limit both calls and tokens.
func (m *Meter) SetOverallCap(l Limits) error {
	if l.Calls <= 0 || l.Tokens <= 0 {
		return errors.New("meter: the overall cap must limit both calls and tokens")
	}
	m.mu.Lock()
	m.cfg.OverallCap = l
	m.mu.Unlock()
	return nil
}

// Share sets part of the overall cap apart for the machines whose IDs
// start with Prefix (one meter shared by several kinds of work, such as
// the spare budget's evaluation, builders, and clean room; loops L3).
//
// Reserve is the fraction of the overall cap kept for the share while it
// is Active: other machines' calls are refused when they would leave the
// share less than its reserve minus what it already used in the window.
// While it is not Active, others may use its reserve; they hand it back
// as soon as it is Active again, for calls not yet made (spend already
// made in the window stays spent). Max, when above 0, is the most of the
// overall cap the share's machines may use. Active nil means always.
// Fractions are taken of the overall cap at each call, so they follow
// SetOverallCap. Refusals by a share are ErrExhausted with no Notify:
// they are the meter's own scheduling, not an owner's limit.
type Share struct {
	Prefix  string
	Reserve float64
	Max     float64
	Active  func() bool
}

// SetShares replaces the meter's shares. Prefixes must be distinct, not
// empty, and not prefixes of one another; fractions must be in [0, 1] and
// reserves may not add up to more than 1.
func (m *Meter) SetShares(shares []Share) error {
	total := 0.0
	for i, sh := range shares {
		if sh.Prefix == "" || sh.Reserve < 0 || sh.Reserve > 1 || sh.Max < 0 || sh.Max > 1 {
			return errors.New("meter: a share needs a prefix and fractions between 0 and 1")
		}
		if sh.Max > 0 && sh.Max < sh.Reserve {
			return errors.New("meter: a share's maximum is below its reserve")
		}
		for _, o := range shares[:i] {
			if strings.HasPrefix(sh.Prefix, o.Prefix) || strings.HasPrefix(o.Prefix, sh.Prefix) {
				return fmt.Errorf("meter: share prefixes %q and %q overlap", o.Prefix, sh.Prefix)
			}
		}
		total += sh.Reserve
	}
	if total > 1 {
		return errors.New("meter: share reserves add up to more than the overall cap")
	}
	m.mu.Lock()
	m.shares = append([]Share(nil), shares...)
	m.mu.Unlock()
	return nil
}

// ShareUsage is the use in the current window by the share with prefix.
func (m *Meter) ShareUsage(prefix string) Limits {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sum(m.st.Shares[prefix], m.cfg.Now().Unix())
}

// shareOf is the prefix of the share machine belongs to. Called with mu
// held.
func (m *Meter) shareOf(machine string) (string, bool) {
	for _, sh := range m.shares {
		if strings.HasPrefix(machine, sh.Prefix) {
			return sh.Prefix, true
		}
	}
	return "", false
}

func frac(l Limits, f float64) Limits {
	return Limits{int64(float64(l.Calls) * f), int64(float64(l.Tokens) * f)}
}

// admitShares refuses a call carrying in tokens that would pass its own
// share's Max or eat into another Active share's unused reserve. Called
// with mu held; active[i] is shares[i].Active().
func (m *Meter) admitShares(shares []Share, active []bool, machine string, now, in int64) error {
	cap := m.cfg.OverallCap
	var held Limits // other active shares' reserves not yet used
	for i, sh := range shares {
		used := m.sum(m.st.Shares[sh.Prefix], now)
		if strings.HasPrefix(machine, sh.Prefix) {
			if sh.Max > 0 && over(used, frac(cap, sh.Max), in) {
				return ErrExhausted
			}
			continue
		}
		if active[i] {
			r := frac(cap, sh.Reserve)
			held = held.add(Limits{max(0, r.Calls-used.Calls), max(0, r.Tokens-used.Tokens)})
		}
	}
	if held == (Limits{}) {
		return nil
	}
	if over(m.sum(m.st.Overall, now).add(held), cap, in) {
		return ErrExhausted
	}
	return nil
}

// Tokens estimates tokens from bytes: one token per 4 bytes, rounded up.
func Tokens(n int64) int64 { return (n + 3) / 4 }

// Wrap meters every request to next as one model call from machine. The
// request body is read in full (up to MaxBody); its size is the input
// estimate and its output limit sizes the reservation. next runs on a
// context the guest cannot cancel (bounded by CallTimeout), and keeps
// writing after the guest hangs up, so the provider's whole answer, and
// the usage it reports, is seen and charged. A refused call gets 429 and
// never reaches next. The call counts against the goal the broker put on
// the request's context (WithGoal), if any.
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
		in := Tokens(int64(len(body)))
		body, reserve, err := m.limit(r.URL.Path, body)
		if err != nil {
			http.Error(w, "model request refused: "+err.Error(), http.StatusBadRequest)
			return
		}
		c, err := m.StartFor(machine, GoalFrom(r.Context()), in, reserve)
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
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), m.cfg.CallTimeout)
		defer cancel()
		rep := &reportSlot{}
		r = r.WithContext(context.WithValue(ctx, reportKey{}, rep))
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Del("Content-Length")
		uw := &usageWriter{w: w, max: m.cfg.MaxBody}
		defer func() { c.Done(uw.used(in, rep.get())) }()
		next.ServeHTTP(uw, r)
	})
}

// limit makes the request's output limit the call's reservation (OP-8).
// Every output-limit key present (max_tokens, max_completion_tokens,
// max_output_tokens; any reasoning budget sits inside them) is clamped to
// MaxReserve, a missing or unusable one counts as MaxReserve, and when
// none is present the limit is inserted at DefaultReserve, under the key
// the path's API reads. The body is re-encoded from what was checked, so
// duplicate keys cannot carry a second, larger limit past the meter. The
// reservation is the largest limit forwarded, so a provider that honors
// its limit cannot be charged past what Start reserved. An empty body
// (a GET) passes unchanged; any other body that is not one JSON object
// is refused, as is a request for more than one choice (n).
func (m *Meter) limit(path string, body []byte) ([]byte, int64, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, m.cfg.DefaultReserve, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, 0, errors.New("body is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, errors.New("trailing data after JSON body")
	}
	// n asks for several choices, each up to the limit, so output could
	// pass the reservation n times over. One choice only.
	if v, ok := obj["n"]; ok && string(bytes.TrimSpace(v)) != "1" {
		return nil, 0, errors.New("only one choice (n=1) per model call")
	}
	reserve := int64(0)
	for _, k := range limitKeys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64)
		if err != nil || n <= 0 || n > m.cfg.MaxReserve {
			n = m.cfg.MaxReserve
		}
		obj[k] = json.RawMessage(strconv.FormatInt(n, 10))
		reserve = max(reserve, n)
	}
	if reserve == 0 {
		reserve = m.cfg.DefaultReserve
		k := "max_completion_tokens"
		switch {
		case strings.HasSuffix(path, "/messages"):
			k = "max_tokens" // Anthropic Messages
		case strings.HasSuffix(path, "/responses"):
			k = "max_output_tokens" // OpenAI Responses
		}
		obj[k] = json.RawMessage(strconv.FormatInt(reserve, 10))
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, err
	}
	return out, reserve, nil
}

// limitKeys are the request keys that bound a call's output.
var limitKeys = []string{"max_tokens", "max_completion_tokens", "max_output_tokens"}

type goalKey struct{}

// WithGoal marks a model request's context with the goal the broker found
// its machine serving, for Wrap to count it against. Only the broker sets
// it; nothing the guest sends names a goal.
func WithGoal(ctx context.Context, goal string) context.Context {
	return context.WithValue(ctx, goalKey{}, goal)
}

// GoalFrom returns the goal WithGoal set, or "".
func GoalFrom(ctx context.Context) string {
	g, _ := ctx.Value(goalKey{}).(string)
	return g
}
