package hint

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

// REQ: OSS-1, OSS-5, OSS-7

type outbox struct {
	mu      sync.Mutex
	batches [][]string
	days    []string
	fail    error
	onSend  func()
}

func (o *outbox) Send(day string, batch [][]byte) error {
	if o.onSend != nil {
		o.onSend()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
	var b []string
	for _, h := range batch {
		b = append(b, string(h))
	}
	o.batches = append(o.batches, b)
	o.days = append(o.days, day)
	return nil
}

func (o *outbox) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var all []string
	for _, b := range o.batches {
		all = append(all, b...)
	}
	return all
}

type rig struct {
	t   *testing.T
	cfg Config
	e   *Emitter
	out *outbox
	log Log
	now time.Time
}

var day0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	r := &rig{t: t, out: &outbox{}, now: day0}
	if cfg.Log == nil {
		cfg.Log = &MemLog{}
	}
	r.log = cfg.Log
	cfg.Outbox = r.out
	cfg.Now = func() time.Time { return r.now }
	r.cfg = cfg
	r.restart()
	return r
}

// restart builds a fresh emitter over the same log, as after a reboot.
func (r *rig) restart() {
	r.t.Helper()
	e, err := New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.e = e
}

// nextRelease moves the clock to the release time of the next day and
// releases.
func (r *rig) nextRelease() error {
	d := time.Date(r.now.Year(), r.now.Month(), r.now.Day(), 0, 0, 0, 0, time.UTC)
	r.now = d.Add(24*time.Hour + DefaultReleaseAt)
	return r.e.Release()
}

func records(t *testing.T, l Log) []Record {
	t.Helper()
	rs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func skill(domain string) Hint {
	return Hint{Kind: "skill_gap", Fields: map[string]string{"domain": domain, "format": "ics", "failure": "timezone", "frequency": "once"}}
}

var vuln = Hint{Kind: "vuln", Fields: map[string]string{"class": "prompt_injection", "vector": "email_html"}}

var allDomains = []string{"calendar", "email", "contacts", "documents", "spreadsheets", "files", "web_forms", "shopping", "travel", "finance", "messaging", "notes", "tasks", "media"}

func canon(t *testing.T, h Hint) string {
	t.Helper()
	c, err := Default().Canonical(h)
	if err != nil {
		t.Fatal(err)
	}
	return string(c)
}

func emit(t *testing.T, e *Emitter, h Hint) Result {
	t.Helper()
	res, err := e.Emit(h)
	if err != nil {
		t.Fatalf("emit %v: %v", h, err)
	}
	return res
}

// failSent is a Log that fails to write Sent records: the box crashed
// after the outbox took the batch but before the commit.
type failSent struct{ MemLog }

func (l *failSent) Append(r Record) error {
	if r.Outcome == Sent {
		return errors.New("crash")
	}
	return l.MemLog.Append(r)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestOSS7DefaultIsAutomatic: with no policy set, a valid hint is queued
// for the next batch, logged, and crosses in canonical form at release.
func TestOSS7DefaultIsAutomatic(t *testing.T) {
	r := newRig(t, Config{})
	if res := emit(t, r.e, good()); res.Outcome != Queued {
		t.Fatalf("emit: %+v", res)
	}
	rs := records(t, r.log)
	if len(rs) != 1 || rs[0].Outcome != Queued || rs[0].Kind != "skill_gap" || rs[0].Fields["failure"] != "timezone" || rs[0].Day != "2026-10-05" || rs[0].Category != "skills" {
		t.Fatalf("log %+v", rs)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != `{"schema":1,"kind":"skill_gap","embargo":false,"fields":{"domain":"calendar","failure":"timezone","format":"ics","frequency":"once"}}` {
		t.Fatalf("sent %q", got)
	}
}

// TestOSS1OnlyTheSetCrosses: hints cross only as one batch per day, at the
// fixed release time on a later day, sorted by canonical form, so neither
// the order nor the time they were emitted reaches the outbox. (This is
// OSS-6's batching and delay; its pseudonymous key and rotation are the
// publication package's.)
func TestOSS1OnlyTheSetCrosses(t *testing.T) {
	r := newRig(t, Config{})
	order := []string{"travel", "calendar", "notes", "email"}
	for i, d := range order {
		r.now = day0.Add(time.Duration(i) * 97 * time.Minute)
		emit(t, r.e, skill(d))
	}
	emit(t, r.e, vuln)
	// Same day: nothing crosses, whatever the hour.
	r.now = day0.Add(14 * time.Hour)
	if err := r.e.Release(); err != nil || len(r.out.batches) != 0 {
		t.Fatalf("same-day release: %v %v", err, r.out.batches)
	}
	// Next day, before the release time: still nothing.
	r.now = time.Date(2026, 10, 6, 0, 30, 0, 0, time.UTC)
	if err := r.e.Release(); err != nil || len(r.out.batches) != 0 {
		t.Fatalf("early release: %v %v", err, r.out.batches)
	}
	// At the release time: one batch, sorted.
	r.now = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC).Add(DefaultReleaseAt)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 1 || len(r.out.batches[0]) != 5 {
		t.Fatalf("batches %v", r.out.batches)
	}
	if !sort.StringsAreSorted(r.out.batches[0]) {
		t.Fatalf("batch not sorted: %v", r.out.batches[0])
	}
	// A second call the same day sends nothing more.
	r.now = r.now.Add(5 * time.Hour)
	emit(t, r.e, skill("media"))
	if err := r.e.Release(); err != nil || len(r.out.batches) != 1 {
		t.Fatalf("second release: %v %v", err, r.out.batches)
	}
}

// TestOSS1EveryHintLogged: queued, duplicate, withheld, asked, and refused
// hints all leave a record the owner can read. A refused hint's record
// carries no content, since it failed the schema.
func TestOSS1EveryHintLogged(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"security": Never, "adapters": Ask}})
	r.e.Emit(good())
	r.e.Emit(good())
	r.e.Emit(vuln)
	r.e.Emit(Hint{Kind: "adapter_gap", Fields: map[string]string{"service_class": "banking", "surface": "web", "failure": "changed_layout", "frequency": "sometimes"}})
	if _, err := r.e.Emit(Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "Ann's flight UA123"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	rs := records(t, r.log)
	want := []Outcome{Queued, Duplicate, Withheld, Withheld, Refused} // adapter_gap changed_layout held (PC1)
	if len(rs) != len(want) {
		t.Fatalf("log %+v", rs)
	}
	for i, o := range want {
		if rs[i].Outcome != o {
			t.Errorf("record %d: %s, want %s", i, rs[i].Outcome, o)
		}
	}
	if last := rs[4]; last.Kind != "" || last.Fields != nil || last.Category != "" {
		t.Fatalf("refused record carries content: %+v", last)
	}
}

// TestOSS7AskEachTime: under "ask", nothing is queued until the owner
// approves; a declined hint never crosses; a repeat of a pending ask is a
// duplicate, on any day; all of it is logged.
func TestOSS7AskEachTime(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Ask}})
	res := emit(t, r.e, good())
	if res.Outcome != Asked || res.ID == 0 {
		t.Fatalf("emit %+v", res)
	}
	if p := r.e.Pending(); len(p) != 1 || p[0].ID != res.ID || p[0].Kind != "skill_gap" {
		t.Fatalf("pending %+v", p)
	}
	r.now = day0.Add(48 * time.Hour)
	if again := emit(t, r.e, good()); again.Outcome != Duplicate {
		t.Fatalf("repeat of a pending ask: %s", again.Outcome)
	}
	if err := r.nextRelease(); err != nil || len(r.out.all()) != 0 {
		t.Fatalf("released an unapproved hint: %v %v", err, r.out.all())
	}
	if err := r.e.Approve(res.ID); err != nil {
		t.Fatal(err)
	}
	if len(r.e.Pending()) != 0 {
		t.Fatal("still pending after approve")
	}
	if err := r.e.Approve(res.ID); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second approve: %v", err)
	}
	res2 := emit(t, r.e, skill("email"))
	if err := r.e.Decline(res2.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, good()) {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS7Never: under "never", the hint is logged and stays on the box.
func TestOSS7Never(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Never}})
	if res := emit(t, r.e, good()); res.Outcome != Withheld {
		t.Fatalf("%+v", res)
	}
	if err := r.nextRelease(); err != nil || len(r.out.all()) != 0 {
		t.Fatalf("%v %v", err, r.out.all())
	}
}
