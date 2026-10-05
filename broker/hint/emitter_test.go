package hint

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// REQ: OSS-1, OSS-5, OSS-7

type outbox struct {
	mu   sync.Mutex
	sent []string
	fail error
}

func (o *outbox) Send(b []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
	o.sent = append(o.sent, string(b))
	return nil
}

func (o *outbox) n() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.sent) }

type rig struct {
	e   *Emitter
	out *outbox
	log Log
	now time.Time
}

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	r := &rig{out: &outbox{}, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	if cfg.Log == nil {
		cfg.Log = &MemLog{}
	}
	r.log = cfg.Log
	cfg.Outbox = r.out
	cfg.Now = func() time.Time { return r.now }
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.e = e
	return r
}

func records(t *testing.T, l Log) []Record {
	t.Helper()
	rs, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

var vuln = Hint{Kind: "vuln", Fields: map[string]string{"class": "prompt_injection", "vector": "email_html"}}

// TestOSS7DefaultIsAutomatic: with no policy set, a valid hint goes to the
// outbox in canonical form, and the log records it.
func TestOSS7DefaultIsAutomatic(t *testing.T) {
	r := newRig(t, Config{})
	res, err := r.e.Emit(good())
	if err != nil || res.Outcome != Forwarded {
		t.Fatalf("emit: %+v %v", res, err)
	}
	if r.out.n() != 1 || r.out.sent[0] != `{"schema":1,"kind":"skill_gap","embargo":false,"fields":{"domain":"calendar","failure":"timezone","format":"ics"}}` {
		t.Fatalf("sent %q", r.out.sent)
	}
	rs := records(t, r.log)
	if len(rs) != 1 || rs[0].Outcome != Forwarded || rs[0].Kind != "skill_gap" || rs[0].Fields["failure"] != "timezone" || rs[0].Day != "2026-10-05" || rs[0].Category != "skills" {
		t.Fatalf("log %+v", rs)
	}
}

// TestOSS1EveryHintLogged: forwarded, withheld, asked, duplicate, and
// refused hints all leave a record the owner can read. A refused hint's
// record carries no content, since it failed the schema.
func TestOSS1EveryHintLogged(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"security": Never, "adapters": Ask}})
	r.e.Emit(good())
	r.e.Emit(good())
	r.e.Emit(vuln)
	r.e.Emit(Hint{Kind: "adapter_gap", Fields: map[string]string{"service_class": "banking", "surface": "web", "failure": "changed_layout"}})
	if _, err := r.e.Emit(Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "Ann's flight UA123"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	rs := records(t, r.log)
	want := []Outcome{Forwarded, Duplicate, Withheld, Asked, Refused}
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
	if r.out.n() != 1 {
		t.Fatalf("sent %d", r.out.n())
	}
}

// TestOSS7AskEachTime: under "ask", nothing crosses until the owner
// approves; a declined hint never crosses; both are logged.
func TestOSS7AskEachTime(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Ask}})
	res, err := r.e.Emit(good())
	if err != nil || res.Outcome != Asked || res.ID == 0 {
		t.Fatalf("emit %+v %v", res, err)
	}
	if p := r.e.Pending(); len(p) != 1 || p[0].ID != res.ID || p[0].Kind != "skill_gap" {
		t.Fatalf("pending %+v", p)
	}
	if r.out.n() != 0 {
		t.Fatal("sent before approval")
	}
	if err := r.e.Approve(res.ID); err != nil {
		t.Fatal(err)
	}
	if r.out.n() != 1 || len(r.e.Pending()) != 0 {
		t.Fatalf("after approve: sent %d pending %d", r.out.n(), len(r.e.Pending()))
	}
	if err := r.e.Approve(res.ID); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second approve: %v", err)
	}
	h2 := Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "email", "format": "html", "failure": "encoding"}}
	res2, _ := r.e.Emit(h2)
	if err := r.e.Decline(res2.ID); err != nil {
		t.Fatal(err)
	}
	if r.out.n() != 1 {
		t.Fatal("declined hint sent")
	}
	rs := records(t, r.log)
	want := []Outcome{Asked, Approved, Asked, Declined}
	for i, o := range want {
		if rs[i].Outcome != o {
			t.Fatalf("log %+v", rs)
		}
	}
}

// TestOSS7Never: under "never", the hint is logged and stays on the box.
func TestOSS7Never(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Never}})
	res, err := r.e.Emit(good())
	if err != nil || res.Outcome != Withheld || r.out.n() != 0 {
		t.Fatalf("%+v %v sent %d", res, err, r.out.n())
	}
}

// TestOSS7PolicyKeysChecked: a policy naming a category the schema lacks is
// a configuration error, not a silent automatic default.
func TestOSS7PolicyKeysChecked(t *testing.T) {
	if _, err := New(Config{Outbox: &outbox{}, Log: &MemLog{}, Policy: map[string]Mode{"skill": Never}}); err == nil {
		t.Fatal("unknown category accepted")
	}
	if _, err := New(Config{Outbox: &outbox{}, Log: &MemLog{}, Policy: map[string]Mode{"skills": Mode(9)}}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := New(Config{Log: &MemLog{}}); err == nil {
		t.Fatal("no outbox accepted")
	}
	if _, err := New(Config{Outbox: &outbox{}}); err == nil {
		t.Fatal("no log accepted")
	}
}

// TestOSS5VulnCrossesEmbargoed: a security hint reaches the outbox marked
// for the embargoed path.
func TestOSS5VulnCrossesEmbargoed(t *testing.T) {
	r := newRig(t, Config{})
	res, err := r.e.Emit(vuln)
	if err != nil || res.Outcome != Forwarded {
		t.Fatal(res, err)
	}
	if r.out.sent[0] != `{"schema":1,"kind":"vuln","embargo":true,"fields":{"class":"prompt_injection","vector":"email_html"}}` {
		t.Fatalf("sent %s", r.out.sent[0])
	}
}

// TestOSS1DailyBound: at most DailyLimit hints cross (or are asked) per
// day, and a repeat of a hint already sent today crosses once, which bounds
// what a compromised private side can signal by choosing hints. The bound
// survives a restart because counts are rebuilt from the log.
func TestOSS1DailyBound(t *testing.T) {
	log, err := OpenFileLog(filepath.Join(t.TempDir(), "hints.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, Config{DailyLimit: 3, Log: log})
	domains := []string{"calendar", "email", "contacts", "documents"}
	var got []Outcome
	for _, d := range domains[:2] {
		res, _ := r.e.Emit(Hint{Kind: "skill_gap", Fields: map[string]string{"domain": d, "format": "ics", "failure": "timezone"}})
		got = append(got, res.Outcome)
	}
	// Restart: a new emitter over the same log keeps today's counts.
	log2, err := OpenFileLog(log.path)
	if err != nil {
		t.Fatal(err)
	}
	r2 := newRig(t, Config{DailyLimit: 3, Log: log2})
	r2.now = r.now.Add(time.Hour)
	for _, d := range []string{"calendar", "contacts", "documents"} {
		res, _ := r2.e.Emit(Hint{Kind: "skill_gap", Fields: map[string]string{"domain": d, "format": "ics", "failure": "timezone"}})
		got = append(got, res.Outcome)
	}
	want := []Outcome{Forwarded, Forwarded, Duplicate, Forwarded, OverLimit}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("outcomes %v, want %v", got, want)
		}
	}
	// Next day: the bound resets.
	r2.now = r2.now.Add(24 * time.Hour)
	if res, _ := r2.e.Emit(Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "documents", "format": "ics", "failure": "timezone"}}); res.Outcome != Forwarded {
		t.Fatalf("next day %v", res.Outcome)
	}
	if n := len(records(t, log2)); n != 6 {
		t.Fatalf("file log has %d records", n)
	}
}

// TestOSS1SendFailureLogged: an outbox failure is logged and returned; the
// hint does not count as sent, so a later retry may cross.
func TestOSS1SendFailureLogged(t *testing.T) {
	r := newRig(t, Config{})
	r.out.fail = errors.New("down")
	if res, err := r.e.Emit(good()); err == nil || res.Outcome != SendFailed {
		t.Fatalf("%+v %v", res, err)
	}
	r.out.fail = nil
	if res, err := r.e.Emit(good()); err != nil || res.Outcome != Forwarded {
		t.Fatalf("retry %+v %v", res, err)
	}
}

// TestOSS1LoggedBeforeSent: the record exists before the outbox sees the
// hint, so nothing crosses unlogged; a failed approval leaves the hint
// pending, also across a restart.
func TestOSS1LoggedBeforeSent(t *testing.T) {
	log := &MemLog{}
	var at int
	r := newRig(t, Config{Log: log, Policy: map[string]Mode{"security": Ask}})
	r.out.fail = errors.New("down")
	probe := &probeOutbox{inner: r.out, log: log, at: &at}
	r.e.cfg.Outbox = probe
	r.e.Emit(good())
	if at != 1 {
		t.Fatalf("log had %d records when the outbox was called", at)
	}
	res, _ := r.e.Emit(vuln)
	if err := r.e.Approve(res.ID); err == nil {
		t.Fatal("approve with failing outbox succeeded")
	}
	if len(r.e.Pending()) != 1 {
		t.Fatal("failed approval dropped the pending hint")
	}
	e2, err := New(Config{Log: log, Outbox: r.out, Now: func() time.Time { return r.now }, Policy: map[string]Mode{"security": Ask}})
	if err != nil {
		t.Fatal(err)
	}
	if p := e2.Pending(); len(p) != 1 || p[0].ID != res.ID {
		t.Fatalf("pending after restart %+v", p)
	}
	r.out.fail = nil
	if err := e2.Approve(res.ID); err != nil {
		t.Fatal(err)
	}
	// The failed skill_gap send did not count: it may cross again today.
	if res, _ := e2.Emit(good()); res.Outcome != Forwarded {
		t.Fatalf("retry after failed send: %s", res.Outcome)
	}
}

type probeOutbox struct {
	inner *outbox
	log   Log
	at    *int
}

func (p *probeOutbox) Send(b []byte) error {
	rs, _ := p.log.List()
	*p.at = len(rs)
	return p.inner.Send(b)
}
