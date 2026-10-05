package hint

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	want := []Outcome{Queued, Duplicate, Withheld, Asked, Refused}
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

// TestOSS7PolicyKeysChecked: a policy naming a category the schema lacks is
// a configuration error, not a silent automatic default; so are limits
// that leave no room for routine or embargo kinds.
func TestOSS7PolicyKeysChecked(t *testing.T) {
	for name, cfg := range map[string]Config{
		"unknown category": {Outbox: &outbox{}, Log: &MemLog{}, Policy: map[string]Mode{"skill": Never}},
		"unknown mode":     {Outbox: &outbox{}, Log: &MemLog{}, Policy: map[string]Mode{"skills": Mode(9)}},
		"no outbox":        {Log: &MemLog{}},
		"no log":           {Outbox: &outbox{}},
		"reserve = limit":  {Outbox: &outbox{}, Log: &MemLog{}, DailyLimit: 4, EmbargoReserve: 4},
		"release at 25h":   {Outbox: &outbox{}, Log: &MemLog{}, ReleaseAt: 25 * time.Hour},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestOSS5VulnCrossesEmbargoed: a security hint crosses marked for the
// embargoed path.
func TestOSS5VulnCrossesEmbargoed(t *testing.T) {
	r := newRig(t, Config{})
	emit(t, r.e, vuln)
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != `{"schema":1,"kind":"vuln","embargo":true,"fields":{"class":"prompt_injection","vector":"email_html"}}` {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS5FloodDoesNotStarveVuln: routine hints cannot use the slots
// reserved for embargo kinds, so a flood of them before a real finding
// still lets the vuln hint cross in the next batch. Hints over the day's
// cap wait for the next batch instead of being dropped.
func TestOSS5FloodDoesNotStarveVuln(t *testing.T) {
	r := newRig(t, Config{DailyLimit: 4, EmbargoReserve: 1})
	for _, d := range allDomains[:10] {
		if res := emit(t, r.e, skill(d)); res.Outcome != Queued {
			t.Fatalf("%s: %s", d, res.Outcome)
		}
	}
	emit(t, r.e, vuln)
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	b := r.out.batches[0]
	if len(b) != 4 || !contains(b, canon(t, vuln)) {
		t.Fatalf("first batch %v", b)
	}
	// The rest follow, oldest first, at most the cap per batch; with no
	// embargo hint waiting, routine hints may use the reserved slot.
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches[1]) != 4 {
		t.Fatalf("second batch %v", r.out.batches[1])
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches[2]) != 3 || len(r.out.all()) != 11 {
		t.Fatalf("third batch %v", r.out.batches[2])
	}
	for _, d := range allDomains[:10] {
		if !contains(r.out.all(), canon(t, skill(d))) {
			t.Fatalf("%s never crossed", d)
		}
	}
}

// TestOSS5BacklogBounded: the waiting queue for routine hints is bounded
// (over the bound a hint is logged over_limit and dropped), and a full
// routine queue never blocks an embargo hint.
func TestOSS5BacklogBounded(t *testing.T) {
	r := newRig(t, Config{DailyLimit: 2, EmbargoReserve: 1, MaxBacklog: 3})
	var got []Outcome
	for _, d := range allDomains[:5] {
		got = append(got, emit(t, r.e, skill(d)).Outcome)
	}
	want := []Outcome{Queued, Queued, Queued, OverLimit, OverLimit}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("outcomes %v, want %v", got, want)
		}
	}
	if res := emit(t, r.e, vuln); res.Outcome != Queued {
		t.Fatalf("vuln behind a full routine queue: %s", res.Outcome)
	}
}

// TestOSS1ClockStepKeepsTheCap: stepping the clock back does not reopen an
// earlier day, so stepping it back and forward again cannot reset the
// day's dedupe or let more than the cap cross in one batch. The day only
// moves forward.
func TestOSS1ClockStepKeepsTheCap(t *testing.T) {
	r := newRig(t, Config{DailyLimit: 2, EmbargoReserve: 1})
	emit(t, r.e, skill("calendar"))
	emit(t, r.e, skill("email"))
	r.now = day0.Add(-24 * time.Hour)
	if res := emit(t, r.e, skill("calendar")); res.Outcome != Duplicate {
		t.Fatalf("after stepping back, repeat: %s", res.Outcome)
	}
	emit(t, r.e, skill("contacts"))
	r.now = day0
	emit(t, r.e, skill("documents"))
	for _, rec := range records(t, r.log) {
		if rec.Day != "2026-10-05" {
			t.Fatalf("record on day %s", rec.Day)
		}
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 1 || len(r.out.batches[0]) != 2 {
		t.Fatalf("first batch %v", r.out.batches)
	}
	// Stepping back after a release does not release that day again.
	r.now = r.now.Add(-24 * time.Hour)
	if err := r.e.Release(); err != nil || len(r.out.batches) != 1 {
		t.Fatalf("release after stepping back: %v %v", err, r.out.batches)
	}
	// After a restart the latest day is rebuilt from the log.
	r.restart()
	if res := emit(t, r.e, skill("contacts")); res.Outcome != Duplicate {
		t.Fatalf("after restart, a hint still waiting: %s", res.Outcome)
	}
}

// TestOSS1RestartKeepsState: the waiting batch, open asks, and today's
// dedupe are rebuilt from the file log after a restart.
func TestOSS1RestartKeepsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hints.jsonl")
	log, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, Config{Log: log, Policy: map[string]Mode{"security": Ask}})
	emit(t, r.e, good())
	ask := emit(t, r.e, vuln)
	r.cfg.Log, err = OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	r.restart()
	if res := emit(t, r.e, good()); res.Outcome != Duplicate {
		t.Fatalf("after restart: %s", res.Outcome)
	}
	if p := r.e.Pending(); len(p) != 1 || p[0].ID != ask.ID {
		t.Fatalf("pending after restart %+v", p)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, good()) {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS1LoggedBeforeSent: the batch's Forwarded record exists before
// the outbox is called, so nothing crosses unlogged. A failed send is
// logged and the same set is resent for the same day at the next release,
// also after a restart, ahead of hints queued since.
func TestOSS1LoggedBeforeSent(t *testing.T) {
	r := newRig(t, Config{})
	emit(t, r.e, good())
	emit(t, r.e, vuln)
	var refs int
	r.out.onSend = func() {
		refs = 0
		for _, rec := range records(t, r.log) {
			if rec.Outcome == Forwarded {
				refs += len(rec.Refs)
			}
		}
	}
	r.out.fail = errors.New("down")
	if err := r.nextRelease(); err == nil {
		t.Fatal("release with failing outbox succeeded")
	}
	if refs != 2 {
		t.Fatalf("log had %d forwarded hints when the outbox was called", refs)
	}
	emit(t, r.e, skill("email")) // queued after the failed batch
	r.out.fail = nil
	r.restart()
	r.now = r.now.Add(24 * time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 1 || len(r.out.batches[0]) != 2 || contains(r.out.batches[0], canon(t, skill("email"))) || r.out.days[0] != "2026-10-06" {
		t.Fatalf("retry sent %v for %v", r.out.batches, r.out.days)
	}
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

// TestOSS5CrashBetweenSendAndCommit: a batch the outbox took but whose Sent
// record was never written is resent after a restart, the same set for the
// same day, so the outbox's idempotent Send can drop the repeat; a vuln
// hint in it is never lost. Then normal batches resume.
func TestOSS5CrashBetweenSendAndCommit(t *testing.T) {
	log := &failSent{}
	r := newRig(t, Config{Log: log})
	emit(t, r.e, vuln)
	emit(t, r.e, good())
	if err := r.nextRelease(); err == nil {
		t.Fatal("commit failure not reported")
	}
	r.cfg.Log = &log.MemLog // the restarted box writes normally
	r.restart()
	emit(t, r.e, skill("email"))
	r.now = r.now.Add(time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 2 || r.out.days[0] != r.out.days[1] || strings.Join(r.out.batches[0], "|") != strings.Join(r.out.batches[1], "|") {
		t.Fatalf("resend %v for %v", r.out.batches, r.out.days)
	}
	if err := r.nextRelease(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 3 || r.out.batches[2][0] != canon(t, skill("email")) {
		t.Fatalf("next batch %v", r.out.batches)
	}
	var sent int
	for _, rec := range records(t, r.log) {
		if rec.Outcome == Sent {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("%d Sent records", sent)
	}
}

// TestOSS7AsksBoundedAndExpire: open asks are bounded, and an ask the
// owner has not answered within DedupeDays expires as declined.
func TestOSS7AsksBoundedAndExpire(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"skills": Ask}, MaxPending: 2})
	emit(t, r.e, skill("calendar"))
	emit(t, r.e, skill("email"))
	if res := emit(t, r.e, skill("notes")); res.Outcome != OverLimit {
		t.Fatalf("third ask: %s", res.Outcome)
	}
	r.now = day0.Add(7 * 24 * time.Hour)
	if res := emit(t, r.e, skill("notes")); res.Outcome != Asked {
		t.Fatalf("after expiry: %s", res.Outcome)
	}
	if p := r.e.Pending(); len(p) != 1 {
		t.Fatalf("pending %+v", p)
	}
	var expired int
	for _, rec := range records(t, r.log) {
		if rec.Outcome == Expired {
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("%d expired", expired)
	}
	r.restart()
	if p := r.e.Pending(); len(p) != 1 {
		t.Fatalf("pending after restart %+v", p)
	}
}

// TestOSS1TornLogTail: a log whose last line was cut off by a crash mid-write
// opens with that line removed (nothing it described happened, since a
// record is written before its effect) and a note of the repair.
func TestOSS1TornLogTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hints.jsonl")
	l, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append(Record{Seq: 1, Day: "2026-10-05", Outcome: Refused})
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":2,"day":"2026-10-0`)
	f.Close()
	l2, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if !l2.Repaired() {
		t.Fatal("repair not reported")
	}
	if err := l2.Append(Record{Seq: 2, Day: "2026-10-05", Outcome: Refused}); err != nil {
		t.Fatal(err)
	}
	if rs := records(t, l2); len(rs) != 2 || rs[1].Seq != 2 {
		t.Fatalf("records %+v", rs)
	}
	// Damage before the last line is not a torn write; it still fails.
	os.WriteFile(path, []byte("{bad\n{\"seq\":1}\n"), 0o600)
	if _, err := OpenFileLog(path); err == nil {
		t.Fatal("corrupt middle line accepted")
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestOSS1DedupeSevenDays: a hint identical to one queued in the last
// seven days is a duplicate, also after a restart; on the eighth day it
// may be queued again. The defaults are the arbitrator's: five hints a
// batch, two of them reserved for embargo kinds.
func TestOSS1DedupeSevenDays(t *testing.T) {
	r := newRig(t, Config{})
	if r.e.cfg.DailyLimit != 5 || r.e.cfg.EmbargoReserve != 2 || r.e.cfg.DedupeDays != 7 {
		t.Fatalf("defaults %d/%d/%d", r.e.cfg.DailyLimit, r.e.cfg.EmbargoReserve, r.e.cfg.DedupeDays)
	}
	emit(t, r.e, good())
	if err := r.nextRelease(); err != nil || len(r.out.all()) != 1 {
		t.Fatalf("release: %v %v", err, r.out.all())
	}
	r.now = day0.Add(6 * 24 * time.Hour)
	r.restart()
	if res := emit(t, r.e, good()); res.Outcome != Duplicate {
		t.Fatalf("day 6: %s", res.Outcome)
	}
	r.now = day0.Add(7 * 24 * time.Hour)
	if res := emit(t, r.e, good()); res.Outcome != Queued {
		t.Fatalf("day 7: %s", res.Outcome)
	}
}

// TestOSS5ResendIsTheRecordedSet: the resend after a restart is the
// canonical bytes recorded when the batch was formed, so a schema change
// in between (here a new version) cannot alter or empty the set.
func TestOSS5ResendIsTheRecordedSet(t *testing.T) {
	log := &failSent{}
	r := newRig(t, Config{Log: log})
	emit(t, r.e, vuln)
	emit(t, r.e, good())
	r.nextRelease()
	v2, err := Parse(bytes.Replace(publicSchema, []byte(`"version": 1`), []byte(`"version": 2`), 1))
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Log, r.cfg.Schema = &log.MemLog, v2
	r.restart()
	r.now = r.now.Add(time.Hour)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if len(r.out.batches) != 2 || strings.Join(r.out.batches[0], "|") != strings.Join(r.out.batches[1], "|") || r.out.days[0] != r.out.days[1] {
		t.Fatalf("resend %v for %v", r.out.batches, r.out.days)
	}
}

// TestOSS5CrashBeforeSend: a crash after the Forwarded record but before
// the outbox is called leaves no SendFailed record; the restart still
// resends the batch.
func TestOSS5CrashBeforeSend(t *testing.T) {
	r := newRig(t, Config{})
	emit(t, r.e, vuln)
	r.out.onSend = func() { panic("crash") }
	func() {
		defer func() { recover() }()
		r.nextRelease()
	}()
	r.out.onSend = nil
	for _, rec := range records(t, r.log) {
		if rec.Outcome == SendFailed || rec.Outcome == Sent {
			t.Fatalf("unexpected %s record", rec.Outcome)
		}
	}
	r.restart()
	r.now = r.now.Add(time.Minute)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, vuln) {
		t.Fatalf("sent %v", got)
	}
}

// TestOSS1SendFailureLoggedOnce: repeated failed retries of one batch log
// one SendFailed record, also across a restart; Pending never lists an
// expired ask.
func TestOSS1SendFailureLoggedOnce(t *testing.T) {
	r := newRig(t, Config{Policy: map[string]Mode{"security": Ask}})
	emit(t, r.e, good())
	ask := emit(t, r.e, vuln)
	r.out.fail = errors.New("down")
	r.nextRelease()
	for i := 0; i < 3; i++ {
		r.now = r.now.Add(time.Hour)
		r.e.Release()
	}
	r.restart()
	r.now = r.now.Add(time.Hour)
	r.e.Release()
	n := 0
	for _, rec := range records(t, r.log) {
		if rec.Outcome == SendFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d SendFailed records", n)
	}
	r.now = day0.Add(8 * 24 * time.Hour)
	for _, p := range r.e.Pending() {
		if p.ID == ask.ID {
			t.Fatal("Pending lists an expired ask")
		}
	}
}

// TestOSS5LegacyForwardedWithoutBatch: a Forwarded record written before
// records carried the batch bytes is rebuilt from its Refs, never resent as
// an empty set and committed.
func TestOSS5LegacyForwardedWithoutBatch(t *testing.T) {
	log := &MemLog{}
	log.Append(Record{Seq: 1, Day: "2026-10-05", Outcome: Queued, Category: "security", Kind: vuln.Kind, Fields: vuln.Fields})
	log.Append(Record{Seq: 2, Day: "2026-10-06", Outcome: Forwarded, Refs: []int{1}})
	r := newRig(t, Config{Log: log})
	r.now = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC).Add(DefaultReleaseAt)
	if err := r.e.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.out.all(); len(got) != 1 || got[0] != canon(t, vuln) || r.out.days[0] != "2026-10-06" {
		t.Fatalf("sent %v for %v", got, r.out.days)
	}
}
