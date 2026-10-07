package hint

import (
	"testing"
	"time"
)

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
