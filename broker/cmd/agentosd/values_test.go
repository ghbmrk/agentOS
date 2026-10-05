package main

// REQ: LOOP-4, CAP-5, CAP-3, CRED-7

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

type succeeds struct{}

func (succeeds) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (succeeds) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

type valuesRig struct {
	t      *testing.T
	now    time.Time
	eng    *journal.Engine
	values *taskValues
}

func newValuesRig(t *testing.T) *valuesRig {
	r := &valuesRig{t: t, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	// The journal keeps no values, as in the box (daemon's redactAll).
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{"task": succeeds{}},
		func(s string) string {
			if s == "" {
				return ""
			}
			return daemon.Redacted
		}, journal.WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	r.eng = eng
	dir := t.TempDir()
	r.values, err = openTaskValues(change.FileStore{Path: filepath.Join(dir, "values.json")}, filepath.Join(dir, "values.key"),
		func() time.Time { return r.now }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// weekly runs the recurring task (draft the weekly report to someone, then
// send it), showing each intent to the value record as the gate would, and
// returns its first intent.
func (r *valuesRig) weekly(goal, to string, week int) string {
	r.t.Helper()
	steps := []journal.Intent{
		{Action: "draft.create", Params: map[string]any{"subject": "Weekly report", "to": to, "meta": map[string]any{"week": week}}},
		{Action: "message.send", Recipients: []string{to}},
	}
	first := ""
	for i, in := range steps {
		in.ID, in.GoalID, in.Origin, in.Account, in.Executor, in.Label = fmt.Sprintf("guest-a/%s-%d", goal, i+1), goal, "guest:a", "mail", "task", "private"
		if _, err := r.eng.Submit(in); err != nil {
			r.t.Fatal(err)
		}
		if _, err := r.eng.Authorize(context.Background(), in.ID); err != nil {
			r.t.Fatal(err)
		}
		r.values.observe(in)
		if _, err := r.eng.Dispatch(context.Background(), in.ID); err != nil {
			r.t.Fatal(err)
		}
		r.now = r.now.Add(30 * time.Second)
		if first == "" {
			first = in.ID
		}
	}
	r.now = r.now.Add(time.Minute)
	return first
}

func (r *valuesRig) judge(goal, first string, v grants.OwnerVerdict) {
	r.t.Helper()
	q := journal.Quality{Verdict: journal.VerdictGood, Source: "owner"}
	switch v {
	case grants.OwnerAcceptedImplicitly:
		q.Source = "owner-implicit"
	case grants.OwnerDeclined:
		q.Verdict = journal.VerdictWrong
	}
	if _, err := r.eng.RecordQuality(first, q); err != nil {
		r.t.Fatal(err)
	}
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{ID: first, GoalID: goal}, Verdict: v})
}

type devAll struct{ ids []string }

func (d devAll) Dev(change.Class) []change.Case {
	var out []change.Case
	for _, id := range d.ids {
		out = append(out, change.Case{ID: "case-" + id, Task: id})
	}
	return out
}

// W3-values: with the journal keeping no values, the compiler builds a
// skill from the record of tasks the owner said YES to, and from nothing
// the plain journal holds.
func TestCompiledSkillsReadKeptValues(t *testing.T) {
	r := newValuesRig(t)
	for i, to := range []string{"ann@example.test", "bo@example.test", "cy@example.test"} {
		g := fmt.Sprint("g", i)
		r.judge(g, r.weekly(g, to, 40+i), grants.OwnerAccepted)
	}
	// Through Loop 1's builder (L3 MUST-1 on #119): Loop 1 mines evidence
	// from the plain journal, so the builder must read kept values itself.
	for name, v := range map[string]*taskValues{"no values kept": nil, "with values": r.values} {
		b, err := skillBuilder(r.eng, v, devAll{})
		if err != nil {
			t.Fatal(err)
		}
		br := loops.Brief{Hypothesis: loops.Hypothesis{Signal: loops.SignalRepeat, Key: "repeat:k", Evidence: r.eng.List()}}
		plain := fmt.Sprint(br.Hypothesis.Evidence)
		cand, err := b.Build(context.Background(), br)
		if b.Ready(br) != (name == "with values") || (err == nil) != (name == "with values") {
			t.Fatalf("%s: ready %v, build %v", name, b.Ready(br), err)
		}
		if fmt.Sprint(br.Hypothesis.Evidence) != plain || strings.Contains(plain, "@example.test") {
			t.Fatalf("%s: values reached Loop 1's brief", name)
		}
		if name == "with values" && len(cand.Files) == 0 {
			t.Fatal("no skill built")
		}
	}
}

// Security V2: a secret-shaped leaf (value, key, or recipient) is kept as
// the placeholder as a whole, so its run never compiles.
func TestSecretShapedValuesAreNotKept(t *testing.T) {
	r := newValuesRig(t)
	token := "sk-" + strings.Repeat("A1b2", 6) // a synthetic key format
	r.values.observe(journal.Intent{ID: "i1", GoalID: "g", Params: map[string]any{
		"note": "your key " + token, token: "x", "meta": map[string]any{"week": 3, "ok": "plain"},
	}, Recipients: []string{token, "ann@example.test"}})
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{ID: "i1", GoalID: "g"}, Verdict: grants.OwnerAccepted})
	s, ok := r.values.values("g", "i1")
	if !ok {
		t.Fatal("values not kept")
	}
	raw := fmt.Sprint(s)
	if strings.Contains(raw, token) || s.Params["note"] != redactedValue || s.Params[redactedValue] != redactedValue ||
		s.Recipients[0] != redactedValue || s.Recipients[1] != "ann@example.test" ||
		s.Params["meta"].(map[string]any)["ok"] != "plain" {
		t.Fatalf("scrubbed values %+v", s)
	}
	// Numbers and digit strings (security F1 on #119): a card or account
	// number is a long digit run whatever its form, and a short code is
	// read with its key, so "code": 123456 is a code like "code 123456".
	r.values.observe(journal.Intent{ID: "i2", GoalID: "n", Params: map[string]any{
		"card": float64(4111111111111111), "code": float64(123456), "acct": "4111 1111 1111 1111",
		"pin": json.Number("4821"), "otp": "903114", "week": float64(3), "amount": 125.5, "zip": "90210",
	}})
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{ID: "i2", GoalID: "n"}, Verdict: grants.OwnerAccepted})
	n, _ := r.values.values("n", "i2")
	for _, k := range []string{"card", "code", "acct", "pin", "otp"} {
		if n.Params[k] != redactedValue {
			t.Errorf("%s kept as %v", k, n.Params[k])
		}
	}
	if n.Params["week"] != float64(3) || n.Params["amount"] != 125.5 || n.Params["zip"] != "90210" {
		t.Errorf("plain values changed: %+v", n.Params)
	}
	// Credentials recall's scrubber removes (L3 MUST-2 on #119): auth
	// schemes, REV-5 token-URL params, long random-looking strings.
	for _, c := range []string{
		"Bearer " + strings.Repeat("Zq7x", 10),
		"https://cb.example.test/done?access_token=" + strings.Repeat("a1", 8),
		strings.Repeat("0123456789abcdef", 4),
	} {
		if got := r.values.scrubValue(map[string]any{"note": c, "list": []any{c}}); fmt.Sprint(got) != fmt.Sprint(map[string]any{"note": redactedValue, "list": []any{redactedValue}}) {
			t.Errorf("%q kept: %v", c, got)
		}
	}
	for _, c := range []string{"https://shop.example.test/orders?page=2", "Weekly report for the team", "ann@example.test"} {
		if r.values.scrub(c) != c {
			t.Errorf("plain %q scrubbed", c)
		}
	}
	// A redactor wired later (P2-4) marks what it would change too.
	r.values.redact = func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	if r.values.scrub("pw hunter2") != redactedValue || r.values.scrub("fine") != "fine" {
		t.Fatal("the journal's redactor is not applied")
	}
}

// Retention (security V4, arbitrator): values are read only once the owner
// said YES; an implicit acceptance keeps keyed hashes only; NO, UNDO or 30
// days with no verdict drop them; at most maxValueGoals goals.
func TestTaskValuesFollowTheOwnersVerdict(t *testing.T) {
	r := newValuesRig(t)
	obs := func(goal, to string) {
		r.values.observe(journal.Intent{ID: goal + "/1", GoalID: goal, Params: map[string]any{"to": to, "count": float64(7)}, Recipients: []string{to}})
	}
	obs("yes", "ann@example.test")
	if _, ok := r.values.values("yes", "yes/1"); ok {
		t.Fatal("values read before any verdict")
	}
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: "yes"}, Verdict: grants.OwnerAccepted})
	if s, ok := r.values.values("yes", "yes/1"); !ok || s.Params["to"] != "ann@example.test" {
		t.Fatalf("after YES: %+v %v", s, ok)
	}

	obs("imp1", "bo@example.test")
	obs("imp2", "cy@example.test")
	obs("imp3", "bo@example.test")
	for _, g := range []string{"imp1", "imp2", "imp3"} {
		r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: g}, Verdict: grants.OwnerAcceptedImplicitly})
	}
	h1, _ := r.values.values("imp1", "imp1/1")
	h2, _ := r.values.values("imp2", "imp2/1")
	h3, _ := r.values.values("imp3", "imp3/1")
	if strings.Contains(fmt.Sprint(h1, h2), "@") || h1.Params["to"] == h2.Params["to"] || h1.Params["to"] != h3.Params["to"] ||
		h1.Recipients[0] != h1.Params["to"] {
		t.Fatalf("implicit values are not keyed hashes: %+v %+v %+v", h1, h2, h3)
	}
	if c, ok := h1.Params["count"].(string); !ok || c != h2.Params["count"] { // numbers too (security R1 on #119)
		t.Fatalf("implicit number kept as %v", h1.Params["count"])
	}
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: "imp1"}, Verdict: grants.OwnerAccepted})
	if h, _ := r.values.values("imp1", "imp1/1"); h.Params["to"] != h1.Params["to"] {
		t.Fatal("a YES after an implicit acceptance brought values back")
	}

	for _, v := range []grants.OwnerVerdict{grants.OwnerDeclined, grants.OwnerUndone} {
		obs("drop", "dee@example.test")
		r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: "drop"}, Verdict: v})
		r.values.mu.Lock()
		_, kept := r.values.st["drop"]
		r.values.mu.Unlock()
		if kept {
			t.Fatalf("values kept after %s", v)
		}
	}

	obs("stale", "eve@example.test")
	r.now = r.now.Add(keepValues + time.Hour)
	obs("fresh", "fay@example.test")
	r.values.mu.Lock()
	_, stale := r.values.st["stale"]
	_, yes := r.values.st["yes"]
	r.values.mu.Unlock()
	if stale || yes {
		t.Fatal("values kept past 30 days")
	}
	for i := 0; i < maxValueGoals+5; i++ {
		obs(fmt.Sprint("n", i), "x@example.test")
	}
	r.values.mu.Lock()
	n := len(r.values.st)
	r.values.mu.Unlock()
	if n != maxValueGoals {
		t.Fatalf("%d goals kept", n)
	}
}

// Security V1, V3, UX-S3-2: in agentosd the record sees guest intents only
// while learning is on, and only the compiler reads it; Loop 1's mining
// reads the journal, which keeps no values.
func TestTaskValuesReachOnlyTheCompiler(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Grants.Observe == nil || lp.mining.e != &lp.eng {
		t.Fatal("values are not observed, or mining reads something else")
	}
	in := journal.Intent{ID: "agent/1", GoalID: "owner:1", Origin: "guest:agent", Params: map[string]any{"to": "ann@example.test"}}
	cfg.Grants.Observe(journal.Intent{ID: "loop/1", Origin: "loops"})
	cfg.Grants.Observe(in)
	if len(lp.observed) != 1 {
		t.Fatalf("observed %d intents, want the guest's one", len(lp.observed))
	}
	<-lp.observed
	// A full queue drops, never blocks the gate.
	for len(lp.observed) < maxObserved {
		lp.observed <- in
	}
	cfg.Grants.Observe(in)
	for len(lp.observed) > 0 {
		<-lp.observed
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	lp.attach(ctx, d)
	if got := d.Owner().Handle(ctx, ownerNum, "LEARNING OFF"); len(got) != 1 || lp.sched.Settings().On(loops.Improve) {
		t.Fatalf("LEARNING OFF: %q", got)
	}
	off := in
	off.ID, off.GoalID = "agent/2", "owner:off"
	cfg.Grants.Observe(off)
	if len(lp.observed) != 0 {
		t.Fatal("queued while learning is off")
	}
	// Queued before LEARNING OFF, recorded after: checked again at dequeue.
	// The loop handles one intent at a time, so once a second one has left
	// the queue the first is done.
	lp.observed <- off
	waitEmpty := func() {
		for deadline := time.Now().Add(5 * time.Second); len(lp.observed) > 0; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the record never drained its queue")
			}
		}
	}
	waitEmpty()
	lp.observed <- journal.Intent{ID: "agent/3", GoalID: "owner:next", Origin: "guest:agent"}
	waitEmpty()
	lp.values.mu.Lock()
	_, kept := lp.values.st["owner:off"]
	lp.values.mu.Unlock()
	if kept {
		t.Fatal("values observed while learning is off")
	}
	cancel()
	d.Wait()
}

// Bounds and load checks (L3 SHOULDs on #119): at most maxValueSteps steps
// a goal, nothing read after keepValues, a malformed record or a key file
// others can read is refused, and an implicit run's data-shaped map keys
// are hashed like its values.
func TestTaskValuesBounds(t *testing.T) {
	r := newValuesRig(t)
	for i := 0; i <= maxValueSteps; i++ {
		r.values.observe(journal.Intent{ID: fmt.Sprint("cap/", i), GoalID: "cap", Params: map[string]any{"n": "x"}})
	}
	r.values.observe(journal.Intent{ID: "old/1", GoalID: "old", Params: map[string]any{"n": "x"}})
	for _, g := range []string{"cap", "old"} {
		r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: g}, Verdict: grants.OwnerAccepted})
	}
	if _, ok := r.values.values("cap", fmt.Sprint("cap/", maxValueSteps-1)); !ok {
		t.Fatal("step within the cap not kept")
	}
	if _, ok := r.values.values("cap", fmt.Sprint("cap/", maxValueSteps)); ok {
		t.Fatal("step over the cap kept")
	}
	r.now = r.now.Add(keepValues + time.Hour)
	if _, ok := r.values.values("old", "old/1"); ok {
		t.Fatal("values read after keepValues")
	}

	r.values.observe(journal.Intent{ID: "imp/1", GoalID: "imp", Params: map[string]any{
		"to": "x", "by_sender": map[string]any{"ann@example.test": "y", "folder_id": "z"}}})
	r.values.verdict(grants.OwnerOutcome{Intent: journal.Intent{GoalID: "imp"}, Verdict: grants.OwnerAcceptedImplicitly})
	h, _ := r.values.values("imp", "imp/1")
	by, _ := h.Params["by_sender"].(map[string]any)
	if strings.Contains(fmt.Sprint(h), "ann@") || by == nil || by["folder_id"] == nil || len(by) != 2 {
		t.Fatalf("implicit keys: %+v", h)
	}

	dir := t.TempDir()
	store := change.FileStore{Path: filepath.Join(dir, "values.json")}
	at, _ := json.Marshal(r.now)
	big := map[string]valueStep{}
	for i := 0; i <= maxValueSteps; i++ {
		big[fmt.Sprint(i)] = valueStep{}
	}
	bigJSON, _ := json.Marshal(big)
	if err := store.Save([]byte(`{"null":null,"nosteps":{"at":` + string(at) + `,"good":true},` +
		`"big":{"at":` + string(at) + `,"good":true,"steps":` + string(bigJSON) + `},` +
		`"ok":{"at":` + string(at) + `,"good":true,"steps":{"ok/1":{"params":{"n":"x"}}}}}`)); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "values.key")
	v, err := openTaskValues(store, keyPath, func() time.Time { return r.now }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.st) != 1 || v.st["ok"] == nil {
		t.Fatalf("malformed goals loaded: %v", v.st)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openTaskValues(store, keyPath, func() time.Time { return r.now }, t.Logf); err == nil {
		t.Fatal("a key file others can read was used")
	}
}
