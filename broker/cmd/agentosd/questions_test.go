package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CAP-10, CH-15, ARC-6

// Agents' questions run in agentosd (W9): the guest tools reach the book
// with the lineage as asker, the owner channel's answer hook and the
// gate's shared budget are the book's, and with no owner channel nothing
// is offered.
func TestQuestionsRunInAgentosd(t *testing.T) {
	dir := t.TempDir()
	qs := &questions{}
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	qs.wire(&cfg) // as main does
	ctx, cancel := context.WithCancel(context.Background())
	defer qs.wait() // the loops write into dir until they stop
	defer cancel()
	if _, ok := qs.Answer(ctx, "Q100 yes"); ok {
		t.Fatal("answered before the book opened")
	}
	if qs.tools() != nil {
		t.Fatal("tools offered before the book opened")
	}
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if l := cfg.Clock(); l != "" {
		t.Fatalf("clock line before the guard opened: %q", l)
	}
	guard, err := qs.open(ctx, d, &preempter{}, defaultQuestionConfig(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Flush()
	// STATUS carries the guard's time check (W9a, UX R3 on #95).
	if l := cfg.Clock(); !strings.HasPrefix(l, "Time check: ") {
		t.Fatalf("STATUS clock line: %q", l)
	}
	if qs.tools() == nil {
		t.Fatal("no tools for the guest plane once the book is open")
	}

	text, handled, err := qs.Call(ctx, "agent", "agent", question.ToolAsk,
		json.RawMessage(`{"request_id":"q1","question":"Which slot?","choices":["9:00","9:30"],"default":"9:30","wait_minutes":30}`))
	if err != nil || !handled {
		t.Fatalf("ask: %v %v", handled, err)
	}
	var res question.ToolResult
	if err := json.Unmarshal([]byte(text), &res); err != nil || res.Question != "Q100" {
		t.Fatalf("ask result %s", text)
	}
	if _, _, err := qs.Call(ctx, "other", "other", question.ToolStatus, json.RawMessage(`{"request_id":"q1"}`)); err == nil {
		t.Fatal("another lineage read the question")
	}
	if _, handled, _ := qs.Call(ctx, "agent", "agent", "effect_request", nil); handled {
		t.Fatal("took the effect tool")
	}
	// Hidden is owner.SecretShaped: an answer only it calls secret-shaped
	// (a short code beside a code word; the book's own checks pass it) is
	// refused.
	if reply, ok := cfg.Answer(ctx, "Q100 my pin is A1B2"); !ok || !strings.Contains(reply, "Codes and keys") {
		t.Fatalf("secret-shaped answer: %q %v", reply, ok)
	}
	if reply, ok := cfg.Answer(ctx, "Q100 9:00"); !ok || !strings.Contains(reply, "Q100") {
		t.Fatalf("answer hook: %q %v", reply, ok)
	}
	// Reserve is the gate's: with the hour's CH-15 budget spent on the
	// gate, a new question is held, not texted.
	for d.Gate().Reserve(time.Now()) {
	}
	text, _, err = qs.Call(ctx, "agent", "agent", question.ToolAsk,
		json.RawMessage(`{"request_id":"q2","question":"Lunch at noon?","default":"yes","wait_minutes":30}`))
	if err != nil || !strings.Contains(text, `"state":"held"`) {
		t.Fatalf("question with the budget spent: %s %v", text, err)
	}
	// A locked session never reaches the hook, so the reply is the unlock
	// prompt (the hook's own tests cover the unlocked path).
	if got := d.Owner().Handle(ctx, ownerNum, "Q100 9:30"); len(got) != 1 || !strings.HasPrefix(got[0], "Locked.") {
		t.Fatalf("locked reply: %q", got)
	}

	// No owner channel: the book does not open.
	cfg2 := cfg
	cfg2.OwnerState, cfg2.JournalPath, cfg2.SocketDir = "", filepath.Join(dir, "j2.log"), filepath.Join(dir, "run2")
	d2, err := daemon.Run(ctx, cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&questions{}).open(ctx, d2, &preempter{}, defaultQuestionConfig(t.TempDir())); err == nil {
		t.Fatal("opened with no owner channel")
	}
}

// REQ: TIM-1, CH-11

// W9a (L3 S1 on #95): an unreadable clock.json restricts the guard until
// phone-network time agrees, which with no carrier is never; STATUS says
// so, since the guard texts nothing yet.
func TestStatusShowsAnUnreadableClockRestriction(t *testing.T) {
	dir := t.TempDir()
	qs := &questions{}
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	qs.wire(&cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer qs.wait() // the loops write into dir until they stop
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	qc := defaultQuestionConfig(dir)
	if err := os.WriteFile(qc.ClockPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := qs.open(ctx, d, &preempter{}, qc)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Flush()
	if l := cfg.Clock(); !strings.HasPrefix(l, "Time check: restricted since") || !strings.Contains(l, "saved check unreadable") {
		t.Fatalf("STATUS clock line: %q", l)
	}
}
