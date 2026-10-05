package main

// REQ: CH-20, CH-19, CH-10

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

const destAddr = "owner@example.test"

// fakeEvidenceGate is the gate as the reply router and the setting use
// it: it records what was submitted and ends each intent in state.
type fakeEvidenceGate struct {
	addr, acct string
	state      journal.State
	reason     string
	subs       []journal.Intent
}

func (f *fakeEvidenceGate) Evidence() (string, string) { return f.addr, f.acct }

func (f *fakeEvidenceGate) Submit(in journal.Intent) (journal.Status, error) {
	f.subs = append(f.subs, in)
	return journal.Status{Intent: in, State: journal.Pending}, nil
}

func (f *fakeEvidenceGate) Authorize(_ context.Context, id string) (journal.Status, error) {
	st := journal.Status{State: f.state, Intent: f.subs[len(f.subs)-1]}
	if f.state != journal.Pending {
		st.State = journal.Authorized
	}
	if f.state == journal.Denied {
		st.State = journal.Denied
		st.Permission.Reason = f.reason
	}
	return st, nil
}

func (f *fakeEvidenceGate) Dispatch(_ context.Context, id string) (journal.Status, error) {
	return journal.Status{State: f.state, Intent: f.subs[len(f.subs)-1]}, nil
}

type evRig struct {
	gate  *fakeEvidenceGate
	sent  []string
	ev    *evidence
	now   time.Time
	store *change.MemStore
}

func newEvRig(t *testing.T, addr string) *evRig {
	r := &evRig{gate: &fakeEvidenceGate{addr: addr, acct: "mail", state: journal.Succeeded},
		now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), store: &change.MemStore{}}
	if addr == "" {
		r.gate.acct = ""
	}
	r.ev = &evidence{
		notify: func(s string) error { r.sent = append(r.sent, s); return nil },
		owns: func(a string) (string, bool) {
			return "mail", a == destAddr || a == "alias@example.test"
		},
		kept: &keptReplies{store: r.store, now: func() time.Time { return r.now }},
		logf: t.Logf,
	}
	r.ev.gate.Store(&evidenceGateBox{r.gate})
	return r
}

const longReply = "Your landlord agreed to fix the boiler on Thursday. " +
	"He also mentioned the rent review: the new figure is in the attached letter, along with the clause about pets and the parking space."

// TestPrivateRepliesGoToTheDestination: with a destination set, a reply
// from a private machine is delivered there by the broker and the text
// carries only a summary and a pointer (CH-20); a public machine's reply,
// or any reply with no destination, is texted as before (DEP-3).
func TestPrivateRepliesGoToTheDestination(t *testing.T) {
	r := newEvRig(t, destAddr)
	r.ev.reply("agent", true, longReply)
	if len(r.gate.subs) != 1 {
		t.Fatalf("submitted %d", len(r.gate.subs))
	}
	in := r.gate.subs[0]
	if opDeliver != mail.OpDeliver || mailExecutor != mail.Tool {
		t.Fatal("the mail adapter's names changed")
	}
	if in.Origin != grants.OriginEvidence || in.Action != mail.OpDeliver || in.Account != "mail" || in.Executor != "mail" ||
		len(in.Recipients) != 1 || in.Recipients[0] != destAddr || in.Params[grants.ParamBody] != longReply || len(in.Params) != 1 {
		t.Fatalf("delivery intent %+v", in)
	}
	want := "Your landlord agreed to fix the boiler on Thursday. Full reply sent to o***@example.test."
	if len(r.sent) != 1 || r.sent[0] != want {
		t.Fatalf("texted %q", r.sent)
	}
	r.ev.reply("agent", false, longReply)
	if len(r.gate.subs) != 1 || r.sent[1] != longReply {
		t.Fatalf("public reply: %q", r.sent)
	}
	n := newEvRig(t, "")
	n.ev.reply("agent", true, longReply)
	if len(n.gate.subs) != 0 || len(n.sent) != 1 || n.sent[0] != longReply {
		t.Fatalf("no destination: %q", n.sent)
	}
}

// TestRedirectedTextsFitOneMessage: the summary is the reply's first line
// or sentence, cut so the whole text with its prefix fits one SMS, and a
// summary that looks like a code is left out (CH-19).
func TestRedirectedTextsFitOneMessage(t *testing.T) {
	r := newEvRig(t, destAddr)
	r.ev.reply("agent", true, strings.Repeat("word ", 100))
	r.ev.reply("agent", true, "First line\nsecond line")
	r.ev.reply("agent", true, "Your login code is 482913. Use it soon.")
	for _, s := range r.sent {
		if len(owner.AgentPrefix+s) > smsSegment || !strings.HasSuffix(s, " Full reply sent to o***@example.test.") {
			t.Fatalf("text %q (%d)", s, len(owner.AgentPrefix+s))
		}
	}
	long := newEvRig(t, "o@"+strings.Repeat("d", 200)+".test")
	long.ev.reply("agent", true, longReply)
	if !strings.HasPrefix(long.sent[0], noSummary+" Full reply sent to o***@ddd") {
		t.Fatalf("long domain: %q", long.sent[0])
	}
	if !strings.HasPrefix(r.sent[0], "word word") || !strings.Contains(r.sent[0], "...") {
		t.Fatalf("long summary %q", r.sent[0])
	}
	if r.sent[1] != "First line Full reply sent to o***@example.test." {
		t.Fatalf("first line %q", r.sent[1])
	}
	if r.sent[2] != "Your agent replied. Full reply sent to o***@example.test." || owner.SecretShaped(r.sent[2]) {
		t.Fatalf("code summary %q", r.sent[2])
	}
}

// TestAFailedDeliveryKeepsTheReply: when delivery does not succeed, the
// private reply still never goes by text; it is kept, bounded, for the
// box's Wi-Fi page.
func TestAFailedDeliveryKeepsTheReply(t *testing.T) {
	for _, st := range []journal.State{journal.Denied, journal.NotApplied, journal.OutcomeUnknown, journal.Pending} {
		r := newEvRig(t, destAddr)
		r.gate.state = st
		r.ev.reply("agent", true, longReply)
		if len(r.sent) != 1 || strings.Contains(r.sent[0], "rent") || !strings.HasSuffix(r.sent[0], keptPointer) {
			t.Fatalf("%s: texted %q", st, r.sent)
		}
		if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != longReply {
			t.Fatalf("%s: kept %+v", st, k)
		}
	}
	r := newEvRig(t, destAddr)
	r.gate.state = journal.Denied
	for i := 0; i < maxKept+5; i++ {
		r.ev.reply("agent", true, fmt.Sprintf("reply %d.", i))
	}
	if k := r.ev.kept.list(); len(k) != maxKept || k[0].Text != "reply 5." {
		t.Fatalf("kept %d, first %+v", len(k), k[0])
	}
	r.now = r.now.Add(keepReplies + time.Minute)
	r.ev.reply("agent", true, "late.")
	if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != "late." {
		t.Fatalf("expired replies kept: %d", len(k))
	}
	// On disk, only the broker reads it.
	path := filepath.Join(t.TempDir(), "kept.json")
	k := &keptReplies{store: change.FileStore{Path: path}, now: time.Now}
	k.keep("x")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept file %v %v", fi, err)
	}
}

// TestEmailRepliesSetting: the owner's text asks the gate for the change
// (high tier with the local page, decided there), only in an unlocked
// session, and only for one of the connected account's own addresses.
func TestEmailRepliesSetting(t *testing.T) {
	ctx := context.Background()
	r := newEvRig(t, "")
	r.gate.state = journal.Pending
	for _, msg := range []string{"email replies", "email replies to me", "please email replies to owner@example.test", "EMAIL REPLIES OFF now"} {
		if got, ok := r.ev.settings(ctx, msg, true); ok {
			t.Fatalf("%q taken: %q", msg, got)
		}
	}
	if _, ok := r.ev.settings(ctx, "EMAIL REPLIES TO owner@example.test", false); ok || len(r.gate.subs) != 0 {
		t.Fatal("a locked session changed where private replies go")
	}
	got, ok := r.ev.settings(ctx, "Email replies to Owner@Example.test", true)
	if !ok || got != evidenceAsked || len(r.gate.subs) != 1 {
		t.Fatalf("set: %q %v", got, ok)
	}
	in := r.gate.subs[0]
	if in.Origin != grants.OriginOwner || in.Action != journal.ActionEvidence ||
		in.Params[grants.ParamEvidenceAddress] != destAddr || in.Params[grants.ParamEvidenceAccount] != "mail" {
		t.Fatalf("intent %+v", in)
	}
	if got, _ := r.ev.settings(ctx, "email replies to eve@example.net", true); got != evidenceNotOwn || len(r.gate.subs) != 1 {
		t.Fatalf("other address: %q", got)
	}
	if got, _ := r.ev.settings(ctx, "EMAIL REPLIES OFF", true); got != evidenceAsked || r.gate.subs[1].Params[grants.ParamEvidenceAddress] != "" {
		t.Fatalf("off: %q", got)
	}
	r.gate.state, r.gate.reason = journal.Denied, "no local page"
	if got, _ := r.ev.settings(ctx, "EMAIL REPLIES OFF", true); got != "Not changed: no local page." {
		t.Fatalf("denied: %q", got)
	}
	r.ev.owns = nil
	if got, _ := r.ev.settings(ctx, "EMAIL REPLIES TO owner@example.test", true); got != evidenceNoMail {
		t.Fatalf("no mail account: %q", got)
	}
	// STATUS names the destination, masked.
	if r.ev.note() != "" {
		t.Fatalf("note with none set: %q", r.ev.note())
	}
	r.gate.addr = destAddr
	if r.ev.note() != "Private replies: emailed to o***@example.test." {
		t.Fatalf("note %q", r.ev.note())
	}
	// The setting goes ahead of the loops' and passes the rest on.
	var cfg daemon.Config
	cfg.Settings = func(context.Context, string, bool) (string, bool) { return "loops", true }
	r.ev.wire(&cfg)
	if got, _ := cfg.Settings(ctx, "LOOPS OFF", true); got != "loops" {
		t.Fatalf("passed on: %q", got)
	}
	if got, _ := cfg.Settings(ctx, "EMAIL REPLIES OFF", true); got == "loops" || len(cfg.Notes) != 1 {
		t.Fatalf("not ahead: %q", got)
	}
	var unset evidence
	if got, ok := unset.settings(ctx, "EMAIL REPLIES OFF", true); !ok || got != evidenceStarting {
		t.Fatalf("before the daemon runs: %q", got)
	}
}
