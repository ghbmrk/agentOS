package owner

import (
	"bytes"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-12, CH-15, CH-19, CH-21
// MUT-kill-5974-owner (#6670), part 3: the pacer.go statements mutgate's
// deletion left alive, each pinned by a test that fails without it. They
// call the function that holds the line directly where they can.

// pacerLog runs f with the standard logger captured and returns what it
// wrote.
func pacerLog(f func()) string {
	var b bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&b)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	f()
	return b.String()
}

// pacerRig opens a channel on a store holding st, with the clock at t.
func pacerRig(t *testing.T, st State, store *failStore, at time.Time) *rig {
	t.Helper()
	if store == nil {
		store = &failStore{}
	}
	if err := store.MemStore.Save(st); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, store)
	r.now = at
	r.ch = r.open()
	return r
}

// pacerNoModem is a channel like r's with no modem.
func pacerNoModem(r *rig) *Channel {
	r.edit = func(c *Config) { c.Modem = nil }
	ch := r.open()
	r.edit = nil
	return ch
}

const voiceLog = "held agent text that mentioned a code"

// SetCurrent(nil) removes the hook: a text with subjects is then never
// confirmed, rather than calling a nil hook.
func TestMutPacerSetCurrentNilRemovesTheHook(t *testing.T) {
	r := newRig(t, nil)
	r.ch.SetCurrent(func([]string) bool { return true })
	r.ch.SetCurrent(nil)
	if r.ch.stillCurrent(HeldText{Text: "Cleared.", Subjects: []string{"s1"}}) {
		t.Fatal("a text with subjects is current with no hook")
	}
}

// With no modem, every send path refuses before it reaches the modem, and
// Release leaves the hold alone.
func TestMutPacerNoModemRefuses(t *testing.T) {
	r := pacerRig(t, State{Held: []HeldText{{Text: "News.", Class: ClassUpdate}}}, nil,
		time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	ch := pacerNoModem(r)
	if err := ch.Post(ClassUpdate, "News."); err == nil {
		t.Fatal("Post with no modem returned nil")
	}
	if err := ch.PostAbout(ClassUpdate, "Cleared.", []string{"s1"}); err == nil {
		t.Fatal("PostAbout with no modem returned nil")
	}
	if err := ch.NotifyAs(ClassUpdate, "Lunch is booked."); err == nil {
		t.Fatal("NotifyAs with no modem returned nil")
	}
	if err := ch.NotifyNow("Lunch is booked."); err != ErrNoModem {
		t.Fatalf("NotifyNow with no modem: %v", err)
	}
	if err := ch.Release(); err != nil {
		t.Fatalf("Release with no modem: %v", err)
	}
	ch.mu.Lock()
	n := len(ch.codes.st.Held)
	ch.mu.Unlock()
	if n != 1 {
		t.Fatalf("Release with no modem left %d held, want 1", n)
	}
}

// A bad saved setting is logged, naming no value, and reset.
func TestMutPacerCheckPacingLogs(t *testing.T) {
	st := State{Pacing: Pacing{PerHour: MaxTextsPerHour + 1}}
	out := pacerLog(func() { checkPacing(&st) })
	if !strings.Contains(out, "saved pacing setting is invalid") || st.Pacing.PerHour != 0 {
		t.Fatalf("log %q, pacing %+v", out, st.Pacing)
	}
}

// NotifyNow fits agent text to one text.
func TestMutPacerNotifyNowFits(t *testing.T) {
	r := newRig(t, nil)
	long := strings.Repeat("Lunch is booked. ", 60)
	if err := r.ch.NotifyNow(long); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 1 || len(got[0]) >= len(long) || !strings.HasPrefix(got[0], "Lunch is booked.") {
		t.Fatalf("sent %q, want one fitted text", got)
	}
}

// checkAgent logs each text it holds for mentioning a code, alone or
// joined to the agent's earlier texts.
func TestMutPacerHoldVoiceIsLogged(t *testing.T) {
	r := newRig(t, nil)
	if out := pacerLog(func() { _ = r.ch.Converse("Your PIN is") }); !strings.Contains(out, voiceLog) {
		t.Fatalf("a voice-shaped text logged %q", out)
	}
	r = newRig(t, nil)
	if out := pacerLog(func() { _ = r.ch.Converse("Please send me your pass") }); strings.Contains(out, voiceLog) {
		t.Fatalf("a plain text logged %q", out)
	}
	if out := pacerLog(func() { _ = r.ch.Converse("word when you can.") }); !strings.Contains(out, voiceLog) {
		t.Fatalf("a text voice-shaped only when joined logged %q", out)
	}
	if out := pacerLog(func() { agentText("K7: reply YES K7 to approve.") }); !strings.Contains(out, voiceLog) {
		t.Fatalf("agentText holding a voice-shaped text logged %q", out)
	}
}

// A text that completes a secret with the agent's earlier text is held as
// a secret, not as a code mention and not sent as written.
func TestMutPacerJoinedSecretIsHeldAsSecret(t *testing.T) {
	r := newRig(t, nil)
	for _, s := range []string{"Please send me your pass", "word 482913"} {
		if err := r.ch.Converse(s); err != nil {
			t.Fatal(err)
		}
	}
	got := r.sentTexts()
	if len(got) != 2 || got[0] != "Please send me your pass" || (got[1] != Hidden && got[1] != HiddenPointer) {
		t.Fatalf("sent %q, want the second held as a secret", got)
	}
}

// joinedAgent keeps only the last maxSinceOwner agent texts.
func TestMutPacerSinceOwnerIsBounded(t *testing.T) {
	r := newRig(t, nil)
	for i := range maxSinceOwner + 2 {
		if err := r.ch.Converse("Note " + strings.Repeat("a", i+1) + "."); err != nil {
			t.Fatal(err)
		}
	}
	r.ch.agentMu.Lock()
	got := slices.Clone(r.ch.sinceOwner)
	r.ch.agentMu.Unlock()
	if len(got) != maxSinceOwner || got[len(got)-1] != "Note "+strings.Repeat("a", maxSinceOwner+2)+"." {
		t.Fatalf("since owner %q, want the last %d", got, maxSinceOwner)
	}
}

// agentText strips control characters from text it lets through.
func TestMutPacerAgentTextStripsControls(t *testing.T) {
	if got := agentText("a\x07b"); strings.ContainsRune(got, '\x07') {
		t.Fatalf("agentText kept a control: %q", got)
	}
}

// A send that provably did not go is uncounted, even when the clock moved
// on while it was in the modem.
func TestMutPacerSettleUncountsANotSent(t *testing.T) {
	r := newRig(t, nil)
	at := r.ch.reserve()
	r.advance(time.Minute)
	r.ch.settle(at, modem.ErrNotSent)
	if n := r.ch.Allowance(r.clock()); n != DefaultTextsPerHour {
		t.Fatalf("allowance %d after a send that did not go, want %d", n, DefaultTextsPerHour)
	}
}

// Refund takes back one count, even when three share its time.
func TestMutPacerRefundTakesOne(t *testing.T) {
	r := newRig(t, nil)
	var at time.Time
	for range DefaultTextsPerHour {
		var ok bool
		if at, ok = r.ch.Spend(true); !ok {
			t.Fatal("Spend refused")
		}
	}
	r.ch.Refund(at)
	if n := r.ch.Allowance(r.clock()); n != 1 {
		t.Fatalf("allowance %d after one refund, want 1", n)
	}
}

// In quiet hours Release changes nothing, not even dropping a stale text.
func TestMutPacerReleaseInQuietHoursKeepsStale(t *testing.T) {
	st := State{Pacing: quiet22to7(), Held: []HeldText{{Text: "Cleared.", Subjects: []string{"s1"}, Class: ClassUpdate}}}
	r := pacerRig(t, st, nil, time.Date(2026, 10, 4, 23, 0, 0, 0, time.UTC))
	r.ch.SetCurrent(func([]string) bool { return false })
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if h := r.held(); len(h) != 1 {
		t.Fatalf("held %d in quiet hours, want 1", len(h))
	}
}

// A failed save in Release, dropping a stale text or removing a sent one,
// is returned.
func TestMutPacerReleaseReturnsSaveErrors(t *testing.T) {
	noon := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	fs := &failStore{}
	r := pacerRig(t, State{Held: []HeldText{{Text: "Cleared.", Subjects: []string{"s1"}, Class: ClassUpdate}}}, fs, noon)
	r.ch.SetCurrent(func([]string) bool { return false })
	fs.fail = true
	if err := r.ch.Release(); err == nil {
		t.Fatal("Release returned nil when dropping a stale text failed to save")
	}

	fs = &failStore{}
	r = pacerRig(t, State{Held: []HeldText{{Text: "News.", Class: ClassUpdate}}}, fs, noon)
	fs.fail = true
	if err := r.ch.Release(); err == nil {
		t.Fatal("Release returned nil when removing a sent text failed to save")
	}
}

// Release reads the clock again after the Current hook: a hook that runs
// into quiet hours stops the send.
func TestMutPacerReleaseRereadsTheClock(t *testing.T) {
	st := State{Pacing: quiet22to7(), Held: []HeldText{{Text: "Cleared.", Subjects: []string{"s1"}, Class: ClassUpdate}}}
	r := pacerRig(t, st, nil, time.Date(2026, 10, 4, 21, 59, 30, 0, time.UTC))
	r.ch.SetCurrent(func([]string) bool { r.advance(time.Minute); return true })
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("sent %q after the hook ran into quiet hours", got)
	}
	if h := r.held(); len(h) != 1 {
		t.Fatalf("held %d, want 1", len(h))
	}
}

// packHeld counts the separator: two texts that fit alone but not joined
// go one at a time.
func TestMutPacerPackHeldCountsTheSeparator(t *testing.T) {
	a := strings.Repeat("a", 228)
	b := strings.Repeat("b", 459-228-len(heldSep)+1)
	_, n, _ := packHeld(time.UTC, 0, []HeldText{{Text: a}, {Text: b}})
	if n != 1 {
		t.Fatalf("packed %d texts whose join is one byte too long, want 1", n)
	}
}

// A held text with no held time goes unmarked.
func TestMutPacerHeldMarkedNoTime(t *testing.T) {
	if got := heldMarked(time.UTC, HeldText{Text: "News."}); got != "News." {
		t.Fatalf("heldMarked %q", got)
	}
}

// Quiet hours inside one day, 02:00 to 05:00, do not wrap round midnight.
func TestMutPacerQuietInsideADay(t *testing.T) {
	r := pacerRig(t, State{Pacing: Pacing{QuietFrom: 2 * 60, QuietTo: 5 * 60}}, nil,
		time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	day := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	if r.ch.Quiet(day.Add(time.Hour)) || !r.ch.Quiet(day.Add(3*time.Hour)) || r.ch.Quiet(day.Add(6*time.Hour)) {
		t.Fatal("quiet 02:00 to 05:00 read wrong at 01:00, 03:00 or 06:00")
	}
}

// A message of no setting's shape, or a setting while locked, changes
// nothing and returns ok false; URGENT AGENT OFF keeps the other classes.
func TestMutPacerSettingShapes(t *testing.T) {
	r := pacerRig(t, State{Pacing: Pacing{Urgent: []Class{ClassApproval, ClassAgent}}}, nil,
		time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	for _, msg := range []string{"", "hello there", "URGENT AGENT", "TEXTS A", "TEXTS 5A"} {
		if reply, ok := r.ch.pacingSetting(msg, true); ok || reply != "" {
			t.Fatalf("%q: %q, %v; want no setting", msg, reply, ok)
		}
	}
	if reply, ok := r.ch.pacingSetting("TEXTS 5", false); ok || reply != "" || r.ch.TextsPerHour() != DefaultTextsPerHour {
		t.Fatalf("locked TEXTS 5: %q, %v, %d an hour", reply, ok, r.ch.TextsPerHour())
	}
	if _, ok := r.ch.pacingSetting("URGENT AGENT OFF", true); !ok {
		t.Fatal("URGENT AGENT OFF not read")
	}
	r.ch.mu.Lock()
	u := slices.Clone(r.ch.codes.st.Pacing.Urgent)
	r.ch.mu.Unlock()
	if !slices.Equal(u, []Class{ClassApproval}) {
		t.Fatalf("urgent %q after URGENT AGENT OFF, want [approval]", u)
	}
	if got := urgentNames(Pacing{ApprovalHeld: true}); got != "security alerts" {
		t.Fatalf("urgentNames %q", got)
	}
}
