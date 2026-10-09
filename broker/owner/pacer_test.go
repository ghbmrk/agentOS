package owner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var regexp6 = regexp.MustCompile(`[0-9]{6}`)

// sentTexts drains the texts the box sent to the owner's phone so far.
func (r *rig) sentTexts() []string {
	r.t.Helper()
	var out []string
	for {
		select {
		case m := <-r.phone.Inbox():
			r.checkFormat(m.Text)
			out = append(out, m.Text)
		case <-time.After(50 * time.Millisecond):
			return out
		}
	}
}

// pacedRig opens a channel with the given pacing setting saved, a
// non-UTC location, and the clock at local hh:mm.
func pacedRig(t *testing.T, p Pacing, hh, mm int) *rig {
	t.Helper()
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz data:", err)
	}
	st := &MemStore{}
	if err := st.Save(State{Pacing: p}); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, st)
	r.now = time.Date(2026, 10, 5, hh, mm, 0, 0, ny).UTC()
	r.edit = func(c *Config) { c.Location = ny }
	r.ch = r.open()
	return r
}

// restarted gives the channel one open request from before a restart, so
// Boot has a restart text to send.
func (r *rig) restarted() {
	r.ch.mu.Lock()
	r.ch.boot = &bootReport{pending: []PendingRef{{ID: "G1"}}}
	r.ch.mu.Unlock()
}

func quiet22to7() Pacing { return Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60} }

func (r *rig) held() []HeldText {
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	return append([]HeldText(nil), r.ch.codes.st.Held...)
}

// REQ: CH-15 (W5-Dc-r1a QH-1)
func TestPacingDefaultsFromAnOldState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.json")
	// A state file as main writes it: no pacing, no hold.
	old := `{"unlocked_until":"0001-01-01T00:00:00Z","locks":2,"last_step":0,"low_locked":false,"cleared_at":"0001-01-01T00:00:00Z","challenged":false,"bound_start":"0001-01-01T00:00:00Z","bound_used":0,"local_start":"0001-01-01T00:00:00Z","local_used":0,"local_alert_at":"0001-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, FileStore{Path: path})
	check := func(name string) {
		t.Helper()
		now := r.clock()
		if got := r.ch.Allowance(now); got != DefaultTextsPerHour || DefaultTextsPerHour != 3 {
			t.Errorf("%s: allowance %d, want 3", name, got)
		}
		for h := 0; h < 24; h++ {
			if r.ch.Quiet(now.Add(time.Duration(h) * time.Hour)) {
				t.Errorf("%s: quiet at +%dh with no window set", name, h)
			}
		}
		if !r.ch.Urgent(ClassSecurity) || r.ch.Urgent(ClassApproval) || r.ch.Urgent(ClassAgent) || r.ch.Urgent(ClassUpdate) {
			t.Errorf("%s: urgent classes not the default (security only)", name)
		}
	}
	check("old state file")
	if r.ch.codes.st.Locks != 2 {
		t.Fatalf("old state not loaded: %+v", r.ch.codes.st)
	}

	// A corrupt setting fails closed to the defaults, never to no pacing.
	for _, bad := range []Pacing{
		{QuietFrom: 25 * 60, QuietTo: 7 * 60},
		{QuietFrom: -1},
		{PerHour: -1},
		{PerHour: 21},
		{Urgent: []Class{ClassUpdate}},
		{Urgent: []Class{"everything"}},
	} {
		st := &MemStore{}
		st.Save(State{Pacing: bad})
		r = newRig(t, st)
		check(fmt.Sprintf("corrupt %+v", bad))
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2)
func TestFourthUpdateInAnHourIsHeld(t *testing.T) {
	r := newRig(t, nil)
	for i := 1; i <= 4; i++ {
		if err := r.ch.Inform(fmt.Sprintf("Update %d.", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 3 {
		t.Fatalf("sent %d texts in the hour, want 3: %q", len(got), got)
	}
	if h := r.held(); len(h) != 1 || h[0].Text != "Update 4." {
		t.Fatalf("held: %+v", h)
	}
	r.advance(59 * time.Minute)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("released inside the hour: %q", got)
	}
	r.advance(2 * time.Minute)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Update 4." {
		t.Fatalf("after the hour: %q", got)
	}
	if h := r.held(); len(h) != 0 {
		t.Fatalf("still held: %+v", h)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2)
func TestQuietHoursHoldUpdatesButNotSecurity(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if !r.ch.Quiet(r.clock()) {
		t.Fatal("23:00 box-local is not quiet under 22-7")
	}
	if r.ch.Quiet(r.clock().Add(-2 * time.Hour)) {
		t.Fatal("21:00 box-local is quiet under 22-7")
	}
	if err := r.ch.Inform("An update."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("update sent in quiet hours: %q", got)
	}
	// A local sign-in alert is security: it goes at once.
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	r.ch.FlushLocal()
	if got := r.sentTexts(); len(got) != 1 || !strings.Contains(got[0], "signed in") {
		t.Fatalf("sign-in alert in quiet hours: %q", got)
	}
	// The restart text carries live codes: it goes at once, never held
	// (round 1, B4).
	r.restarted()
	r.ch.Boot()
	if got := r.sentTexts(); len(got) != 1 || !strings.HasPrefix(got[0], "Box restarted.") {
		t.Fatalf("restart text in quiet hours: %q", got)
	}
	// Agent text: held, prefix kept.
	if err := r.ch.Notify("hello"); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.NotifyAs(ClassApproval, "taken back"); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("agent text sent in quiet hours: %q", got)
	}
	h := r.held()
	if len(h) != 3 || h[1].Text != AgentPrefix+"hello" || h[2].Text != AgentPrefix+"taken back" {
		t.Fatalf("held: %+v", h)
	}

	// With URGENT approval ON, the restart text and NotifyAs(approval) go.
	r = pacedRig(t, Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60, Urgent: []Class{ClassApproval}}, 23, 0)
	r.restarted()
	r.ch.Boot()
	if got := r.sentTexts(); len(got) != 1 || !strings.HasPrefix(got[0], "Box restarted.") {
		t.Fatalf("restart text with URGENT approval: %q", got)
	}
	r.ch.Notify("hello")
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("agent text went with only URGENT approval: %q", got)
	}
	r.ch.NotifyAs(ClassApproval, "taken back")
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+"taken back" {
		t.Fatalf("NotifyAs(approval) with URGENT approval: %q", got)
	}

	// With URGENT agent ON, Notify goes at once and keeps the prefix.
	r = pacedRig(t, Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60, Urgent: []Class{ClassAgent}}, 23, 0)
	r.ch.Notify("hello")
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+"hello" {
		t.Fatalf("Notify with URGENT agent: %q", got)
	}
	r.ch.NotifyAs(ClassApproval, "taken back")
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("NotifyAs(approval) went with only URGENT agent: %q", got)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2), CH-11
func TestRepliesAreNeverHeld(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	// Spend the allowance with urgent texts.
	for i := 0; i < DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ClassSecurity, "Security alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sentTexts()
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d, want spent", a)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.ch.Run(ctx)
	ask := func(text string) string {
		t.Helper()
		r.carrier.Inject(ownerNum, boxNum, text)
		select {
		case m := <-r.phone.Inbox():
			return m.Text
		case <-time.After(2 * time.Second):
			t.Fatalf("no reply to %q in quiet hours with the allowance spent", text)
		}
		return ""
	}
	if got := ask("STOP"); !strings.Contains(got, "top") {
		t.Fatalf("STOP: %q", got)
	}
	got := ask("RESUME")
	m := regexp6.FindString(got)
	if m == "" {
		t.Fatalf("RESUME code text: %q", got)
	}
	if got := ask("RESUME " + m); !strings.HasPrefix(got, "Resumed") {
		t.Fatalf("RESUME code: %q", got)
	}
	if got := ask("HELP"); !strings.HasPrefix(got, "Commands:") {
		t.Fatalf("HELP: %q", got)
	}
	if got := ask("STATUS"); got == "" {
		t.Fatal("STATUS: no reply")
	}
	cancel()
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance changed by replies: %d", a)
	}
	r.ch.mu.Lock()
	n := len(r.ch.codes.st.Sent)
	r.ch.mu.Unlock()
	if n != DefaultTextsPerHour {
		t.Fatalf("replies counted: %d sends recorded, want %d", n, DefaultTextsPerHour)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2)
func TestRequestsShareTheAllowance(t *testing.T) {
	r := newRig(t, nil)
	for i := 0; i < 2; i++ {
		if _, err := r.ch.Request([]Item{lowItem(fmt.Sprintf("m%d", i))}, 0); err != nil {
			t.Fatal(err)
		}
	}
	r.ch.Inform("First update.")
	r.ch.Inform("Second update.")
	got := r.sentTexts()
	if len(got) != 3 || got[2] != "First update." {
		t.Fatalf("sent: %q", got)
	}
	if h := r.held(); len(h) != 1 || h[0].Text != "Second update." {
		t.Fatalf("held: %+v", h)
	}

	// An auto-reply alert counts too, and is never held by the owner.
	r = newRig(t, nil)
	r.ch.Inform("One.")
	r.ch.Inform("Two.")
	r.ch.Inform("Three.")
	if _, err := r.ch.QueueAutoReply(AutoReply{Ref: "t1", Recipients: []string{"bob@example.test"}, Body: "Thanks, got it."}); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 4 || !strings.HasPrefix(got[3], "Auto-reply") {
		t.Fatalf("sent: %q", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after four sends", a)
	}
}

// failStore fails saves while fail is set.
type failStore struct {
	MemStore
	fail bool
}

func (f *failStore) Save(s State) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.MemStore.Save(s)
}

// REQ: CH-15 (W5-Dc-r1a QH-3), OP-9
func TestHeldTextSurvivesARestart(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Inform("Held overnight."); err != nil {
		t.Fatal(err)
	}
	r.ch = r.open() // restart from saved state
	if h := r.held(); len(h) != 1 {
		t.Fatalf("hold after restart: %+v", h)
	}
	r.advance(7*time.Hour + time.Minute) // 06:01: still quiet
	r.ch.Release()
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("released in quiet hours: %q", got)
	}
	r.advance(time.Hour) // 07:01
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	r.ch.Release()
	r.ch = r.open()
	r.ch.Release()
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Held overnight." {
		t.Fatalf("released: %q", got)
	}

	// A save failure on hold returns the error and sends nothing.
	fs := &failStore{}
	fs.MemStore.Save(State{Pacing: quiet22to7()})
	r = pacedRig(t, quiet22to7(), 23, 0)
	r.store = fs
	r.ch = r.open()
	fs.fail = true
	if err := r.ch.Inform("Not saved."); err == nil {
		t.Fatal("hold with a failing save returned nil")
	}
	if got, h := r.sentTexts(), r.held(); len(got) != 0 || len(h) != 0 {
		t.Fatalf("sent %q, held %+v", got, h)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-3), OP-9, CH-12
func TestHoldIsBounded(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for i := 1; i <= 40; i++ {
		if err := r.ch.Inform(fmt.Sprintf("Update %d.", i)); err != nil {
			t.Fatal(err)
		}
	}
	h := r.held()
	if len(h) != MaxHeld || MaxHeld != 32 || h[0].Text != "Update 9." {
		t.Fatalf("hold: %d texts: %+v", len(h), h)
	}
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) == 0 || !strings.HasPrefix(got[0], "8 earlier texts were dropped while paced.") {
		t.Fatalf("released: %q", got)
	}
	all := strings.Join(got, " / ")
	if !strings.Contains(all, "Update 9.") || !strings.Contains(all, "Update 40.") || strings.Contains(all, "Update 8.") {
		t.Fatalf("released: %q", got)
	}
	r.ch.mu.Lock()
	dropped := r.ch.codes.st.HeldDropped
	r.ch.mu.Unlock()
	if dropped != 0 || len(r.held()) != 0 {
		t.Fatalf("after release: dropped %d, held %d", dropped, len(r.held()))
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-4)
func TestReleasePacksAndKeepsOrder(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for i := 1; i <= 5; i++ {
		r.ch.Inform(fmt.Sprintf("Held %d.", i))
	}
	r.advance(8 * time.Hour)
	r.box.SetDown(true)
	if err := r.ch.Release(); err == nil {
		t.Fatal("release over a down line returned nil")
	}
	if h := r.held(); len(h) != 5 {
		t.Fatalf("a send error lost held texts: %+v", h)
	}
	// A newer update, posted while the line is down, waits behind them.
	if err := r.ch.Inform("Newer."); err != nil {
		t.Fatal(err)
	}
	r.box.SetDown(false)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 1 {
		t.Fatalf("five short texts and one newer went as %d texts: %q", len(got), got)
	}
	want := "Held 1. / Held 2. / Held 3. / Held 4. / Held 5. / Newer."
	if got[0] != want {
		t.Fatalf("packed: %q, want %q", got[0], want)
	}

	// Post releases first: a newer update never goes before an older one.
	r = pacedRig(t, quiet22to7(), 23, 0)
	r.ch.Inform("Old.")
	r.advance(8 * time.Hour)
	r.ch.Inform("New.")
	got = r.sentTexts()
	if strings.Join(got, " | ") != "Old. | New." && strings.Join(got, " | ") != "Old. / New." {
		t.Fatalf("order: %q", got)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-6), CH-3, CH-11
func TestPacingSettingsNeedUnlock(t *testing.T) {
	r := newRig(t, nil)
	at23 := time.Date(2026, 10, 5, 23, 0, 0, 0, time.UTC)
	if got := r.say("QUIET 22-7"); !strings.Contains(got, "Send a code from your code generator") {
		t.Fatalf("locked QUIET: %q", got)
	}
	if r.ch.Quiet(at23) {
		t.Fatal("locked QUIET changed the setting")
	}
	if a := r.agent.got(); len(a) != 0 {
		t.Fatalf("setting reached the agent: %q", a)
	}
	// The code unlocks; RUN then applies the held setting.
	r.unlock()
	const quietSet = "Quiet hours set: 22:00 to 07:00. Texts wait until then, except security alerts. Reply QUIET OFF to end them."
	if got := r.say("RUN"); got != quietSet {
		t.Fatalf("QUIET after unlock: %q", got)
	}
	if got := r.say("quiet 22-7."); got != quietSet {
		t.Fatalf("QUIET: %q", got)
	}
	if !r.ch.Quiet(at23) {
		t.Fatal("QUIET 22-7 not applied")
	}
	if st, _ := r.store.Load(); st.Pacing.QuietFrom != 22*60 || st.Pacing.QuietTo != 7*60 {
		t.Fatalf("not saved: %+v", st.Pacing)
	}
	if got := r.say("URGENT approval ON"); !strings.HasPrefix(got, "Approval requests now go at once") {
		t.Fatalf("URGENT approval ON: %q", got)
	}
	if !r.ch.Urgent(ClassApproval) {
		t.Fatal("URGENT approval ON not applied")
	}
	if got := r.say("Quiet hours set: "); strings.Contains(got, "Quiet hours set") {
		t.Fatalf("chat taken as a setting: %q", got)
	}
	if got := r.say("TEXTS 5"); !strings.HasPrefix(got, "Texts set: 5 an hour.") {
		t.Fatalf("TEXTS 5: %q", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 5 {
		t.Fatalf("allowance %d after TEXTS 5", a)
	}
	for _, bad := range []string{"TEXTS 0", "TEXTS 21", "QUIET 25-7", "URGENT update ON", "URGENT security OFF", "URGENT agent MAYBE"} {
		if got := r.say(bad); got != pacingForms {
			t.Fatalf("%s: %q", bad, got)
		}
	}
	if a := r.ch.Allowance(r.clock()); a != 5 || !r.ch.Urgent(ClassSecurity) || !r.ch.Quiet(at23) {
		t.Fatal("a refused form changed the setting")
	}
	if got := r.say("QUIET OFF"); !strings.HasPrefix(got, "Quiet hours off.") {
		t.Fatalf("QUIET OFF: %q", got)
	}
	if r.ch.Quiet(at23) {
		t.Fatal("QUIET OFF not applied")
	}
	if got := r.say("URGENT agent ON"); !strings.HasPrefix(got, "Agent texts now go at once") {
		t.Fatalf("URGENT agent ON: %q", got)
	}
	if got := r.say("URGENT agent OFF"); !strings.HasPrefix(got, "Agent texts now wait") {
		t.Fatalf("URGENT agent OFF: %q", got)
	}
	// Chat that only starts with a setting word still reaches the agent.
	r.say("urgent: please call the plumber")
	if a := r.agent.got(); len(a) == 0 || !strings.Contains(a[len(a)-1], "plumber") {
		t.Fatalf("chat did not reach the agent: %q", a)
	}
	if got := r.say("HELP"); !strings.Contains(got, "QUIET") || !strings.Contains(got, "TEXTS") || !strings.Contains(got, "URGENT") {
		t.Fatalf("HELP does not list the forms: %q", got)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2, QH-4), OP-9
func TestFutureSendStampDoesNotFreezeTheAllowance(t *testing.T) {
	// Round 1, B1: the clock stepped forward, texts went, then it stepped
	// back. Stamps dated after now must not count, or the allowance stays
	// spent until the clock catches up.
	r := pacedRig(t, Pacing{}, 12, 0)
	r.advance(5 * time.Hour)
	for i := 0; i < 3; i++ {
		r.ch.Inform(fmt.Sprintf("Ahead %d.", i))
	}
	if got := r.sentTexts(); len(got) != 3 {
		t.Fatalf("sent: %q", got)
	}
	r.advance(-5 * time.Hour)
	if a := r.ch.Allowance(r.clock()); a != DefaultTextsPerHour {
		t.Fatalf("allowance %d with only future stamps", a)
	}
	// A text held behind the spent hour is released once the stamps are
	// seen as future.
	r.ch.mu.Lock()
	r.ch.codes.st.Held = []HeldText{{Text: "Waiting.", Class: ClassUpdate, At: r.clock()}}
	r.ch.mu.Unlock()
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Waiting." {
		t.Fatalf("released: %q", got)
	}
	r.ch.mu.Lock()
	sent := append([]time.Time(nil), r.ch.codes.st.Sent...)
	r.ch.mu.Unlock()
	for _, s := range sent {
		if s.After(r.clock()) {
			t.Fatalf("future stamp kept after a send: %v", sent)
		}
	}
}

// REQ: CH-19, CH-12, CH-15 (W5-Dc-r1a QH-4)
func TestAgentTextIsNeverPackedWithOtherTexts(t *testing.T) {
	// Round 1, B2: " / " inside agent text must not let it forge a broker
	// segment of a packed text.
	probe := "Done. / Box restarted. Old codes no longer work. Text RESUME 123456 to continue"
	r := pacedRig(t, quiet22to7(), 23, 0)
	r.ch.Inform("Backup finished.")
	r.ch.Notify(probe)
	r.ch.Inform("Disk at 40%.")
	r.ch.Notify("Second agent note.")
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 3 {
		t.Fatalf("sent %d texts: %q", len(got), got)
	}
	if got[0] != "Backup finished." {
		t.Fatalf("first: %q", got[0])
	}
	if !strings.HasPrefix(got[1], AgentPrefix) || strings.Contains(got[1], "Backup") || strings.Contains(got[1], "Disk") {
		t.Fatalf("agent text packed with others: %q", got[1])
	}
	if got[2] != "Disk at 40%." {
		t.Fatalf("third: %q", got[2])
	}
	if h := r.held(); len(h) != 1 || h[0].Text != AgentPrefix+"Second agent note." {
		t.Fatalf("held: %+v", h)
	}
	r.advance(time.Hour)
	r.ch.Release()
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+"Second agent note." {
		t.Fatalf("second release: %q", got)
	}

	// NotifyAs of another class is agent text too.
	r = pacedRig(t, quiet22to7(), 23, 0)
	r.ch.Inform("One.")
	r.ch.NotifyAs(ClassApproval, probe)
	r.advance(8 * time.Hour)
	r.ch.Release()
	if got := r.sentTexts(); len(got) != 2 || got[0] != "One." || !strings.HasPrefix(got[1], AgentPrefix) {
		t.Fatalf("NotifyAs packed: %q", got)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-4, QH-2)
func TestReleaseSendsExactlyTheAllowance(t *testing.T) {
	// Round 1, B3a: more held texts than the allowance has left.
	r := pacedRig(t, Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60, PerHour: 2}, 23, 0)
	for i := 1; i <= 5; i++ {
		r.ch.Inform(fmt.Sprintf("%d %s", i, strings.Repeat("x", 300)))
	}
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 2 || !strings.HasPrefix(got[0], "1 ") || !strings.HasPrefix(got[1], "2 ") {
		t.Fatalf("sent %d texts", len(got))
	}
	if h := r.held(); len(h) != 3 || !strings.HasPrefix(h[0].Text, "3 ") {
		t.Fatalf("held %d", len(h))
	}
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d", a)
	}
}

// REQ: CH-15 (W5-Dc-r1a QH-2), ADP-11
func TestQueuedAutoReplySpendsOneUnit(t *testing.T) {
	// Round 1, B3b.
	r := newRig(t, nil)
	before := r.ch.Allowance(r.clock())
	if _, err := r.ch.QueueAutoReply(AutoReply{Ref: "a1", Recipients: []string{"bob@example.test"}, Body: "Thanks, got it."}); err != nil {
		t.Fatal(err)
	}
	r.sentTexts()
	if a := r.ch.Allowance(r.clock()); a != before-1 {
		t.Fatalf("allowance %d after one auto-reply, was %d", a, before)
	}
}

// REQ: CH-12, CH-15 (W5-Dc-r1a QH-2)
func TestRestartTextIsNeverHeld(t *testing.T) {
	// Round 1, B4: the restart text carries live codes, so it never waits
	// in the hold to be released after they died. It goes at once in
	// quiet hours and with the allowance spent, and nothing is held.
	r := pacedRig(t, quiet22to7(), 23, 0)
	r.restarted()
	r.ch.Boot()
	if got := r.sentTexts(); len(got) != 1 || !strings.HasPrefix(got[0], "Box restarted.") {
		t.Fatalf("restart text in quiet hours: %q", got)
	}
	if h := r.held(); len(h) != 0 {
		t.Fatalf("held: %+v", h)
	}

	r = pacedRig(t, Pacing{PerHour: 1}, 12, 0)
	r.ch.Inform("Spends the hour.")
	r.sentTexts()
	r.restarted()
	r.ch.Boot()
	if got := r.sentTexts(); len(got) != 1 || !strings.HasPrefix(got[0], "Box restarted.") {
		t.Fatalf("restart text past the allowance: %q", got)
	}
	if h := r.held(); len(h) != 0 {
		t.Fatalf("held: %+v", h)
	}
}
