package owner

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// REQ: CH-11, CH-12, CH-15, CH-18, CH-19, CH-21, OWN-4, ADP-11
// MUT-kill-5974-owner-5 (#6742): the statements in voicecheck.go,
// converse.go, name.go, disclose.go, totp.go, boot.go, informquote.go and
// commit.go that mutgate's deletion left alive, each pinned by a test that
// fails without it. They call the function that holds the line directly
// where they can.

// voiceCases checks VoiceShaped on each text, wanting want.
func voiceCases(t *testing.T, want bool, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if got := VoiceShaped(s); got != want {
			t.Errorf("VoiceShaped(%q) = %v, want %v", s, got, want)
		}
	}
}

// A term the raw text shows but no fold does counts: Go's \b is ASCII, so
// "code" before a Cyrillic е is a whole word as written, while the fold
// reads "codee".
func TestMutVoiceRawReadingCounts(t *testing.T) {
	voiceCases(t, true, "codeе")
	voiceCases(t, false, "codee")
}

// Each half of the reply-options footer counts in the reading it shows in,
// raw or folded, whichever reading the other half shows in.
func TestMutVoiceFooterHalvesInEitherReading(t *testing.T) {
	voiceCases(t, true,
		"reply yesе or no", // "reply yes" only as written
		"reply yes or noе", // "or no" only as written
		"rep1y yes or no",  // "reply yes" only in the fold (1 to l)
		"reply yes 0r no",  // "or no" only in the fold (0 to o)
	)
	voiceCases(t, false, "reply yesе", "or noе", "rep1y yes", "0r no")
}

// A line opens like a request as written or in a fold, and every line of
// the text is read, whatever line break ends the one before.
func TestMutVoiceOpeningEachLineEachReading(t *testing.T) {
	voiceCases(t, true,
		"R7 ⅼ: hi", // as written: ⅼ (U+217C) is no letter; its fold l is
		"Ｒ7: hi",   // in the fold only: fullwidth Ｒ is no ASCII letter
	)
	for _, br := range []string{"\n", "\r", "\v", "\f", "\u0085", " ", " "} {
		voiceCases(t, true, "hi"+br+"R7: x")
	}
	voiceCases(t, false, "hi R7: x")
}

// holdVoice logs the hold, never the text.
func TestMutVoiceHoldIsLogged(t *testing.T) {
	if got := pacerLog(holdVoice); !strings.Contains(got, voiceLog) || !strings.Contains(got, "(CH-21)") {
		t.Fatalf("log %q", got)
	}
}

// halted reports whether the i-th acknowledgement timer was stopped.
func (a *ackTimers) halted(i int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return i < len(a.ts) && a.ts[i].halted
}

// A second message while one acknowledgement is due arms no new one: the
// acknowledgement still goes ACK seconds after the first.
func TestMutAckDueFromTheFirstMessage(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	a.fire(2 * time.Second)
	r.say("for four")
	a.fire(3 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements 5 s after the first message, want 1", n)
	}
}

// Task chat after a STOP stops the acknowledgement the STOP voided before
// arming its own.
func TestMutAckVoidedTimerIsStopped(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	r.say("STOP")
	r.sentTexts()
	r.say("book a table")
	if !a.halted(0) {
		t.Fatal("the acknowledgement voided by STOP still runs")
	}
}

// A reply stops the acknowledgement's timer and clears it, so the owner's
// next message arms a fresh one.
func TestMutReplyStopsAndClearsTheAck(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	if err := r.ch.Converse("Which night?"); err != nil {
		t.Fatal(err)
	}
	if !a.halted(0) {
		t.Fatal("a reply left the acknowledgement's timer running")
	}
	r.sentTexts()
	r.say("Friday")
	a.fire(5 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements for the message after a reply, want 1", n)
	}
}

// The argument may follow NAME after more than one space.
func TestMutParseNameTrimsTheArgument(t *testing.T) {
	if n, ok := parseName("NAME  123456"); !ok || n.code != "123456" || n.name != "" {
		t.Fatalf("parseName = %+v, %v", n, ok)
	}
}

// A code-generator code whose spend cannot be saved renames nothing and
// says the state could not be saved.
func TestMutNameCodeSaveFailureRenamesNothing(t *testing.T) {
	store := &failStore{}
	r := newRig(t, store)
	r.edit = func(c *Config) { c.OwnerName = "Mark Jones" }
	r.ch = r.open()
	r.unlock()
	store.fail = true
	if got := r.say("NAME Dave Smith " + r.totp()); got != stateErr {
		t.Fatalf("reply %q, want %q", got, stateErr)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed to %q", n)
	}
}

// With texted codes locked, a rename asks for a code-generator code, not a
// texted one it did not send.
func TestMutAskRenameLowLockedAsksForTheGenerator(t *testing.T) {
	r := named(t)
	r.ch.mu.Lock()
	r.ch.codes.st.LowLocked = true
	got := r.ch.askRenameLocked("Dave Smith", r.clock())
	r.ch.mu.Unlock()
	if want := `Change my name to "Dave Smith"? To confirm, reply NAME and a code from your code generator`; !strings.HasPrefix(got, want) {
		t.Fatalf("reply %q", got)
	}
}

// renameCode asks to rename to name in an unlocked session and returns the
// texted code.
func renameCode(t *testing.T, r *rig, name string) string {
	t.Helper()
	m := nameCodeRe.FindStringSubmatch(r.say("NAME " + name))
	if m == nil {
		t.Fatal("no rename code")
	}
	return m[1]
}

// An expired rename is void for good: the clock stepping back does not
// revive it.
func TestMutExpiredRenameStaysVoid(t *testing.T) {
	r := named(t)
	r.unlock()
	code := renameCode(t, r, "Dave Smith")
	r.advance(r.ch.cfg.CodeTTL)
	const none = "No rename is waiting. Send NAME and the new name."
	if got := r.say("NAME " + code); got != none {
		t.Fatalf("expired: %q", got)
	}
	r.advance(-time.Minute)
	if got := r.say("NAME " + code); got != none || r.ch.Name() != "" {
		t.Fatalf("after the clock stepped back: %q, name %q", got, r.ch.Name())
	}
}

// A confirmation the store cannot count says so, and does not read as a
// wrong code.
func TestMutConfirmRenameSaveFailure(t *testing.T) {
	store := &failStore{}
	r := newRig(t, store)
	r.edit = func(c *Config) { c.OwnerName = "Mark Jones" }
	r.ch = r.open()
	r.unlock()
	renameCode(t, r, "Dave Smith")
	store.fail = true
	if got := r.say("NAME 000000"); got != stateErr {
		t.Fatalf("reply %q, want %q", got, stateErr)
	}
}

// A rename voided by three wrong codes stays void: its right code then
// renames nothing.
func TestMutVoidedRenameIsGone(t *testing.T) {
	r := named(t)
	r.unlock()
	code := renameCode(t, r, "Dave Smith")
	for i := 0; i < WrongPerRequest; i++ {
		r.say("NAME 000000")
	}
	if got := r.say("NAME " + code); got != "No rename is waiting. Send NAME and the new name." || r.ch.Name() != "" {
		t.Fatalf("after the void: %q, name %q", got, r.ch.Name())
	}
}

// codeKinds checks CodeKind on each text.
func codeKinds(t *testing.T, cases map[string]string) {
	t.Helper()
	for s, want := range cases {
		if got := CodeKind(s); got != want {
			t.Errorf("CodeKind(%q) = %q, want %q", s, got, want)
		}
	}
}

// A run of numbers joined into one word reads as its whole text: here
// "ⅽ0ⅾ℮" and the number U+09F4, which folds to a space, fold to the code
// word "code".
func TestMutJoinedNumbersReadWhole(t *testing.T) {
	codeKinds(t, map[string]string{"ⅽ0ⅾ℮৴ is 1234": "a code of 4 digits"})
}

// A word whose plain fold is a code word is one even when no CH-12 fold
// is: Arabic-Indic ٢ folds to 2 only in fold.
func TestMutCodeWordByPlainFold(t *testing.T) {
	codeKinds(t, map[string]string{"٢FA 123456": "a code of 6 digits"})
}

// Joined digits count by their digits, not by the text that joins them.
func TestMutJoinedDigitsCountByDigits(t *testing.T) {
	codeKinds(t, map[string]string{"code 12 34 56 78 90": "a code of 10 digits"})
}

// An empty seed matches no code, not even the one an empty HMAC key gives.
func TestMutMatchTOTPEmptySeed(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, seed := range [][]byte{nil, {}} {
		code := hotp(seed, uint64(now.Unix()/totpStep))
		if s, ok := MatchTOTP(seed, code, now, 0); ok || s != 0 {
			t.Fatalf("MatchTOTP(%v) = %d, %v", seed, s, ok)
		}
	}
}

// A restart with nothing open still tells Reissue so, once.
func TestMutBootWithNothingOpenCallsReissue(t *testing.T) {
	r := newRig(t, nil)
	calls := 0
	r.reissue = func(c []Carried) {
		calls++
		if len(c) != 0 {
			t.Errorf("carried %+v", c)
		}
	}
	r.ch = r.open()
	r.ch.Boot()
	r.ch.Boot()
	if calls != 1 {
		t.Fatalf("Reissue called %d times, want 1", calls)
	}
}

// A restart text too long for one text gives the counts instead.
func TestMutBootTextTooLongGivesCounts(t *testing.T) {
	var st State
	for i := 0; i < 200; i++ {
		st.Pending = append(st.Pending, PendingRef{ID: fmt.Sprintf("R%03d", i)})
	}
	r := pacerRig(t, st, nil, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	r.ch.Boot()
	want := "Box restarted. 0 requests re-sent with new codes, 200 cancelled, 0 expired, 0 auto-replies not sent, and 0 approved actions cancelled."
	if got := r.inbox(); got != want {
		t.Fatalf("restart text %q", got)
	}
}

// The clip steps back to a rune boundary: a rune across byte 64 is left
// out whole, and the clip ends.
func TestMutInformQuoteClipsOnARune(t *testing.T) {
	s := strings.Repeat("a", 63) + "é tail"
	done := make(chan string, 1)
	go func() { done <- InformQuote(s) }()
	select {
	case got := <-done:
		if want := strings.Repeat("a", 63) + "..."; got != want {
			t.Fatalf("InformQuote = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("InformQuote did not return")
	}
}

// An owner phrase matches as its folded, lower-case words, however it was
// written.
func TestMutOwnerPhraseIsNormalised(t *testing.T) {
	c := Commitments{Phrases: []string{"Hold  Tight"}}
	if got := c.Match("hold tight please"); got != "commitment" {
		t.Fatalf("Match = %q", got)
	}
	if got := (Commitments{}).Match("hold tight please"); got != "" {
		t.Fatalf("defaults alone: %q", got)
	}
}

