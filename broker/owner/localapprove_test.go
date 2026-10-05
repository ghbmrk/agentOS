package owner

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// REQ: CH-10, CH-12, CH-7

// localItem is an action whose recipients cannot be shown in a text
// (O19): it is asked on the local page (P2-2a, UX-144-2).
func localItem(ref string) Item {
	it := lowItem(ref)
	it.Recipient = "bіlling@аcme.example, CANARY-ops@acme.example" // look-alikes
	return it
}

// P2-2a: an action whose recipients cannot be texted is asked on the
// Wi-Fi page. The text names no recipient, approving it by text is
// refused (the owner never saw where it goes), and NO by text works.
func TestALocalOnlyItemIsAskedOnThePage(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.ch.Request([]Item{localItem("i1")}, 0); err != ErrLocalOnly {
		t.Fatalf("by text: %v", err)
	}
	id, err := r.ch.RequestLocal(localItem("i1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	text := r.inbox()
	if !strings.HasPrefix(text, id+": ") || !strings.Contains(text, "2 recipients") || strings.Contains(text, "acme") ||
		!strings.Contains(text, "Wi-Fi page") || !strings.Contains(text, "NO "+id) || strings.Contains(text, "YES") {
		t.Fatalf("notice %q", text)
	}
	// Security D3: every YES form, each with a valid code, is refused
	// with the fixed wording and not counted.
	for _, yes := range []string{"YES " + id + " %s", "YES %s", "YES " + id + " 1 %s", "yes " + id + " %s"} {
		got := r.say(fmt.Sprintf(yes, r.totp()))
		if got != "Not approved. Approve "+id+" on my Wi-Fi page; it shows where this goes. Or reply NO "+id+"." { // UX on P2-2a 2A
			t.Fatalf("%q by text: %q", yes, got)
		}
	}
	if len(r.ch.codes.st.Wrong) != 0 || len(r.decisions()) != 0 {
		t.Fatal("a refused YES counted or decided")
	}
	if got := r.say("NO " + id); !strings.HasPrefix(got, "Denied "+id) {
		t.Fatalf("NO by text: %q", got)
	}
	if d := r.decisions(); len(d) != 1 || d[0].Approved || d[0].Ref != "i1" {
		t.Fatalf("decisions %+v", d)
	}
}

// The page approves with a fresh code-generator code, through the same
// checks as a texted YES: the decision carries any hold, and wrong codes
// void the request and count toward the lock.
func TestThePageApprovesWithACode(t *testing.T) {
	r := newRig(t, nil)
	it := localItem("i1")
	it.UndoWindow = 10 * time.Minute
	id, _ := r.ch.RequestLocal(it, 0)
	r.inbox()
	open := r.ch.LocalRequests()
	if len(open) != 1 || open[0].ID != id || !open[0].Local || open[0].Tier != High || len(open[0].Items) != 1 ||
		open[0].Items[0].Recipient != it.Recipient {
		t.Fatalf("listed %+v", open)
	}
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, ""); err != ErrWrongCode {
		t.Fatalf("no code: %v", err)
	}
	msg, err := r.ch.LocalAnswer(id, r.sum(id), true, r.totp())
	if err != nil || !strings.HasPrefix(msg, "Approved "+id+". Your agent can go ahead. It runs at") || !strings.Contains(msg, "UNDO") {
		t.Fatalf("approve: %q %v", msg, err)
	}
	if d := r.decisions(); len(d) != 1 || !d[0].Approved || d[0].Hold == "" {
		t.Fatalf("decisions %+v", d)
	}
	if len(r.ch.LocalRequests()) != 0 {
		t.Fatal("still listed")
	}

	id2, _ := r.ch.RequestLocal(localItem("i2"), 0)
	r.inbox()
	for i := 0; i < WrongPerRequest; i++ {
		if _, err := r.ch.LocalAnswer(id2, r.sum(id2), true, "000000"); err != ErrWrongCode {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if d := r.decisions(); len(d) != 1 || d[0].Approved || d[0].Why != "void" {
		t.Fatalf("after wrong codes %+v", d)
	}
	if len(r.ch.codes.st.Wrong) != WrongPerRequest {
		t.Fatalf("wrong count %d", len(r.ch.codes.st.Wrong))
	}
}

// Deny needs no code; any open request, text-asked or not, is listed
// with its items in full, and answers to a closed or unknown request
// fail.
func TestThePageDeniesAndListsEveryOpenRequest(t *testing.T) {
	r := newRig(t, nil)
	textID, _ := r.ch.Request([]Item{lowItem("t1"), highItem("t2")}, 0)
	r.inbox()
	localID, _ := r.ch.RequestLocal(localItem("l1"), 0)
	r.inbox()
	open := r.ch.LocalRequests()
	if len(open) != 2 || open[0].ID != textID || open[0].Local || len(open[0].Items) != 2 || open[1].ID != localID {
		t.Fatalf("listed %+v", open)
	}
	shown := r.sum(textID)
	if got := r.say("NO " + textID + " 2"); !strings.Contains(got, "Denied") {
		t.Fatalf("deny item 2: %q", got)
	}
	if d := r.decisions(); len(d) != 1 || d[0].Ref != "t2" || d[0].Approved {
		t.Fatalf("decisions %+v", d)
	}
	if open := r.ch.LocalRequests(); len(open[0].Done) != 2 || !open[0].Done[1] || open[0].Done[0] {
		t.Fatalf("done %+v", open[0].Done)
	}
	// The page showed both items open: that form is refused (Security D1).
	if _, err := r.ch.LocalAnswer(textID, shown, false, ""); err != ErrChanged {
		t.Fatalf("stale: %v", err)
	}
	if msg, err := r.ch.LocalAnswer(textID, r.sum(textID), false, ""); err != nil || !strings.Contains(msg, "Denied") {
		t.Fatalf("deny the rest: %q %v", msg, err)
	}
	if _, err := r.ch.LocalAnswer("Z9", "", false, ""); err != ErrNoRequest {
		t.Fatalf("unknown: %v", err)
	}
}

// sum is the LocalRequest.Sum the page would show for id.
func (r *rig) sum(id string) string {
	for _, rq := range r.ch.LocalRequests() {
		if rq.ID == id {
			return rq.Sum
		}
	}
	return ""
}

// A page approval is told to the owner, coalesced like local sign-ins
// (O16), so a phone left signed in cannot act unseen.
func TestPageAnswersAreToldToTheOwner(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, r.totp()); err != nil {
		t.Fatal(err)
	}
	r.ch.FlushLocal()
	if got := r.inbox(); got != "Approved "+id+" on my Wi-Fi page at "+r.clock().Format("15:04")+". Not you? Text STOP." {
		t.Fatalf("alert %q", got)
	}
}

// UX A1, A2: a page-only request stays open for LocalTTL and its notice
// names the verified verb and object, the recipient count and the
// deadline, never a recipient.
func TestTheLocalNoticeNamesTheActionAndTheDeadline(t *testing.T) {
	r := newRig(t, nil)
	it := localItem("i1")
	it.Object = strings.Repeat("quarterly report ", 6)
	id, _ := r.ch.RequestLocal(it, 0)
	text := r.inbox()
	exp := r.clock().Add(LocalTTL)
	want := id + `: your agent wants to send "` + field(it.Object, 40) + `" to 2 recipients I can't show in a text. Approve or deny on my Wi-Fi page before ` +
		exp.Format("15:04") + ", or reply NO " + id + "."
	if text != want {
		t.Fatalf("notice\n got %q\nwant %q", text, want)
	}
	if rq := r.ch.LocalRequests(); !rq[0].Expires.Equal(exp) {
		t.Fatalf("expires %v", rq[0].Expires)
	}
	r.unlock()
	if got := r.say("STATUS"); !strings.Contains(got, "1 waiting for you on my Wi-Fi page.") {
		t.Fatalf("STATUS %q", got)
	}
	if _, err := r.ch.LocalAnswer(id, r.sum(id), false, ""); err != nil {
		t.Fatal(err)
	}
	if got := r.say("STATUS"); strings.Contains(got, "Wi-Fi page") {
		t.Fatalf("STATUS after %q", got)
	}
}

// Security D2: a code accepted on the page is spent for texts too, and one
// accepted by text is spent for the page.
func TestACodeIsSpentAcrossThePageAndTexts(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	textID, _ := r.ch.Request([]Item{highItem("t1")}, 0)
	r.inbox()
	code := r.totp()
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, code); err != nil {
		t.Fatal(err)
	}
	if got := r.say("YES " + textID + " " + code); strings.Contains(got, "Approved") {
		t.Fatalf("a page code approved by text: %q", got)
	}
	id2, _ := r.ch.RequestLocal(localItem("i2"), 0)
	r.inbox()
	code = r.totp()
	textID2, _ := r.ch.Request([]Item{highItem("t2")}, 0)
	r.inbox()
	if got := r.say("YES " + textID2 + " " + code); !strings.Contains(got, "Approved") {
		t.Fatalf("by text: %q", got)
	}
	if _, err := r.ch.LocalAnswer(id2, r.sum(id2), true, code); err != ErrWrongCode {
		t.Fatalf("a texted code approved on the page: %v", err)
	}
}

// UX A6, Security D5: page answers within the alert hour, and a request
// voided by wrong codes there, reach the owner in one coalesced text.
func TestPageAnswersAreCoalesced(t *testing.T) {
	r := newRig(t, nil)
	a, _ := r.ch.RequestLocal(localItem("a"), 0)
	b, _ := r.ch.RequestLocal(localItem("b"), 0)
	v, _ := r.ch.RequestLocal(localItem("v"), 0)
	for i := 0; i < 3; i++ {
		r.inbox()
	}
	if _, err := r.ch.LocalAnswer(a, r.sum(a), false, ""); err != nil {
		t.Fatal(err)
	}
	first := r.inbox()
	if !strings.HasPrefix(first, "Denied "+a+" on my Wi-Fi page") {
		t.Fatalf("first %q", first)
	}
	if _, err := r.ch.LocalAnswer(b, r.sum(b), true, r.totp()); err != nil {
		t.Fatal(err)
	}
	var last string
	for i := 0; i < WrongPerRequest; i++ {
		msg, err := r.ch.LocalAnswer(v, r.sum(v), true, "000000")
		if err != ErrWrongCode {
			t.Fatalf("wrong %d: %v", i, err)
		}
		last = msg
	}
	if !strings.Contains(last, "void") {
		t.Fatalf("last wrong %q", last)
	}
	// The first wrong code of the window is told at once (O16).
	if got := r.inbox(); !strings.Contains(got, "wrong code") {
		t.Fatalf("wrong-code alert %q", got)
	}
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("not coalesced: %q", m.Text)
	default:
	}
	r.advance(SignInAlertEvery)
	r.ch.FlushLocal()
	got := r.inbox()
	if !strings.HasPrefix(got, "On my Wi-Fi page: Approved "+b+" at ") || !strings.Contains(got, v+" void after wrong codes at ") ||
		!strings.HasSuffix(got, "Not you? Text STOP.") {
		t.Fatalf("coalesced %q", got)
	}
	if len(r.ch.codes.st.LocalAnswers) != 0 {
		t.Fatal("answers kept after the text")
	}
}

// Potency R3: a page-only request lapses after LocalTTL, not CodeTTL, and
// is reported in the digest like any expired request (CH-13).
func TestALocalRequestLapsesAfterLocalTTL(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	r.advance(LocalTTL - time.Minute)
	r.ch.Tick()
	if len(r.decisions()) != 0 || len(r.ch.LocalRequests()) != 1 {
		t.Fatal("lapsed before LocalTTL")
	}
	r.advance(time.Minute)
	r.ch.Tick()
	if d := r.decisions(); len(d) != 1 || d[0].Approved || d[0].Why != "expired" || d[0].Ref != "i1" {
		t.Fatalf("decisions %+v", d)
	}
	if ds, _ := r.ch.TakeExpired(); len(ds) != 1 || ds[0].Request != id {
		t.Fatalf("digest %+v", ds)
	}
	if len(r.ch.LocalRequests()) != 0 {
		t.Fatal("still listed")
	}
}

// UX on #165: near the local bound, a wrong code on the page says how
// many tries remain before approving there pauses.
func TestThePageWarnsBeforeTheLocalBound(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	r.ch.mu.Lock()
	r.ch.codes.commit(func(s *State) { s.LocalStart, s.LocalUsed = r.clock(), LocalBound-4 })
	r.ch.mu.Unlock()
	if msg, _ := r.ch.LocalAnswer(id, r.sum(id), true, "000000"); strings.Contains(msg, "more tr") {
		t.Fatalf("3 left: %q", msg)
	}
	if msg, _ := r.ch.LocalAnswer(id, r.sum(id), true, "000001"); !strings.Contains(msg, "2 more tries on my Wi-Fi today, then approving here pauses until") {
		t.Fatalf("2 left: %q", msg)
	}
	// Security R3: with none left it says the page is paused.
	id2, _ := r.ch.RequestLocal(localItem("i2"), 0)
	r.inbox()
	r.ch.mu.Lock()
	r.ch.codes.commit(func(s *State) { s.LocalUsed = LocalBound - 1 })
	r.ch.mu.Unlock()
	if msg, _ := r.ch.LocalAnswer(id2, r.sum(id2), true, "000002"); !strings.Contains(msg, "Approving here is paused until") || strings.Contains(msg, "0 more") {
		t.Fatalf("0 left: %q", msg)
	}
}

// Security R1 on #165: a code texted with a refused YES is spent, so a
// text that leaked it cannot be replayed on the page; it still is not
// counted as wrong.
func TestARefusedTextedCodeIsSpent(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	code := r.totp()
	if got := r.say("YES " + id + " " + code); !strings.Contains(got, "on my Wi-Fi page") {
		t.Fatalf("YES by text: %q", got)
	}
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, code); err != ErrWrongCode {
		t.Fatalf("replayed on the page: %v", err)
	}
	if len(r.decisions()) != 0 {
		t.Fatal("decided")
	}
}

// L3 M1 on #165: a texted low-tier request shown on the page is approved
// there with a code-generator code, as the page asks; its texted code is
// not taken there.
func TestThePageApprovesTextedRequestsWithAStrongCode(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("t1")}, 0)
	texted := lowCodeRe.FindStringSubmatch(r.inbox())[2]
	// L3 S-a: the texted code is refused there with a hint, not counted
	// as wrong; it spends a try of the day's bound like any code (L3 on
	// #171).
	used := r.ch.codes.st.LocalUsed
	for i := 0; i < WrongPerRequest; i++ {
		if _, err := r.ch.LocalAnswer(id, r.sum(id), true, texted); err == nil || err.Error() != "That's the code I texted. Here, use a code from your code generator." {
			t.Fatalf("texted code on the page: %v", err)
		}
	}
	if len(r.ch.codes.st.Wrong) != 0 || r.ch.codes.st.LocalUsed != used+WrongPerRequest || len(r.ch.LocalRequests()) != 1 {
		t.Fatal("the texted code counted as wrong, or spent no try")
	}
	msg, err := r.ch.LocalAnswer(id, r.sum(id), true, r.totp())
	if err != nil || !strings.HasPrefix(msg, "Approved "+id+". Your agent can go ahead.") {
		t.Fatalf("strong code: %q %v", msg, err)
	}
	if d := r.decisions(); len(d) != 1 || !d[0].Approved {
		t.Fatalf("decisions %+v", d)
	}
}

// L3 S4: when an approved item could not be held for undo it did not run,
// and the page says so rather than "go ahead".
func TestThePageSaysWhenAnApprovedItemDidNotRun(t *testing.T) {
	r := newRig(t, nil)
	it := localItem("i1")
	it.UndoWindow = 10 * time.Minute
	id, _ := r.ch.RequestLocal(it, 0)
	r.inbox()
	sum, code := r.sum(id), r.totp()
	// No ID left for the hold.
	r.ch.mu.Lock()
	for _, l := range idLetters {
		for d := 0; d < 100; d++ {
			r.ch.codes.st.Retired[fmt.Sprintf("%c%d", l, d)] = r.clock()
			r.ch.codes.st.Retired[fmt.Sprintf("%c%02d", l, d)] = r.clock()
		}
	}
	r.ch.mu.Unlock()
	msg, err := r.ch.LocalAnswer(id, sum, true, code)
	if err != nil || strings.Contains(msg, "go ahead") || !strings.Contains(msg, "did not run") {
		t.Fatalf("approve: %q %v", msg, err)
	}
	// L3 N3: the owner's text says so too.
	if got := r.inbox(); !strings.Contains(got, "(it did not run) on my Wi-Fi page") {
		t.Fatalf("told %q", got)
	}
}

// L3 S2: wrong page codes that lock the session or switch on challenge
// mode are texted like a sign-in's.
func TestWrongPageCodesThatLockAreTexted(t *testing.T) {
	r := newRig(t, nil)
	var ids []string
	for i := 0; i < WrongToLock; i++ {
		id, _ := r.ch.RequestLocal(localItem(fmt.Sprint("i", i)), 0)
		r.inbox()
		ids = append(ids, id)
	}
	for i := 0; i < WrongToLock; i++ {
		r.ch.LocalAnswer(ids[i/2], r.sum(ids[i/2]), true, fmt.Sprintf("%06d", i))
	}
	var all []string
	for {
		select {
		case m := <-r.phone.Inbox():
			all = append(all, m.Text)
			continue
		default:
		}
		break
	}
	if !strings.Contains(strings.Join(all, "\n"), "Texted codes are off and the session is locked") {
		t.Fatalf("not told of the lock: %q", all)
	}
}

// L3 S3: an answer after expiry but before Tick finds the request closed.
func TestAnAnswerAfterExpiryIsRefused(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	sum := r.sum(id)
	r.advance(LocalTTL)
	if _, err := r.ch.LocalAnswer(id, sum, true, r.totp()); err != ErrNoRequest {
		t.Fatalf("after expiry: %v", err)
	}
	if d := r.decisions(); len(d) != 1 || d[0].Approved || d[0].Why != "expired" {
		t.Fatalf("decisions %+v", d)
	}
}

// L3 nit: the sum covers the expiry, so a request asked again under a
// reused ID has another sum.
func TestTheSumCoversTheExpiry(t *testing.T) {
	r := &request{id: "K1", items: []Item{lowItem("a")}, done: []bool{false}, expires: time.Unix(1000, 0)}
	later := *r
	later.expires = r.expires.Add(time.Hour)
	if requestSum(r) == requestSum(&later) {
		t.Fatal("expiry not in the sum")
	}
}

// L3 S-b on #165: many wrong page codes text the lock once and challenge
// mode once, each when it happens, and challenge mode reaches the digest.
func TestManyWrongPageCodesTellTheLockAndChallengeOnce(t *testing.T) {
	r := newRig(t, nil)
	n := WrongToChallenge + 2
	for i := 0; i < n; i++ {
		if i%WrongPerRequest == 0 {
			r.ch.RequestLocal(localItem(fmt.Sprint("i", i)), 0)
		}
		open := r.ch.LocalRequests()
		id := open[len(open)-1].ID
		if _, err := r.ch.LocalAnswer(id, r.sum(id), true, fmt.Sprintf("%06d", i)); err != ErrWrongCode {
			t.Fatalf("wrong %d: %v", i, err)
		}
	}
	var locks, challenges int
	for {
		select {
		case m := <-r.phone.Inbox():
			locks += strings.Count(m.Text, "the session is locked")
			challenges += strings.Count(m.Text, "need a challenge")
			continue
		default:
		}
		break
	}
	if locks != 1 || challenges != 1 {
		t.Fatalf("%d lock texts, %d challenge texts", locks, challenges)
	}
	if notes := strings.Join(r.ch.TakeDigestNotes(), " "); !strings.Contains(notes, "challenge mode switched on 1 times") {
		t.Fatalf("digest %q", notes)
	}
}

// L3 MUST on #171: with the day's page bound spent, the texted code gets
// the same answer as any other code, so the hint is no oracle for it.
func TestTheTextedCodeHintNeedsACountedTry(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("t1")}, 0)
	texted := lowCodeRe.FindStringSubmatch(r.inbox())[2]
	r.ch.mu.Lock()
	r.ch.codes.st.LocalStart, r.ch.codes.st.LocalUsed = r.clock(), LocalBound
	r.ch.mu.Unlock()
	wrong := "000000"
	if wrong == texted {
		wrong = "000001"
	}
	for _, code := range []string{texted, wrong} {
		if _, err := r.ch.LocalAnswer(id, r.sum(id), true, code); err != ErrTooMany {
			t.Fatalf("%s with the bound spent: %v", code, err)
		}
	}
}

// L3 SHOULDs on #171: only this request's texted code gets the hint;
// another request's counts as wrong. A deny with the texted code typed in
// still denies.
func TestOnlyThisRequestsTextedCodeGetsTheHint(t *testing.T) {
	r := newRig(t, nil)
	a, _ := r.ch.Request([]Item{lowItem("a1")}, 0)
	r.inbox()
	b, _ := r.ch.Request([]Item{lowItem("b1")}, 0)
	textedB := lowCodeRe.FindStringSubmatch(r.inbox())[2]
	if _, err := r.ch.LocalAnswer(a, r.sum(a), true, textedB); err != ErrWrongCode || len(r.ch.codes.st.Wrong) != 1 {
		t.Fatalf("B's code on A: %v, %d wrong", err, len(r.ch.codes.st.Wrong))
	}
	if msg, err := r.ch.LocalAnswer(b, r.sum(b), false, textedB); err != nil || msg != "Denied "+b+"." {
		t.Fatalf("deny with the code typed in: %q %v", msg, err)
	}
	if d := r.decisions(); len(d) != 1 || d[0].Approved || d[0].Ref != "b1" {
		t.Fatalf("decisions %+v", d)
	}
}

// L3 SHOULD on #171: a page-only request's code is never texted, so it
// never gets the hint.
func TestAPageOnlyRequestNeverGetsTheTextedHint(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	r.ch.mu.Lock()
	r.ch.open[id].code = "123456" // as if one were set
	r.ch.mu.Unlock()
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, "123456"); err == ErrTextedCode {
		t.Fatal("hint on a page-only request")
	}
}

// L3 nit on #171: when only some items of a request ran, the owner's
// text says not all of it ran.
func TestThePageSaysWhenNotAllOfARequestRan(t *testing.T) {
	r := newRig(t, nil)
	held := lowItem("h1")
	held.UndoWindow = 10 * time.Minute
	id, _ := r.ch.Request([]Item{lowItem("n1"), held}, 0)
	r.inbox()
	sum, code := r.sum(id), r.totp()
	r.ch.mu.Lock()
	for _, l := range idLetters {
		for d := 0; d < 100; d++ {
			r.ch.codes.st.Retired[fmt.Sprintf("%c%d", l, d)] = r.clock()
			r.ch.codes.st.Retired[fmt.Sprintf("%c%02d", l, d)] = r.clock()
		}
	}
	r.ch.mu.Unlock()
	if _, err := r.ch.LocalAnswer(id, sum, true, code); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(); !strings.Contains(got, "Approved "+id+" (not all of it ran) on my Wi-Fi page") {
		t.Fatalf("told %q", got)
	}
}

// L3 F1 on #171 at 654aa24: while the state cannot be saved, the texted
// code and a wrong code get the same answer, so a failing store does not
// make the hint an unlimited oracle.
func TestTheTextedCodeHintNeedsASavedTry(t *testing.T) {
	fs := &flakyStore{}
	r := newRig(t, fs)
	id, _ := r.ch.Request([]Item{lowItem("t1")}, 0)
	texted := lowCodeRe.FindStringSubmatch(r.inbox())[2]
	wrong := "000000"
	if wrong == texted {
		wrong = "000001"
	}
	fs.setFail(true)
	var got []string
	for _, code := range []string{texted, wrong} {
		_, err := r.ch.LocalAnswer(id, r.sum(id), true, code)
		if err == nil || err == ErrTextedCode {
			t.Fatalf("%s with the store failing: %v", code, err)
		}
		got = append(got, err.Error())
	}
	if got[0] != got[1] {
		t.Fatalf("answers differ: %q", got)
	}
	// Once a day's window has passed, the hint is back (L3 nit: M7).
	fs.setFail(false)
	r.ch.mu.Lock()
	r.ch.codes.st.LocalStart, r.ch.codes.st.LocalUsed = r.clock().Add(-WrongWindow), LocalBound
	r.ch.mu.Unlock()
	if _, err := r.ch.LocalAnswer(id, r.sum(id), true, texted); err != ErrTextedCode {
		t.Fatalf("after the window: %v", err)
	}
}

// Potency R2 on P2-2a: page requests opened together share their notice
// texts, as many to a text as fit, each still its own request.
func TestPageRequestsOpenedTogetherShareAText(t *testing.T) {
	r := newRig(t, nil)
	before := len(r.carrier.Log())
	ids, err := r.ch.RequestLocalEach([]Item{localItem("i1"), localItem("i2")}, []time.Duration{0, time.Hour})
	if err != nil || len(ids) != 2 || ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		t.Fatalf("ids %v err %v", ids, err)
	}
	sent := r.carrier.Log()[before:]
	if len(sent) != 1 || !strings.HasPrefix(sent[0].Text, ids[0]+": ") || !strings.Contains(sent[0].Text, " "+ids[1]+": ") || strings.Contains(sent[0].Text, "acme") {
		t.Fatalf("sent %+v", sent)
	}
	got := r.ch.LocalRequests()
	if len(got) != 2 || !got[0].Local || !got[1].Local || !got[1].Expires.Equal(r.now.Add(time.Hour)) {
		t.Fatalf("requests %+v", got)
	}
	if _, err := r.ch.RequestLocalEach([]Item{localItem("i3")}, nil); err == nil {
		t.Fatal("ttls not checked")
	}
}

// confirmItem is a change that needs the owner's confirmation on the
// page (a grant, evidence, sharing or release change; CH-3).
func confirmItem(ref string) Item {
	return Item{Ref: ref, Object: "mail.read for CANARY-agent", Facts: Facts{Kind: GrantChange, Verb: "grant", NoRecipient: true}}
}

// Security Q1 (amended) on P2-2a part 2: a change that needs the page is
// never offered YES by text; its notice offers only NO, and the page
// approves and confirms it with one fresh strong code bound to it (P2):
// the decision says it came from the page, with the shown item's sum,
// and a G4 code does not then pass for G5.
func TestAConfirmationTakesOneCodeOnThePage(t *testing.T) {
	r := newRig(t, nil)
	ids, err := r.ch.RequestLocalEach([]Item{confirmItem("g4"), confirmItem("g5")}, []time.Duration{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	text := r.inbox()
	for _, id := range ids {
		if !strings.Contains(text, id+": your agent wants to grant \"mail.read for CANARY-agent\". Approve or deny on my Wi-Fi page before ") || !strings.Contains(text, "or reply NO "+id+".") {
			t.Fatalf("notice %q", text)
		}
	}
	if strings.Contains(text, "YES") || strings.Contains(text, "recipient") {
		t.Fatalf("notice %q", text)
	}
	// UX U-2A-4: the reply says nothing was approved, with the ID only.
	if got := r.say("YES " + ids[0] + " " + r.totp()); got != "Not approved: "+ids[0]+" can only be approved on my Wi-Fi page. Use a new code there." {
		t.Fatalf("YES by text: %q", got)
	}
	code := r.totp()
	if _, err := r.ch.LocalAnswer(ids[0], r.sum(ids[0]), true, code); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ch.LocalAnswer(ids[1], r.sum(ids[1]), true, code); err != ErrWrongCode {
		t.Fatalf("G4's code for G5: %v", err)
	}
	d := r.decisions()
	if len(d) != 1 || !d[0].Approved || !d[0].Page || d[0].Ref != "g4" || d[0].Sum != ItemSum(confirmItem("g4")) {
		t.Fatalf("decisions %+v", d)
	}
	// A texted request's approval is not from the page.
	id, _ := r.ch.Request([]Item{lowItem("t1")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	for m == nil {
		m = lowCodeRe.FindStringSubmatch(r.inbox())
	}
	r.say("YES " + id + " " + m[2])
	if d := r.decisions(); len(d) != 1 || d[0].Ref != "t1" || !d[0].Approved || d[0].Page {
		t.Fatalf("decisions %+v", d)
	}
}

// UX U-2A-5: the owner's text for a page decision names the page, since
// it is the alert for a decision the owner may not have made.
func TestPageDecisionsAreToldNamingThePage(t *testing.T) {
	r := newRig(t, nil)
	ids, _ := r.ch.RequestLocalEach([]Item{confirmItem("g4"), confirmItem("g5")}, []time.Duration{0, 0})
	r.inbox()
	at := r.clock().Format("15:04")
	if _, err := r.ch.LocalAnswer(ids[0], r.sum(ids[0]), true, r.totp()); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(); got != "Approved "+ids[0]+" on my Wi-Fi page at "+at+". Not you? Text STOP." {
		t.Fatalf("approved: %q", got)
	}
	r.advance(SignInAlertEvery)
	at = r.clock().Format("15:04")
	if _, err := r.ch.LocalAnswer(ids[1], r.sum(ids[1]), false, ""); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(); got != "Denied "+ids[1]+" on my Wi-Fi page at "+at+". Not you? Text STOP." {
		t.Fatalf("denied: %q", got)
	}
	// Coalesced, with the same alert tail.
	more, _ := r.ch.RequestLocalEach([]Item{confirmItem("g6"), confirmItem("g7")}, []time.Duration{0, 0})
	r.inbox()
	at1 := r.clock().Format("15:04")
	r.ch.LocalAnswer(more[0], r.sum(more[0]), false, "") // within the hour: held
	r.advance(time.Minute)
	at2 := r.clock().Format("15:04")
	r.ch.LocalAnswer(more[1], r.sum(more[1]), false, "")
	r.advance(SignInAlertEvery)
	r.ch.FlushLocal()
	if got := r.inbox(); got != "On my Wi-Fi page: Denied "+more[0]+" at "+at1+", Denied "+more[1]+" at "+at2+". Not you? Text STOP." {
		t.Fatalf("coalesced: %q", got)
	}
}
