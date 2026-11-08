package main

// REQ: LOG-4, CH-3, CH-26

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// forgetPageRig is the Forget step over a real kernel's owner keys (two
// hardware keys) and a forget flow over a fake kernel's subjects.
type forgetPageRig struct {
	t  *testing.T
	pk *passkeyRig
	k  *fakeKernel
	m  *rewindMachines
	b  *forgetBox
	p  pageForget
	// told is what the owner was texted; done is the last confirm's
	// answer.
	told []string
	done localapi.EraseDone
	at   time.Time
}

func newForgetPageRig(t *testing.T) *forgetPageRig {
	r := &forgetPageRig{t: t, pk: newPasskeyRig(t), k: newFakeKernel(), m: &rewindMachines{}, at: time.Date(2026, 11, 8, 14, 5, 0, 0, time.Local)}
	r.k.add("s1", "Alice Smith", 3, map[string]int64{"L1": 1_700_000_000_000})
	r.k.add("s2", "Bob", 1, nil)
	r.b = newForgetBox(t, r.k, r.m, t.TempDir())
	r.p = pageForget{F: r.b.f, K: r.pk.k, Tell: func(text string) { r.told = append(r.told, text) }, Now: func() time.Time { return r.at }}
	return r
}

func (r *forgetPageRig) find(session, name string) localapi.EraseFound {
	r.t.Helper()
	f, err := r.p.Find(context.Background(), session, name)
	if err != nil {
		r.t.Fatalf("find %s: %v", name, err)
	}
	return f
}

// tap is by's get() over f's challenge, confirmed in session.
func (r *forgetPageRig) tap(session string, f localapi.EraseFound, challenge []byte, by *authenticator) (string, error) {
	r.t.Helper()
	ad, cd, sig := by.get(r.t, challenge)
	done, err := r.p.Confirm(context.Background(), session, f.Handle, ad, cd, sig)
	r.done = done
	return done.Text, err
}

// The owner's tap over the list found erases exactly that list, rewinds
// the agent that read it before answering (b's confirm), and the page
// gets b's texts unchanged: the readback before the tap and the result
// after it.
func TestTheForgetTapErasesTheListShown(t *testing.T) {
	r := newForgetPageRig(t)
	f := r.find("sess-a", "alice smith")
	want, _ := newForgetFlow(r.k, r.b.rw).find(context.Background(), "alice smith")
	if f.Text != want.Text() || !strings.HasPrefix(f.Text, "Found 3 items named alice smith (message 3).") {
		t.Fatalf("readback %q, b's %q", f.Text, want.Text())
	}
	c := key.Challenge(forgetMsg("sess-a", f.Handle, []string{"s1"}))
	if len(f.Handle) != localapi.EraseHandle || !slices.Equal(f.Challenge, c[:]) {
		t.Fatalf("handle %q challenge %x", f.Handle, f.Challenge)
	}
	text, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[1])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.k.erases, []string{"s1"}) || !slices.Equal(r.m.calls, []string{"L1"}) {
		t.Fatalf("erased %v, rewound %v", r.k.erases, r.m.calls)
	}
	res := forgetResult{Name: "alice smith", Items: 3, Erased: 1, Rewound: []string{"L1"}}
	if text != res.Text() || !strings.HasPrefix(text, "Forgot everything named alice smith (3 items). It can no longer be read.") {
		t.Fatalf("result %q, b's %q", text, res.Text())
	}
	if r.done.Kept {
		t.Fatal("a whole erase reads as kept")
	}
	// The owner is texted of the page erase by count and kind, its time
	// and the passkey that tapped, never by the name. A hardware key
	// cannot be cut off on the page, so STOP is the step.
	note := "I forgot 3 items (message 3) on my Wi-Fi page at 14:05 after a tap by passkey " + noticePrint(r.pk.anchors[1].public(t)) + ". Not you? Text STOP."
	if !slices.Equal(r.told, []string{note}) || strings.Contains(strings.ToLower(note), "alice") || owner.CodeShaped(note) || owner.SecretShaped(note) {
		t.Fatalf("told %q", r.told)
	}
}

// Any of the owner's passkeys proves the owner: an enrolled phone passkey
// as well as a hardware key, since an erase only takes away. A phone cut
// off can no longer.
func TestAPhonePasskeyTapForgetsAndACutOneDoesNot(t *testing.T) {
	r := newForgetPageRig(t)
	phone, cut := newAuthenticator(t), newAuthenticator(t)
	if err := r.pk.enrol("p1", phone, r.pk.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.pk.enrol("p2", cut, r.pk.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.pk.cut(cut, r.pk.anchors[0]); err != nil {
		t.Fatal(err)
	}
	f := r.find("sess-a", "Bob")
	if _, err := r.tap("sess-a", f, f.Challenge, cut); code(err) != localapi.ErrEraseBadAssertion || len(r.k.erases) != 0 {
		t.Fatalf("cut-off phone: %v, erased %v", err, r.k.erases)
	}
	if _, err := r.tap("sess-a", f, f.Challenge, phone); err != nil || !slices.Equal(r.k.erases, []string{"s2"}) {
		t.Fatalf("phone: %v, erased %v", err, r.k.erases)
	}
	// A phone passkey's notice names the step that cuts it off.
	if len(r.told) != 1 || !strings.HasSuffix(r.told[0], "by passkey "+noticePrint(phone.public(t))+". Not you? Text STOP, and cut that passkey off on the passkey page.") {
		t.Fatalf("told %q", r.told)
	}
}

// An unsigned tap, a tap by a key that is not the owner's, a tap over
// another find's list, or one made in another page session erases
// nothing, and the find still stands for the owner's own tap.
func TestATapOverAnythingElseErasesNothing(t *testing.T) {
	r := newForgetPageRig(t)
	alice, bob := r.find("sess-a", "Alice Smith"), r.find("sess-a", "Bob")
	ctx := context.Background()
	stranger := newAuthenticator(t)
	ad, cd, sig := r.pk.anchors[0].get(t, alice.Challenge)
	for name, try := range map[string]func() error{
		"unsigned": func() error { _, err := r.p.Confirm(ctx, "sess-a", alice.Handle, ad, cd, []byte{0x30, 0}); return err },
		"garbage": func() error {
			_, err := r.p.Confirm(ctx, "sess-a", alice.Handle, []byte{1}, []byte{2}, []byte{3})
			return err
		},
		"stranger": func() error { _, err := r.tap("sess-a", alice, alice.Challenge, stranger); return err },
		// Alice's tap, sent with Bob's handle.
		"other list": func() error { _, err := r.p.Confirm(ctx, "sess-a", bob.Handle, ad, cd, sig); return err },
		// Alice's tap from sess-a, sent from sess-b.
		"other session": func() error { _, err := r.p.Confirm(ctx, "sess-b", alice.Handle, ad, cd, sig); return err },
	} {
		if err := try(); code(err) != localapi.ErrEraseBadAssertion {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(r.k.erases) != 0 || len(r.told) != 0 {
		t.Fatalf("erased %v, told %q", r.k.erases, r.told)
	}
	if _, err := r.tap("sess-a", bob, bob.Challenge, r.pk.anchors[0]); err != nil || !slices.Equal(r.k.erases, []string{"s2"}) {
		t.Fatalf("Bob's own tap: %v, erased %v", err, r.k.erases)
	}
}

// A tap replayed after its confirm, or made after the find expired,
// erases nothing more.
func TestAReplayedOrLateTapErasesNothing(t *testing.T) {
	r := newForgetPageRig(t)
	ctx := context.Background()
	f := r.find("sess-a", "Bob")
	ad, cd, sig := r.pk.anchors[0].get(t, f.Challenge)
	if _, err := r.p.Confirm(ctx, "sess-a", f.Handle, ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := r.p.Confirm(ctx, "sess-a", f.Handle, ad, cd, sig); code(err) != localapi.ErrEraseStale {
		t.Fatalf("replayed: %v", err)
	}
	now := time.Now()
	r.b.f.now = func() time.Time { return now }
	f = r.find("sess-a", "Alice Smith")
	r.b.f.now = func() time.Time { return now.Add(forgetFor) }
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); code(err) != localapi.ErrEraseStale {
		t.Fatalf("late: %v", err)
	}
	if _, err := r.p.Confirm(ctx, "sess-a", strings.Repeat("0", localapi.EraseHandle), ad, cd, sig); code(err) != localapi.ErrEraseStale {
		t.Fatalf("never found: %v", err)
	}
	if !slices.Equal(r.k.erases, []string{"s2"}) {
		t.Fatalf("erased %v", r.k.erases)
	}
}

// namedFails is a kernel whose look-up answers err.
type namedFails struct {
	*fakeKernel
	err error
}

func (n namedFails) Named(context.Context, string) ([]string, []string, error) {
	return nil, nil, n.err
}

// Nothing to confirm offers no tap; a kernel that cannot be reached gives
// the page a fixed code and no kernel text, and erases nothing.
func TestForgetFindsWithNothingToConfirm(t *testing.T) {
	r := newForgetPageRig(t)
	if f := r.find("sess-a", "Carol"); f.Handle != "" || f.Challenge != nil || f.Text != "Nothing named Carol was found." {
		t.Fatalf("nothing found: %+v", f)
	}
	r.k.closed = true
	if f := r.find("sess-a", "Bob"); f.Handle != "" || f.Text != "Stored content can't be read right now, so nothing was forgotten." {
		t.Fatalf("closed: %+v", f)
	}
	r.k.closed = false
	p := pageForget{F: newForgetFlow(namedFails{r.k, errors.New("kernel: unreachable at /run/x")}, r.b.rw), K: r.pk.k}
	if f, err := p.Find(context.Background(), "sess-a", "Bob"); code(err) != localapi.ErrEraseUnavailable || f.Text != "" {
		t.Fatalf("unreachable: %+v %v", f, err)
	}
	f := r.find("sess-a", "Bob")
	r.pk.k.err = errors.New("kernel: owner keys unreadable")
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); code(err) != localapi.ErrEraseUnavailable || len(r.k.erases) != 0 {
		t.Fatalf("keys unreadable: %v, erased %v", err, r.k.erases)
	}
	r.pk.k.err = nil
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil {
		t.Fatalf("after the keys came back: %v", err)
	}
}

// The tap's message is its own domain, apart from every message the
// kernel's keys sign, and binds each part by length.
func TestTheForgetMessageIsItsOwn(t *testing.T) {
	m := forgetMsg("s", "h", []string{"a", "b"})
	for _, d := range []string{key.DomainCosign, key.DomainRoot, key.DomainLink, key.DomainUse, key.DomainEnroll, key.DomainUnenroll} {
		if strings.HasPrefix(string(m), d) || d == domainPageForget {
			t.Fatalf("shares %q", d)
		}
	}
	if slices.Equal(m, forgetMsg("s", "h", []string{"ab"})) || slices.Equal(m, forgetMsg("s", "h", []string{"a"})) ||
		slices.Equal(m, forgetMsg("sh", "", []string{"a", "b"})) {
		t.Fatal("two lists sign the same")
	}
}

// A partial erase is never texted as whole: the page says "Not finished"
// and the owner's text says only some went (UX 1 on #5092).
func TestAPartialPageEraseIsNotTextedAsWhole(t *testing.T) {
	r := newForgetPageRig(t)
	r.k.add("s3", "Carol", 1, nil)
	r.k.add("s4", "Carol", 2, nil)
	r.k.eraseErr["s4"] = errors.New("kernel: unreachable")
	f := r.find("sess-a", "Carol")
	text, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0])
	if err != nil || !strings.HasPrefix(text, "Not finished:") || !slices.Equal(r.k.erases, []string{"s3"}) || !r.done.Kept {
		t.Fatalf("partial: %q %v %v, erased %v", text, err, r.done.Kept, r.k.erases)
	}
	// It counts only what went: s3's one item, not s4's two.
	if len(r.told) != 1 || !strings.HasPrefix(r.told[0], "I forgot 1 item (message 1) on my Wi-Fi page at 14:05 ") ||
		!strings.Contains(r.told[0], ". Some others found with them are still kept. Not you?") {
		t.Fatalf("told %q", r.told)
	}
	// Nothing erased texts nothing.
	r.k.eraseErr["s3"], r.told = errors.New("kernel: unreachable"), nil
	r.k.erased["s3"] = false
	r.k.erases = nil
	f = r.find("sess-a", "Carol")
	if text, err = r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil || !strings.HasPrefix(text, "Nothing was forgotten") || len(r.told) != 0 || !r.done.Kept {
		t.Fatalf("none: %q %v, told %q", text, err, r.told)
	}
}

// The notice counts only what this erase took, by kind: subjects erased
// meanwhile are not counted (Security 4 on #5092), and when every subject
// went meanwhile nothing is texted, since this erase took nothing
// (Potency 3 on #5092).
func TestTheForgetNoticeCountsOnlyThisErase(t *testing.T) {
	r := newForgetPageRig(t)
	r.k.add("s3", "Carol", 2, nil)
	r.k.add("s4", "Carol", 1, nil)
	r.k.items["s4"] = append(r.k.items["s4"], kernelsock.Item{Store: "photos", Class: "photo"}, kernelsock.Item{Store: "photos", Class: "photo"})
	f := r.find("sess-a", "Carol")
	if !strings.HasPrefix(f.Text, "Found 5 items named Carol (message 3, photo 2).") {
		t.Fatalf("readback %q", f.Text)
	}
	r.k.erased["s3"] = true // erased meanwhile
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil || r.done.Kept {
		t.Fatalf("%v kept %v", err, r.done.Kept)
	}
	if len(r.told) != 1 || !strings.HasPrefix(r.told[0], "I forgot 3 items (message 1, photo 2) on my Wi-Fi page") || strings.Contains(r.told[0], "still kept") {
		t.Fatalf("told %q", r.told)
	}
	r.told = nil
	r.k.add("s5", "Dan", 1, nil)
	f = r.find("sess-a", "Dan")
	r.k.erased["s5"] = true
	if text, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil || len(r.told) != 0 || r.done.Kept {
		t.Fatalf("all erased meanwhile: %q %v, told %q", text, err, r.told)
	}
	// A subject with nothing kept under its name is told without a count.
	r.k.add("s6", "Eve", 0, nil)
	f = r.find("sess-a", "Eve")
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil || len(r.told) != 1 ||
		!strings.HasPrefix(r.told[0], "I forgot a name with nothing kept under it on my Wi-Fi page") {
		t.Fatalf("told %q", r.told)
	}
}

// A name typed with either apostrophe finds what is kept under both, and
// each subject once (#5097 item 10).
func TestForgetFindsBothApostrophes(t *testing.T) {
	r := newForgetPageRig(t)
	r.k.add("s3", "O'Brien", 1, nil)
	r.k.add("s4", "O\u2019Brien", 2, nil)
	for _, n := range []string{"O'Brien", "O\u2019Brien"} {
		if f := r.find("sess-a", n); !strings.HasPrefix(f.Text, "Found 3 items named "+n+" (message 3).") {
			t.Fatalf("%s: %q", n, f.Text)
		}
	}
	if !slices.Equal(spellings("Ann"), []string{"Ann"}) || !slices.Equal(spellings("O'B\u2019x"), []string{"O'B\u2019x", "O'B'x", "O\u2019B\u2019x"}) {
		t.Fatal("spellings")
	}
}

// A notice that cannot be sent is kept on disk and sent in order once the
// owner can be reached, after a restart too; nothing sent is sent again
// (Potency 5 on #5092).
func TestAnUnsentForgetNoticeIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), forgetToldFile)
	var sent []string
	fail := errors.New("no owner channel")
	send := func(s string) error {
		if fail != nil {
			return fail
		}
		sent = append(sent, s)
		return nil
	}
	told := openForgetTold(path, send)
	told.tell("one")
	told.tell("two")
	if len(sent) != 0 {
		t.Fatalf("sent %q", sent)
	}
	// A restart reads them back; run sends them at once.
	told = openForgetTold(path, send)
	fail = nil
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { told.run(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		told.mu.Lock()
		n := len(told.texts)
		told.mu.Unlock()
		if n == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if !slices.Equal(sent, []string{"one", "two"}) {
		t.Fatalf("sent %q", sent)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the record stays: %v", err)
	}
	told.tell("three")
	if !slices.Equal(sent, []string{"one", "two", "three"}) {
		t.Fatalf("sent %q", sent)
	}
	// An unreadable record is set aside, not overwritten.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if told = openForgetTold(path, send); len(told.texts) != 0 {
		t.Fatal("read a bad record")
	}
	if b, err := os.ReadFile(path + ".bad"); err != nil || string(b) != "{" {
		t.Fatalf("set aside: %q %v", b, err)
	}
}
