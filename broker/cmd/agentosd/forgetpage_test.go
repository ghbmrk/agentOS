package main

// REQ: LOG-4, CH-3, CH-26

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
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
	// told is what the owner was texted.
	told []string
}

func newForgetPageRig(t *testing.T) *forgetPageRig {
	r := &forgetPageRig{t: t, pk: newPasskeyRig(t), k: newFakeKernel(), m: &rewindMachines{}}
	r.k.add("s1", "Alice Smith", 3, map[string]int64{"L1": 1_700_000_000_000})
	r.k.add("s2", "Bob", 1, nil)
	r.b = newForgetBox(t, r.k, r.m, t.TempDir())
	r.p = pageForget{F: r.b.f, K: r.pk.k, Tell: func(text string) error { r.told = append(r.told, text); return nil }}
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
	return r.p.Confirm(context.Background(), session, f.Handle, ad, cd, sig)
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
	// The owner is texted of the page erase by count and the passkey that
	// tapped, never by the name.
	note := forgetNotice(forgetResult{Items: 3, Erased: 1}, r.pk.anchors[1].public(t))
	if !slices.Equal(r.told, []string{note}) || strings.Contains(strings.ToLower(note), "alice") ||
		!strings.HasPrefix(note, "I forgot 3 items on my Wi-Fi page after a tap by passkey ") || !strings.HasSuffix(note, ". Not you? Text STOP.") {
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
	if err != nil || !strings.HasPrefix(text, "Not finished:") || !slices.Equal(r.k.erases, []string{"s3"}) {
		t.Fatalf("partial: %q %v, erased %v", text, err, r.k.erases)
	}
	if len(r.told) != 1 || !strings.HasPrefix(r.told[0], "I forgot some of 3 items, not all, on my Wi-Fi page") {
		t.Fatalf("told %q", r.told)
	}
	// Nothing erased texts nothing.
	r.k.eraseErr["s3"], r.told = errors.New("kernel: unreachable"), nil
	r.k.erased["s3"] = false
	r.k.erases = nil
	f = r.find("sess-a", "Carol")
	if text, err = r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); err != nil || !strings.HasPrefix(text, "Nothing was forgotten") || len(r.told) != 0 {
		t.Fatalf("none: %q %v, told %q", text, err, r.told)
	}
}
