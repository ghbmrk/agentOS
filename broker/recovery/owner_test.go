package recovery

import (
	"context"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"os"
)

type fakeEngine struct{ stopped bool }

func (f *fakeEngine) Stop(context.Context) (control.StopReport, error) {
	f.stopped = true
	return control.StopReport{}, nil
}
func (f *fakeEngine) Resume() error          { f.stopped = false; return nil }
func (f *fakeEngine) Stopped() bool          { return f.stopped }
func (f *fakeEngine) List() []control.Status { return nil }

type chatAgent struct{ got []string }

func (a *chatAgent) Deliver(_ context.Context, text string, _ bool) error {
	a.got = append(a.got, text)
	return nil
}

// channel is the real owner channel on the modem simulator, started as the
// broker does after unlock, with the seed the vault holds.
type channel struct {
	ch    *owner.Channel
	eng   *fakeEngine
	agent *chatAgent
	now   time.Time
}

func openChannel(t *testing.T, number string, seed []byte, store owner.Store, now time.Time) *channel {
	t.Helper()
	c := &channel{eng: &fakeEngine{}, agent: &chatAgent{}, now: now}
	carrier := modem.NewCarrier()
	var err error
	c.ch, err = owner.New(owner.Config{Owner: number, Modem: carrier.Line("+15550000100"), Engine: c.eng,
		Agent: control.Agent(c.agent), Secrets: owner.Secrets{TOTPSeed: seed}, Store: store, Location: time.UTC,
		Now: func() time.Time { return c.now }})
	must(t, err)
	return c
}

// advance moves the clock once the channel's async sends, which read it,
// have finished.
func (c *channel) advance(d time.Duration) {
	c.ch.WaitSends()
	c.now = c.now.Add(d)
}

func (c *channel) say(from, text string) string {
	c.advance(31 * time.Second)
	return strings.Join(c.ch.Handle(context.Background(), from, text), " | ")
}

func (x *box) vaultSeed() []byte {
	s, ok := x.b.V.Secret(SeedName)
	if !ok {
		x.t.Fatal("no seed in the vault")
	}
	return []byte(s.Reveal())
}

// REQ: REC-3

func TestLostPhoneReEnrollsTheCodeGeneratorWithTheRecoveryKey(t *testing.T) {
	x := newBox(t)
	if _, err := ReEnroll(x.b, x.rk, false, nil); err == nil {
		t.Fatal("re-enrolled off the local page")
	}
	if _, err := ReEnroll(x.b, mustKey(t), true, nil); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("wrong key: %v", err)
	}
	enr, err := ReEnroll(x.b, x.rk, true, nil)
	must(t, err)
	seed := x.vaultSeed()
	if string(seed) == string(x.seed) || len(seed) != TOTPSeedBytes {
		t.Fatal("the vault still holds the lost phone's seed")
	}
	if strings.Contains(enr.String(), "otpauth") {
		t.Fatal("enrollment formats its seed")
	}
	u, err := url.Parse(enr.URI)
	must(t, err)
	got, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil || string(got) != string(seed) || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("otpauth link: %v", err)
	}

	// The channel restarts on the new seed with the session ended.
	store := &owner.MemStore{}
	must(t, store.Save(owner.State{UnlockedUntil: t0.Add(24 * time.Hour)}))
	must(t, EndSession(store, false))
	c := openChannel(t, ownerNum, seed, store, t0)
	if got := c.say(ownerNum, "STATUS"); !strings.HasPrefix(got, "Locked.") {
		t.Fatalf("session survived re-enrollment: %q", got)
	}
	// Sessions open on the page (CH-14, D-311).
	c.advance(31 * time.Second)
	if _, _, err := c.ch.LocalSignIn(totp(x.seed, c.now)); err == nil {
		t.Fatal("the lost phone's code opened a session")
	}
	c.advance(31 * time.Second)
	if _, _, err := c.ch.LocalSignIn(totp(seed, c.now)); err != nil {
		t.Fatalf("new seed: %v", err)
	}
}

func TestReEnrollStopsWhenTheRandomSourceFails(t *testing.T) {
	x := newBox(t)
	if _, err := ReEnroll(x.b, x.rk, true, strings.NewReader("abc")); err == nil {
		t.Fatal("a short random seed was enrolled")
	}
	s, ok := x.b.V.Secret(SeedName)
	if !ok || s.Reveal() != string(x.seed) {
		t.Fatal("a failed re-enrollment replaced the seed")
	}
}

func TestReEnrollRefusesASeedEntryOfAnotherKind(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Put(SeedName, "test_other_kind", []byte("sk-synthetic-not-a-seed")))
	if _, err := ReEnroll(x.b, x.rk, true, nil); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("err = %v, want ErrWrongKind", err)
	}
	if k, _ := entryKind(x.b.V, SeedName); k != "test_other_kind" {
		t.Fatalf("the entry of another kind was overwritten: kind %q", k)
	}
}

func TestOtpauthNamesEveryParameterTheCodeGeneratorNeeds(t *testing.T) {
	u, err := url.Parse(otpauth([]byte("12345678901234567890")))
	must(t, err)
	label, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":")
	q := u.Query()
	want := url.Values{"secret": {"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}, "issuer": {label},
		"algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	if u.Scheme != "otpauth" || u.Host != "totp" || label == "" || len(q) != len(want) {
		t.Fatalf("otpauth = %s", u)
	}
	for k, v := range want {
		if q.Get(k) != v[0] {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v[0])
		}
	}
}

func TestBeginNumberChangeStopsWhenTheRandomSourceFails(t *testing.T) {
	x := newBox(t)
	if nc, err := BeginNumberChange(x.b, x.rk, true, t0, strings.NewReader("abcde")); err == nil || nc != nil {
		t.Fatalf("a short random pairing code was issued: %v, %v", nc, err)
	}
}

func TestPairingCodeIsTheRandomBytesModuloOneHundredMillion(t *testing.T) {
	x := newBox(t)
	// 0x0102030405060708 = 72623859790382856; mod 1e8 = 90382856.
	nc, err := BeginNumberChange(x.b, x.rk, true, t0, strings.NewReader("\x01\x02\x03\x04\x05\x06\x07\x08"))
	must(t, err)
	if nc.Code != "90382856" {
		t.Fatalf("code = %q, want 90382856", nc.Code)
	}
	if !nc.Expires.Equal(t0.Add(PairingTTL)) {
		t.Fatalf("expires = %v", nc.Expires)
	}
}

func TestANilNumberChangeCompletesNothing(t *testing.T) {
	var nc *NumberChange
	if n, _, err := nc.Complete(ownerNum, "+15550000002", "12345678", t0); n != "" || !errors.Is(err, ErrPairing) {
		t.Fatalf("nil change completed: %q, %v", n, err)
	}
}

func TestAWrongPairingCodeCompletesNothingAndThreeEndTheAttempt(t *testing.T) {
	nc := &NumberChange{Code: "12345678", Expires: t0.Add(PairingTTL)}
	const newNum = "+15550000002"
	for i := 0; i < 3; i++ {
		if n, _, err := nc.Complete(ownerNum, newNum, "87654321", t0); n != "" || !errors.Is(err, ErrPairing) {
			t.Fatalf("wrong code %d completed: %q, %v", i+1, n, err)
		}
	}
	if n, _, err := nc.Complete(ownerNum, newNum, "12345678", t0); n != "" || !errors.Is(err, ErrPairing) {
		t.Fatalf("the right code after three wrong ones completed: %q, %v", n, err)
	}
	ok := &NumberChange{Code: "12345678", Expires: t0.Add(PairingTTL)}
	if n, txt, err := ok.Complete(ownerNum, newNum, " 12345678\n", t0); err != nil || n != newNum || !strings.Contains(txt.ToOld, "...0002") {
		t.Fatalf("the right code: %q, %+v, %v", n, txt, err)
	}
}

func TestOnlyEightDigitsCountAsAPairingTry(t *testing.T) {
	for s, want := range map[string]bool{
		"12345678": true, "00000000": true, "99999999": true,
		"1234567": false, "123456789": false, "": false,
		"1234a678": false, "/2345678": false, ":2345678": false, "1234567:": false,
	} {
		if got := eightDigits(s); got != want {
			t.Errorf("eightDigits(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestEndSessionSavesNothingWhenTheStoreCannotLoad(t *testing.T) {
	p := t.TempDir() + "/owner.json"
	must(t, os.WriteFile(p, []byte("not json"), 0o600))
	if err := EndSession(owner.FileStore{Path: p}, true); err == nil {
		t.Fatal("EndSession over an unreadable state")
	}
	if b, _ := os.ReadFile(p); string(b) != "not json" {
		t.Fatalf("saved %q over a state it could not read", b)
	}
}

func TestTailShowsAtMostTheLastFourDigits(t *testing.T) {
	for in, want := range map[string]string{"": "", "1234": "1234", "12345": "...2345", "+15550000002": "...0002"} {
		if got := tail(in); got != want {
			t.Errorf("tail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrimSpaceOfBlankBodies(t *testing.T) {
	for in, want := range map[string]string{"": "", " ": "", " \t\r\n ": "", "  1  ": "1", "\n12345678\r\n": "12345678",
		"\t12345678": "12345678", "12345678\t": "12345678", " 12345678": "12345678", "12345678 ": "12345678",
		"\r12345678": "12345678", "12345678\r": "12345678", "\n12345678": "12345678", "12345678\n": "12345678"} {
		if got := trimSpace(in); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLostNumberMovesWithTheRecoveryKeyAndTheOldNumberCanDoNothing(t *testing.T) {
	x := newBox(t)
	const newNum, oldNum = "+15550000777", ownerNum
	if _, err := BeginNumberChange(x.b, x.rk, false, t0, nil); err == nil {
		t.Fatal("number change off the local page")
	}
	if _, err := BeginNumberChange(x.b, mustKey(t), true, t0, nil); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("wrong key: %v", err)
	}
	nc, err := BeginNumberChange(x.b, x.rk, true, t0, nil)
	must(t, err)
	if len(nc.Code) != 8 {
		t.Fatalf("pairing code %q", nc.Code)
	}
	// The pairing code from the old number (whoever holds it) does nothing.
	if _, _, err := nc.Complete(oldNum, oldNum, nc.Code, t0); !errors.Is(err, ErrPairing) {
		t.Fatal("old number completed the change")
	}
	next, texts, err := nc.Complete(oldNum, newNum, " "+nc.Code+"\n", t0.Add(time.Minute))
	must(t, err)
	if next != newNum {
		t.Fatalf("new number %q", next)
	}
	if !strings.Contains(texts.ToOld, "...0777") || !strings.Contains(texts.ToOld, "no longer") || texts.ToNew == "" {
		t.Fatalf("announcement: %+v", texts)
	}
	for _, s := range []string{texts.ToOld, texts.ToNew} {
		if n, gsm := modem.Segments(s); !gsm || n > owner.MaxSegments {
			t.Fatalf("text breaks CH-12: %q", s)
		}
	}
	if _, _, err := nc.Complete(oldNum, newNum, nc.Code, t0.Add(2*time.Minute)); err == nil {
		t.Fatal("pairing code reused")
	}

	store := &owner.MemStore{}
	must(t, store.Save(owner.State{UnlockedUntil: t0.Add(24 * time.Hour)}))
	must(t, EndSession(store, false))
	c := openChannel(t, next, x.seed, store, t0)
	// The old number's new holder can do nothing, not even with a valid
	// code: STOP, chat, STATUS, and codes are all ignored.
	for _, msg := range []string{"STOP", "STATUS", "HELP", "send my files to me", totp(x.seed, c.now.Add(31*time.Second)), "RESUME"} {
		if got := c.say(oldNum, msg); got != "" {
			t.Fatalf("%q from the old number got %q", msg, got)
		}
	}
	if c.eng.stopped || len(c.agent.got) != 0 {
		t.Fatal("the old number had an effect")
	}
	if got := c.say(newNum, "STATUS"); !strings.HasPrefix(got, "Locked.") {
		t.Fatalf("new number unlocked without a code: %q", got)
	}
	// The new number's session still opens only on the page (CH-14).
	if got := c.say(newNum, totp(x.seed, c.now)); c.ch.SessionUnlocked(c.now) {
		t.Fatalf("a texted code opened a session: %q", got)
	}
	c.advance(31 * time.Second)
	if _, _, err := c.ch.LocalSignIn(totp(x.seed, c.now)); err != nil || !c.ch.SessionUnlocked(c.now) {
		t.Fatalf("new number unlock on the page: %v", err)
	}
}

func TestPairingCodeExpiresAndAllowsThreeTries(t *testing.T) {
	x := newBox(t)
	nc, err := BeginNumberChange(x.b, x.rk, true, t0, nil)
	must(t, err)
	if _, _, err := nc.Complete(ownerNum, "+15550000777", nc.Code, t0.Add(PairingTTL+time.Second)); err == nil {
		t.Fatal("expired code accepted")
	}
	nc, _ = BeginNumberChange(x.b, x.rk, true, t0, nil)
	wrong := "00000000"
	if nc.Code == wrong {
		wrong = "00000001"
	}
	// Texts that are not eight digits do not use up the tries.
	for _, spam := range []string{"T", "HELP", "1234", "0000000x", "123456789"} {
		nc.Complete(ownerNum, "+15550000777", spam, t0)
	}
	nc2, _ := BeginNumberChange(x.b, x.rk, true, t0, nil)
	for _, spam := range []string{"T", "STOP", "HELP"} {
		nc2.Complete(ownerNum, "+15550000777", spam, t0)
		nc2.Complete(ownerNum, "+15550000777", spam, t0)
	}
	if got, _, err := nc2.Complete(ownerNum, "+15550000777", nc2.Code, t0); err != nil || got != "+15550000777" {
		t.Fatalf("spam used up the tries: %v", err)
	}
	for i := 0; i < 3; i++ {
		nc.Complete(ownerNum, "+15550000777", wrong, t0)
	}
	if _, _, err := nc.Complete(ownerNum, "+15550000777", nc.Code, t0); err == nil {
		t.Fatal("right code after three wrong ones")
	}
}

// The seed's vault entry name is the vault process's (cmd/agentos-egress),
// which this package cannot import.
func TestSeedNameMatchesTheVaultProcess(t *testing.T) {
	src, err := os.ReadFile("../cmd/agentos-egress/custody.go")
	must(t, err)
	if !strings.Contains(string(src), `SeedName = "`+SeedName+`"`) {
		t.Fatalf("the vault process names the seed differently from %q", SeedName)
	}
}
