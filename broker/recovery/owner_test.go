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
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"os"
)

type fakeEngine struct{ stopped bool }

func (f *fakeEngine) Stop(context.Context) (journal.StopReport, error) {
	f.stopped = true
	return journal.StopReport{}, nil
}
func (f *fakeEngine) Resume() error          { f.stopped = false; return nil }
func (f *fakeEngine) Stopped() bool          { return f.stopped }
func (f *fakeEngine) List() []journal.Status { return nil }

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

func (c *channel) say(from, text string) string {
	c.now = c.now.Add(31 * time.Second)
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
	if got := c.say(ownerNum, "STATUS"); !strings.Contains(got, "code generator") {
		t.Fatalf("session survived re-enrollment: %q", got)
	}
	if got := c.say(ownerNum, totp(x.seed, c.now)); strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("the lost phone's code unlocked: %q", got)
	}
	if got := c.say(ownerNum, totp(seed, c.now)); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("new seed: %q", got)
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
	if got := c.say(newNum, "STATUS"); !strings.Contains(got, "code generator") {
		t.Fatalf("new number unlocked without a code: %q", got)
	}
	if got := c.say(newNum, totp(x.seed, c.now)); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("new number unlock: %q", got)
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
	for i := 0; i < 3; i++ {
		nc.Complete(ownerNum, "+15550000777", "00000000x", t0)
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
