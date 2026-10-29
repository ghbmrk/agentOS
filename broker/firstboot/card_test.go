package firstboot

// REQ: HW-1, REC-4, ONB-7

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// boot is one start of a box from an image partition at dir: the card
// step's state, the journal and the process log all live on that
// partition, and provisioning writes the real vault there.
type boot struct {
	t     *testing.T
	dir   string
	step  *CardStep
	shown *card.Card // copy of the generated card, kept by the test only
	v     *vault.Vault
	calls int
}

func journalPath(dir string) string {
	return filepath.Join(dir, "var", "log", "agentos", "journal.log")
}

func bootImage(t *testing.T, dir string) *boot {
	t.Helper()
	b := &boot{t: t, dir: dir}
	for _, d := range []string{"var/lib/agentos", "var/log/agentos", "egress"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	jf, err := os.OpenFile(journalPath(dir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { jf.Close() })
	st := change.FileStore{Path: filepath.Join(dir, "var", "lib", "agentos", "firstboot-card.json")}
	b.step, err = NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				cp.GridSeed = bytes.Clone(c.GridSeed)
				b.shown = &cp
			}
			return c, err
		},
		Provision: b.provision,
		Journal: func(e string) {
			jf.WriteString(e + "\n")
			log.Print("journal: " + e)
			slog.Info("journal", "event", e)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// provision is the vault process's setup (§8.1): a vault sealed by the
// card's passphrase, then the recovery slot and the card's stored values.
func (b *boot) provision(c *card.Card) error {
	b.calls++
	eg := filepath.Join(b.dir, "egress")
	v, err := vault.CreateSealed(filepath.Join(eg, "vault"), filepath.Join(eg, "vault.keys"), vault.Passphrase(c.VaultPassphrase))
	if err != nil {
		return err
	}
	b.v = v
	b.t.Cleanup(func() { v.Close() })
	box := &recovery.Box{VaultPath: filepath.Join(eg, "vault"), KeysPath: filepath.Join(eg, "vault.keys"), V: v}
	return recovery.Provision(box, recovery.Card{SetupSecret: c.SetupSecret,
		SetupCode: c.SetupCode, VaultPassphrase: c.VaultPassphrase, GridSeed: c.GridSeed, RecoveryKey: c.RecoveryKey},
		vault.Passphrase(c.VaultPassphrase))
}

func (b *boot) answers() (string, string) {
	w, g := b.step.Display().Asks()
	return strings.Fields(b.shown.VaultPassphrase)[w-1], strings.Split(b.shown.RecoveryKey, "-")[g-1]
}

// needles are the card's secrets as the A8 scanner looks for them.
func needles(c *card.Card) []recovery.Needle {
	return []recovery.Needle{
		{Name: "passphrase", Value: []byte(c.VaultPassphrase), Text: true},
		{Name: "recovery key", Value: []byte(c.RecoveryKey), Text: true},
		{Name: "setup secret", Value: []byte(c.SetupSecret), Text: true},
		{Name: "setup code", Value: []byte(c.SetupCode), Text: true},
		{Name: "grid seed", Value: c.GridSeed},
	}
}

// scan fails the test if any card secret is on the partition.
func scan(t *testing.T, dir string, c *card.Card) {
	t.Helper()
	s, err := recovery.NewScanner(needles(c))
	if err != nil {
		t.Fatal(err)
	}
	found, skipped, err := s.Tree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) > 0 {
		t.Fatalf("scan skipped %v", skipped)
	}
	if len(found) > 0 {
		t.Fatalf("card text on the partition: %v", found)
	}
}

// captureLogs sends the standard and structured loggers to a file on the
// partition for the test's duration.
func captureLogs(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "var", "log", "agentos", "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	ow, of, od := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(f)
	slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
	t.Cleanup(func() { log.SetOutput(ow); log.SetFlags(of); slog.SetDefault(od); f.Close() })
}

// Acceptance 1: after the confirm step, no card text remains on the box's
// partition or in its journal and logs; the vault the card provisioned
// opens with the card's passphrase.
func TestCardStepConfirmLeavesNoCardText(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "var", "log", "agentos"), 0o700); err != nil {
		t.Fatal(err)
	}
	captureLogs(t, dir)
	b := bootImage(t, dir)
	if err := b.step.Hold(); !errors.Is(err, ErrCardPending) {
		t.Fatalf("hold before confirm: %v", err)
	}
	h := b.step.Display().Handler(func(*http.Request) bool { return true }, "/setup")
	r := httptest.NewRequest("GET", "/card", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), b.shown.RecoveryKey) {
		t.Fatalf("card page: %d", w.Code)
	}
	word, grp := b.answers()
	r = httptest.NewRequest("POST", "/card", strings.NewReader(url.Values{"word": {word}, "group": {grp}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d", w.Code)
	}
	if err := b.step.Hold(); err != nil {
		t.Fatalf("hold after confirm: %v", err)
	}
	if _, err := b.step.Display().Page(); !errors.Is(err, card.ErrDisplayGone) {
		t.Fatalf("display after confirm: %v", err)
	}
	b.v.Close()

	jb, err := os.ReadFile(journalPath(dir))
	if err != nil || len(jb) == 0 {
		t.Fatalf("journal empty: %v", err)
	}
	scan(t, dir, b.shown)

	// The vault holds the card: it opens with the passphrase from paper.
	v, err := vault.OpenSealed(filepath.Join(dir, "egress", "vault"), filepath.Join(dir, "egress", "vault.keys"), vault.Passphrase(b.shown.VaultPassphrase))
	if err != nil {
		t.Fatalf("vault does not open with the card's passphrase: %v", err)
	}
	v.Close()

	// A restart keeps setup open past the card step and shows no card.
	again := bootImage(t, dir)
	if again.step.Display() != nil || again.step.Hold() != nil || again.shown != nil {
		t.Fatal("card step runs again after a confirmed boot")
	}
}

// Acceptance 2: without a correct confirm the display copy stays, nothing
// is provisioned, and the box does not finish setup.
func TestCardStepWithoutConfirmHolds(t *testing.T) {
	dir := t.TempDir()
	b := bootImage(t, dir)
	h := b.step.Display().Handler(func(*http.Request) bool { return true }, "/setup")
	for _, f := range []url.Values{{}, {"word": {"xqzxqzx"}, "group": {"AAAAA"}}} {
		r := httptest.NewRequest("POST", "/card", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("wrong confirm: %d", w.Code)
		}
	}
	if err := b.step.Hold(); !errors.Is(err, ErrCardPending) || !strings.Contains(err.Error(), "Owner Card") {
		t.Fatalf("hold: %v", err)
	}
	if b.calls != 0 {
		t.Fatal("provisioned without a confirm")
	}
	if _, err := os.Stat(filepath.Join(dir, "egress", "vault.keys")); !os.IsNotExist(err) {
		t.Fatal("vault created without a confirm")
	}
	if _, err := b.step.Display().Page(); err != nil {
		t.Fatalf("display gone: %v", err)
	}
	// Nothing of the unconfirmed card was written to the partition.
	scan(t, dir, b.shown)
	// A restart before the confirm shows a new card, never the old one:
	// the old one was never provisioned, so it unlocks nothing.
	again := bootImage(t, dir)
	if again.step.Hold() == nil || again.shown == nil || again.shown.RecoveryKey == b.shown.RecoveryKey {
		t.Fatal("restart before confirm reused the card or opened setup")
	}
}

// A failed latch save after provisioning keeps the step held and the
// display shown, so the owner is never told setup moved on when it did
// not.
func TestCardStepLatchFailureHolds(t *testing.T) {
	st := &change.MemStore{}
	var provisioned int
	var shown *card.Card
	s, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				shown = &cp
			}
			return c, err
		},
		Provision: func(*card.Card) error { provisioned++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	st.Fail = errors.New("disk full")
	w, g := s.Display().Asks()
	word, grp := strings.Fields(shown.VaultPassphrase)[w-1], strings.Split(shown.RecoveryKey, "-")[g-1]
	if err := s.Display().Confirm(word, grp); err == nil {
		t.Fatal("confirm succeeded without the latch")
	}
	if !errors.Is(s.Hold(), ErrCardPending) || s.Display().Confirmed() {
		t.Fatal("step moved on without the latch")
	}
	st.Fail = nil
	if err := s.Display().Confirm(word, grp); err != nil {
		t.Fatal(err)
	}
	if s.Hold() != nil || provisioned != 2 {
		t.Fatalf("hold %v, provisioned %d", s.Hold(), provisioned)
	}
}

// Acceptance 3: two boots of the same image make different cards, and the
// image itself holds none of either card's values (no seller-known value).
func TestCardStepTwoBootsDiffer(t *testing.T) {
	image := t.TempDir()
	if err := os.MkdirAll(filepath.Join(image, "var", "lib", "agentos"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(image, "var", "lib", "agentos", "release"), []byte("agentos 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flash := func() string {
		d := t.TempDir()
		if err := os.CopyFS(d, os.DirFS(image)); err != nil {
			t.Fatal(err)
		}
		return d
	}
	a, b := bootImage(t, flash()), bootImage(t, flash())
	ca, cb := a.shown, b.shown
	for name, pair := range map[string][2]string{
		"setup secret": {ca.SetupSecret, cb.SetupSecret}, "setup code": {ca.SetupCode, cb.SetupCode},
		"passphrase": {ca.VaultPassphrase, cb.VaultPassphrase}, "recovery key": {ca.RecoveryKey, cb.RecoveryKey},
		"grid seed": {string(ca.GridSeed), string(cb.GridSeed)},
	} {
		if pair[0] == pair[1] {
			t.Fatalf("two boots share the %s", name)
		}
	}
	scan(t, image, ca)
	scan(t, image, cb)
}

func TestNewCardStepBadState(t *testing.T) {
	st := &change.MemStore{}
	if err := st.Save([]byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t), Provision: func(*card.Card) error { return nil }}); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

// countRand counts the bytes read from it.
type countRand struct{ n int }

func (c *countRand) Read(p []byte) (int, error) { c.n += len(p); return len(p), nil }

// REQ: HW-1
//
// No authority, no card: a card step without the page authority (nil or
// not the page's) builds no display, draws nothing and generates nothing,
// holds with the fixed ErrNoAuthority line, and never errors out of
// NewCardStep or Begin, so the page does not crash-loop. Again leaves the
// vault alone. It catches a crash-loop or a card drawn early.
func TestCardStepHoldsWithoutAuthority(t *testing.T) {
	for name, auth := range map[string][]byte{"nil": nil, "garbage": []byte("not a certificate")} {
		r := &countRand{}
		gen := 0
		cfg := card.DisplayConfig{Authority: auth, Rand: r,
			Generate:  func(r io.Reader) (*card.Card, error) { gen++; return card.Generate(r) },
			Provision: func(*card.Card) error { t.Fatal("provisioned without a card"); return nil }}
		s, err := NewCardStep(&change.MemStore{}, cfg)
		if err != nil {
			t.Fatalf("%s: NewCardStep: %v", name, err)
		}
		if s.Display() != nil || !errors.Is(s.Hold(), ErrNoAuthority) || r.n != 0 || gen != 0 {
			t.Fatalf("%s: display %v, hold %v, %d random bytes, %d cards", name, s.Display(), s.Hold(), r.n, gen)
		}
		resets := 0
		if err := s.Again(func() error { resets++; return nil }); !errors.Is(err, ErrNoAuthority) || resets != 0 {
			t.Fatalf("%s: Again = %v after %d resets", name, err, resets)
		}
		if s.Hold().Error() != "I can't make your Owner Card yet, because my page certificate isn't ready. Restart me and open this page again. If you see this again, tell me in a text." {
			t.Fatalf("hold text %q", s.Hold())
		}
		// Begin, on the download route, starts and holds the same way.
		fb, err := Begin(BoxConfig{Download: true, Latch: &change.MemStore{}, Reset: func() error { return nil }, Card: cfg,
			Claim: claim.Config{Store: &change.MemStore{}}})
		if err != nil {
			t.Fatalf("%s: Begin: %v", name, err)
		}
		if fb.Card.Display() != nil || !errors.Is(fb.Card.Hold(), ErrNoAuthority) || r.n != 0 || gen != 0 {
			t.Fatalf("%s: Begin's card step drew a card", name)
		}
	}
	// A confirmed latch needs no authority: the card is done.
	st := &change.MemStore{}
	if err := st.Save([]byte(`{"card_confirmed":true}`)); err != nil {
		t.Fatal(err)
	}
	s, err := NewCardStep(st, card.DisplayConfig{Provision: func(*card.Card) error { return nil }})
	if err != nil || s.Hold() != nil {
		t.Fatalf("confirmed card step: %v, hold %v", err, s.Hold())
	}
}

// REQ: HW-1
//
// OWN-card-flow decisions 8 and 10: a provision that answers ErrKept
// latches the step as confirmed and leaves its line for the page once; one
// that answers another Line holds, keeps the card for a retry and leaves
// its line once; a retry that succeeds leaves none. It catches a stuck box
// after a crash between the hand-off and the latch, and a refusal that
// latches.
func TestCardStepKeptLatchesAndLinesHold(t *testing.T) {
	refusal := Line("a fixed refusal line")
	var answer error
	st := &change.MemStore{}
	var shown *card.Card
	s, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				shown = &cp
			}
			return c, err
		},
		Provision: func(*card.Card) error { return answer }})
	if err != nil {
		t.Fatal(err)
	}
	if TakeNote(s) != "" {
		t.Fatal("a note before any confirm")
	}
	confirm := func() error {
		w, g := s.Display().Asks()
		return s.Display().Confirm(strings.Fields(shown.VaultPassphrase)[w-1], strings.Split(shown.RecoveryKey, "-")[g-1])
	}
	answer = fmt.Errorf("wrapped: %w", refusal)
	if err := confirm(); !errors.Is(err, refusal) || s.Hold() == nil || s.Display() == nil {
		t.Fatalf("a refusal: %v, hold %v", err, s.Hold())
	}
	if b, _ := st.Load(); b != nil {
		t.Fatalf("a refusal latched: %s", b)
	}
	if n := TakeNote(s); n != string(refusal) || TakeNote(s) != "" {
		t.Fatalf("note %q, then not cleared", n)
	}
	answer = errors.New("not a line")
	if err := confirm(); err == nil || TakeNote(s) != "" || s.Hold() == nil {
		t.Fatalf("a plain error: %v, or it left a note", err)
	}
	answer = fmt.Errorf("keeper: %w", ErrKept)
	if err := confirm(); err != nil || s.Hold() != nil {
		t.Fatalf("kept: %v, hold %v", err, s.Hold())
	}
	if n := TakeNote(s); n != string(ErrKept) {
		t.Fatalf("kept note %q", n)
	}
	b, err := st.Load()
	if err != nil || !strings.Contains(string(b), `"card_confirmed":true`) {
		t.Fatalf("kept did not latch: %s %v", b, err)
	}
	if TakeNote(nil) != "" {
		t.Fatal("a note with no card step")
	}
}
