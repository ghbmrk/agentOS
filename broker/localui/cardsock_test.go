package localui

// REQ: HW-1, F10

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// fakeUnlock is the vault process's unlock socket for the card ops: it
// records each body and answers with the next reply set for its path.
type fakeUnlock struct {
	mu     sync.Mutex
	bodies map[string][]byte
	code   map[string]int
	reply  map[string]any
}

func newFakeUnlock(t *testing.T) (*fakeUnlock, *UnlockClient) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ul") // a short path: sockets are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "unlock.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUnlock{bodies: map[string][]byte{}, code: map[string]int{}, reply: map[string]any{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies[r.URL.Path] = b
		code, reply := f.code[r.URL.Path], f.reply[r.URL.Path]
		f.mu.Unlock()
		if code == 0 {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(reply)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return f, NewUnlockClient(path)
}

func (f *fakeUnlock) set(path string, code int, reply any) {
	f.mu.Lock()
	f.code[path], f.reply[path] = code, reply
	f.mu.Unlock()
}

func (f *fakeUnlock) body(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[path]
}

var refusedCodes = map[string]any{"error": "no code generator is confirmed", "reason": ReasonCodesUnconfirmed}

// Brief test 2: the card's seven fields go to /card/provision; the K21
// refusal's reason wraps ErrCodesUnconfirmed, another refusal does not;
// /card/reset's remade comes back.
func TestTheCardOpsGoOverTheUnlockSocket(t *testing.T) {
	f, u := newFakeUnlock(t)
	ctx := context.Background()
	c := &card.Card{SetupSecret: "canary-secret",
		SetupCode: "canary-code", VaultPassphrase: "canary pass phrase", GridSeed: []byte{1, 2, 3}, RecoveryKey: "CANA-RY00"}
	f.set("/card/provision", 200, map[string]any{"ok": true})
	if err := u.ProvisionCard(ctx, c); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(f.body("/card/provision"), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"setup_secret": c.SetupSecret,
		"setup_code": c.SetupCode, "vault_passphrase": c.VaultPassphrase, "grid_seed": "AQID", "recovery_key": c.RecoveryKey}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("provision body %v, want %v", got, want)
	}

	f.set("/card/provision", http.StatusPreconditionFailed, refusedCodes)
	err := u.ProvisionCard(ctx, c)
	var verr *VaultError
	if !errors.Is(err, ErrCodesUnconfirmed) || !errors.As(err, &verr) || verr.Status != http.StatusPreconditionFailed {
		t.Fatalf("K21 refusal: %v", err)
	}
	f.set("/card/provision", http.StatusPreconditionFailed, map[string]any{"error": "setup is not open"})
	if err := u.ProvisionCard(ctx, c); err == nil || errors.Is(err, ErrCodesUnconfirmed) {
		t.Fatalf("a refusal without the reason: %v", err)
	}

	for _, remade := range []bool{false, true} {
		f.set("/card/reset", 200, map[string]any{"ok": true, "remade": remade})
		if got, err := u.ResetCard(ctx); err != nil || got != remade {
			t.Fatalf("reset remade %v: %v %v", remade, got, err)
		}
	}
}

// Either vault answer that voids the code generator sets CodesVoid
// through CardBox: a reset that remade the setup vault, and the K21
// provision refusal. A plain provision or reset does not.
func TestCardBoxMarksTheCodesVoid(t *testing.T) {
	f, u := newFakeUnlock(t)
	void := &CodesVoid{}
	box := CardBox(u, &fakeKeeper{word: KeeperOK}, change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")},
		&change.MemStore{}, void, testAuthority())
	f.set("/card/reset", 200, map[string]any{"ok": true})
	f.set("/card/provision", 200, map[string]any{"ok": true})
	if box.Reset() != nil || box.Card.Provision(&card.Card{}) != nil || void.Take() {
		t.Fatal("void after a plain reset and provision")
	}
	f.set("/card/reset", 200, map[string]any{"ok": true, "remade": true})
	if err := box.Reset(); err != nil || !void.Take() {
		t.Fatalf("remade reset: %v", err)
	}
	f.set("/card/provision", http.StatusPreconditionFailed, refusedCodes)
	if err := box.Card.Provision(&card.Card{}); !errors.Is(err, ErrCodesUnconfirmed) || !void.Take() {
		t.Fatalf("K21 provision: %v", err)
	}
	if void.Take() {
		t.Fatal("Take did not clear the mark")
	}
}

// voidRig is a card rig whose provision the test answers, with CodesVoid
// set as CardBox would set it.
type voidRig struct {
	*cardRig
	void   *CodesVoid
	refuse bool // the next provision is the K21 refusal
}

func newVoidRig(t *testing.T) *voidRig {
	t.Helper()
	vr := &voidRig{cardRig: &cardRig{rig: newRig(t)}, void: &CodesVoid{}}
	var err error
	vr.step, err = firstboot.NewCardStep(&change.MemStore{}, card.DisplayConfig{Authority: testAuthority(),
		Generate: func(rd io.Reader) (*card.Card, error) {
			c, err := card.Generate(rd)
			if err == nil {
				cp := *c
				vr.shown = &cp
			}
			return c, err
		},
		Provision: func(*card.Card) error {
			if vr.refuse {
				vr.refuse = false
				vr.remade()
				return fmt.Errorf("%w: %w", ErrCodesUnconfirmed, &VaultError{http.StatusPreconditionFailed, "refused"})
			}
			vr.made++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	vr.owned = vr.step
	vr.srv = vr.open(&MemStore{})
	vr.srv.cfg.CodesVoid = vr.void
	return vr
}

// remade is the vault process making the setup vault anew: no code
// generator is enrolled in it, and CardBox marks the codes void.
func (vr *voidRig) remade() {
	vr.hooks.mu.Lock()
	vr.hooks.seed = nil
	vr.hooks.mu.Unlock()
	vr.void.Set()
}

// redoCodes completes the codes step again from the page it shows.
func (vr *voidRig) redoCodes(page string) {
	vr.t.Helper()
	m := secretRe.FindStringSubmatch(page)
	if m == nil {
		vr.t.Fatalf("no new key on the codes step: %s", page)
	}
	seed, err := b32.DecodeString(m[1])
	if err != nil {
		vr.t.Fatal(err)
	}
	vr.post("/setup/codes", url.Values{"code": {owner.TOTP(seed, vr.clock())}})
}

func (vr *voidRig) onCodesWithNote() string {
	vr.t.Helper()
	page := html.UnescapeString(vr.get("/setup"))
	if !strings.Contains(page, replaceCodesNote) || !strings.Contains(page, `action="/setup/codes"`) {
		vr.t.Fatalf("not the codes step with the replace note: %s", page)
	}
	return page
}

// Brief test 3, the provision: the confirm whose provision the vault
// refused for an unconfirmed code generator goes back to the codes step,
// not the retry page; the note stays until step 3 is done again, and the
// same card then confirms.
func TestARefusedProvisionReturnsToTheCodesStep(t *testing.T) {
	vr := newVoidRig(t)
	vr.toCard()
	vr.get("/setup/card")
	w, g := vr.answers()
	vr.refuse = true
	rec := vr.do("POST", "/setup/card", url.Values{"word": {w}, "group": {g}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("refused confirm: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if vr.step.Hold() == nil {
		t.Fatal("the card counts as confirmed after a refused provision")
	}
	page := vr.onCodesWithNote()
	if !strings.Contains(html.UnescapeString(vr.get("/setup")), replaceCodesNote) {
		t.Fatal("the note left before step 3 was done again")
	}
	vr.redoCodes(page)
	if page := html.UnescapeString(vr.get("/setup")); strings.Contains(page, replaceCodesNote) || !strings.Contains(page, "Owner Card") {
		t.Fatalf("after step 3 again: %s", page)
	}
	shown := *vr.shown
	vr.get("/setup/card")
	if vr.shown.RecoveryKey != shown.RecoveryKey {
		t.Fatal("the display made a new card for the retry")
	}
	w, g = vr.answers()
	rec = vr.do("POST", "/setup/card", url.Values{"word": {w}, "group": {g}})
	if rec.Code != http.StatusSeeOther || vr.step.Hold() != nil || vr.made != 1 {
		t.Fatalf("confirm after step 3: %d hold %v provisions %d", rec.Code, vr.step.Hold(), vr.made)
	}
}

// Brief test 3, the reset: a reset that remade the setup vault (as Begin's
// ResetUnlatched after a restart) sends the next /setup to the codes step
// with the note.
func TestARemadeVaultReturnsToTheCodesStep(t *testing.T) {
	vr := newVoidRig(t)
	vr.toCard()
	vr.remade()
	vr.redoCodes(vr.onCodesWithNote())
	if page := html.UnescapeString(vr.get("/setup")); strings.Contains(page, replaceCodesNote) || !strings.Contains(page, "Owner Card") {
		t.Fatalf("after step 3 again: %s", page)
	}
}

// Brief test 7: the card step says a card from before a restart is void,
// and the replace note fits a text message's GSM-7 alphabet (CH-12).
func TestTheCardStepCarriesTheRestartNote(t *testing.T) {
	cr := newCardRig(t)
	cr.toCard()
	if page := html.UnescapeString(cr.get("/setup")); !strings.Contains(page, cardRestartNote) {
		t.Fatalf("card step without the restart note: %s", page)
	}
	for _, s := range []string{replaceCodesNote, cardRestartNote} {
		if _, gsm := modem.Segments(s); !gsm {
			t.Fatalf("not GSM-7: %q", s)
		}
	}
}

// heldUntil is a card step whose hold the test lifts.
type heldUntil struct{ held bool }

func (h *heldUntil) Display() *card.Display { return nil }
func (h *heldUntil) Hold() error {
	if h.held {
		return firstboot.ErrCardPending
	}
	return nil
}

// #1330 and external review 12 item 12: CardFinish makes one finish call.
// A held card sends card false, so agentosd's finish refuses (card
// pending); a confirmed card sends card true in that same call. A card
// pending after a confirmed report reruns the card step and answers
// ErrCardAgain; a rerun that fails answers neither that nor card pending's
// refusal alone, and a refusal for a held card reruns nothing.
func TestCardFinishSendsOneCall(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	vaultHasCard := true
	ops := InProcess{
		localapi.OpSetupFinish: func(_ context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			var f localapi.Finish
			if json.Unmarshal(raw, &f) != nil || f.Owner != ownerNum {
				return nil, sockets.Code(localapi.ErrBadArgs)
			}
			calls = append(calls, fmt.Sprintf("%s card=%v", localapi.OpSetupFinish, f.Card))
			if !f.Card || !vaultHasCard {
				return nil, sockets.Code(localapi.ErrCardPending)
			}
			return struct{}{}, nil
		},
	}
	hold := &heldUntil{held: true}
	agains := 0
	var againErr error
	f := CardFinish{AgentosdSetup: AgentosdSetup{Owner: ops}, Card: hold,
		Again: func() error { agains++; return againErr }}
	if err := f.Finish(ownerNum); !refused(err, localapi.ErrCardPending) || fmt.Sprint(calls) != "[page_setup_finish card=false]" || agains != 0 {
		t.Fatalf("held card: %v, calls %v, reruns %d", err, calls, agains)
	}
	hold.held, calls = false, nil
	if err := f.Finish(ownerNum); err != nil || fmt.Sprint(calls) != "[page_setup_finish card=true]" {
		t.Fatalf("confirmed card: %v, calls %v", err, calls)
	}
	vaultHasCard, calls = false, nil
	if err := f.Finish(ownerNum); !errors.Is(err, ErrCardAgain) || agains != 1 || len(calls) != 1 {
		t.Fatalf("vault without a card: %v, reruns %d, calls %v", err, agains, calls)
	}
	againErr = errors.New("vault busy")
	if err := f.Finish(ownerNum); err == nil || errors.Is(err, ErrCardAgain) || agains != 2 {
		t.Fatalf("failed rerun: %v, reruns %d", err, agains)
	}
	if err := (AgentosdSetup{Owner: ops}).Finish(ownerNum); !refused(err, localapi.ErrCardPending) {
		t.Fatalf("AgentosdSetup reported a card: %v", err)
	}
}

// #1330: a finish refused because the vault holds no Owner Card (CardFinish
// reran the step: ErrCardAgain) shows the fixed message, routes setup back
// to the card step with a new card, and once that card is confirmed and
// the recovery step done again, setup finishes.
func TestCardPendingMakesTheCardAgain(t *testing.T) {
	cr := newCardRig(t)
	cr.toCard()
	cr.get("/setup/card")
	w, g := cr.answers()
	cr.post("/setup/card", url.Values{"word": {w}, "group": {g}})
	if cr.step.Hold() != nil {
		t.Fatal("first card not confirmed")
	}
	first := *cr.shown
	resets := 0
	reruns := 0
	cr.hooks.mu.Lock()
	cr.hooks.refuseFinish = func() error {
		if reruns > 0 {
			return nil
		}
		reruns++
		if err := cr.step.Again(func() error { resets++; return nil }); err != nil {
			return err
		}
		return ErrCardAgain
	}
	cr.hooks.connected = true
	cr.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
	cr.hooks.mu.Unlock()
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	cr.post("/setup/host", url.Values{}) // the last step's post runs the finish
	if cr.srv.setup.done() || reruns != 1 || resets != 1 {
		t.Fatalf("done %v, reruns %d, resets %d", cr.srv.setup.done(), reruns, resets)
	}
	page := html.UnescapeString(cr.get("/setup"))
	if !strings.Contains(page, cardAgain) || !strings.Contains(page, `href="/setup/card"`) {
		t.Fatalf("not the card step with the message: %s", page)
	}
	if strings.Contains(page, "Could not finish setup") {
		t.Fatal("the dead-end message")
	}
	cr.get("/setup/card")
	if cr.shown.RecoveryKey == first.RecoveryKey {
		t.Fatal("the same card shown again")
	}
	w, g = cr.answers()
	cr.post("/setup/card", url.Values{"word": {w}, "group": {g}})
	if cr.step.Hold() != nil || cr.made != 2 {
		t.Fatalf("new card: hold %v, provisions %d", cr.step.Hold(), cr.made)
	}
	if !strings.Contains(cr.get("/setup"), `action="/setup/recovery"`) {
		t.Fatal("the recovery step was not asked again")
	}
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	cr.srv.setup.maybeFinish()
	if !cr.srv.setup.done() || cr.hooks.finishes != 1 {
		t.Fatalf("done %v, finishes %d", cr.srv.setup.done(), cr.hooks.finishes)
	}
	if _, gsm := modem.Segments(cardAgain); !gsm {
		t.Fatalf("not GSM-7: %q", cardAgain)
	}
}
