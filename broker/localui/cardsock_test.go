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
	c := &card.Card{WiFiName: "AgentOS-CANARY", WiFiPassword: "canary-wifi", SetupSecret: "canary-secret",
		SetupCode: "canary-code", VaultPassphrase: "canary pass phrase", GridSeed: []byte{1, 2, 3}, RecoveryKey: "CANA-RY00"}
	f.set("/card/provision", 200, map[string]any{"ok": true})
	if err := u.ProvisionCard(ctx, c); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(f.body("/card/provision"), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"wifi_name": c.WiFiName, "wifi_password": c.WiFiPassword, "setup_secret": c.SetupSecret,
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
	box := CardBox(u, change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")},
		&change.MemStore{}, void)
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
	vr.step, err = firstboot.NewCardStep(&change.MemStore{}, card.DisplayConfig{
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

// Brief test 4, the page's side: CardFinish sends no report while the
// card is held, so agentosd's finish refuses (card pending); once the card
// is confirmed it reports, then finishes. A refused report stops the
// finish.
func TestCardFinishReportsTheConfirmedCard(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	reported, refuse := false, false
	ops := InProcess{
		localapi.OpSetupCard: func(_ context.Context, _ sockets.Peer, raw json.RawMessage) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, localapi.OpSetupCard)
			var c localapi.SetupCard
			if json.Unmarshal(raw, &c) != nil || !c.Confirmed || refuse {
				return nil, sockets.Code(localapi.ErrBadArgs)
			}
			reported = true
			return struct{}{}, nil
		},
		localapi.OpSetupFinish: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, localapi.OpSetupFinish)
			if !reported {
				return nil, sockets.Code(localapi.ErrCardPending)
			}
			return struct{}{}, nil
		},
	}
	hold := &heldUntil{held: true}
	f := CardFinish{AgentosdSetup: AgentosdSetup{Owner: ops}, Card: hold}
	if err := f.Finish(ownerNum); err == nil || fmt.Sprint(calls) != "["+localapi.OpSetupFinish+"]" {
		t.Fatalf("held card: %v, calls %v", err, calls)
	}
	hold.held, refuse, calls = false, true, nil
	if err := f.Finish(ownerNum); err == nil || fmt.Sprint(calls) != "["+localapi.OpSetupCard+"]" {
		t.Fatalf("refused report: %v, calls %v", err, calls)
	}
	refuse, calls = false, nil
	if err := f.Finish(ownerNum); err != nil || fmt.Sprint(calls) != "["+localapi.OpSetupCard+" "+localapi.OpSetupFinish+"]" {
		t.Fatalf("confirmed card: %v, calls %v", err, calls)
	}
}
