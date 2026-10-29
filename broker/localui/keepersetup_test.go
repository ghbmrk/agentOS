package localui

// REQ: HW-1, STO-2, F10

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/firstboot"
)

// fakeKeeper is the keeper's hand-off: it records each request and answers
// word, or err.
type fakeKeeper struct {
	mu    sync.Mutex
	word  string
	err   error
	calls []keeperCall
	// before runs at each call, under no lock (the order checks).
	before func()
}

type keeperCall struct{ pass, rec, fp string }

func (k *fakeKeeper) Hand(_ context.Context, c *card.Card, fp string) (string, error) {
	if k.before != nil {
		k.before()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, keeperCall{c.VaultPassphrase, c.RecoveryKey, fp})
	return k.word, k.err
}

func (k *fakeKeeper) set(word string, err error) {
	k.mu.Lock()
	k.word, k.err = word, err
	k.mu.Unlock()
}

// keeperListener serves the hand-off socket as agentos-keeper-setup@ does:
// it reads one request to its end and answers with answer(request).
func keeperListener(t *testing.T, answer func([]byte) string) (string, <-chan []byte) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ks") // a short path: sockets are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "setup.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(io.LimitReader(c, 16<<10))
			got <- b
			if w := answer(b); w != "" {
				io.WriteString(c, w+"\n")
			}
			c.Close()
		}
	}()
	return path, got
}

// The client speaks agentos-enroll -take-factors' request: one JSON object
// with exactly v, passphrase, recovery_key and fingerprint, the card's text
// as printed, the write half closed, and the one word back. A peer that is
// not the keeper's uid is sent nothing; no answer is an error, never a word.
// It catches a request the keeper's strict decoder refuses, and factors
// sent to a socket a lower user planted.
func TestKeeperSetupSpeaksTakeFactors(t *testing.T) {
	c := &card.Card{VaultPassphrase: "canary pass phrase", RecoveryKey: "CANA-RY00-KEY0"}
	fp := card.Fingerprint(testAuthority())
	path, got := keeperListener(t, func([]byte) string { return KeeperKept })
	word, err := KeeperSetup{Socket: path, UID: os.Getuid()}.Hand(context.Background(), c, fp)
	if err != nil || word != KeeperKept {
		t.Fatalf("word %q, err %v", word, err)
	}
	req := <-got
	dec := json.NewDecoder(strings.NewReader(string(req)))
	dec.DisallowUnknownFields()
	var r struct {
		V           int    `json:"v"`
		Passphrase  string `json:"passphrase"`
		RecoveryKey string `json:"recovery_key"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := dec.Decode(&r); err != nil || dec.More() || strings.Contains(string(req), `\`) {
		t.Fatalf("request %q: %v", req, err)
	}
	if r.V != 1 || r.Passphrase != c.VaultPassphrase || r.RecoveryKey != c.RecoveryKey || r.Fingerprint != fp {
		t.Fatalf("request %+v", r)
	}

	if _, err := (KeeperSetup{Socket: path, UID: os.Getuid() + 1}).Hand(context.Background(), c, fp); err == nil {
		t.Fatal("spoke to a socket of another uid")
	}
	if b := <-got; len(b) != 0 {
		t.Fatalf("sent %d bytes to a socket of another uid", len(b))
	}

	silent, _ := keeperListener(t, func([]byte) string { return "" })
	if w, err := (KeeperSetup{Socket: silent, UID: os.Getuid()}).Hand(context.Background(), c, fp); err == nil || w != "" {
		t.Fatalf("no answer read as %q", w)
	}
	if _, err := (KeeperSetup{Socket: filepath.Join(t.TempDir(), "none.sock")}).Hand(context.Background(), c, fp); err == nil {
		t.Fatal("no socket read as an answer")
	}
	for _, bad := range []*card.Card{
		{VaultPassphrase: `a "quoted" phrase`, RecoveryKey: c.RecoveryKey},
		{VaultPassphrase: c.VaultPassphrase, RecoveryKey: `CANA\RY`},
		{VaultPassphrase: "", RecoveryKey: c.RecoveryKey},
	} {
		if _, err := (KeeperSetup{Socket: path, UID: os.Getuid()}).Hand(context.Background(), bad, fp); err == nil {
			t.Fatal("sent a card text the keeper's request cannot hold")
		}
	}
}

// keeperRig is a setup page whose card step is CardBox's, with a fake
// keeper and the fake vault process.
type keeperRig struct {
	*cardRig
	keeper *fakeKeeper
	vault  *fakeUnlock
	latch  *change.MemStore
}

func newKeeperRig(t *testing.T) *keeperRig {
	t.Helper()
	f, u := newFakeUnlock(t)
	kr := &keeperRig{cardRig: &cardRig{rig: newRig(t)}, keeper: &fakeKeeper{word: KeeperOK}, vault: f, latch: &change.MemStore{}}
	f.set("/card/provision", 200, map[string]any{"ok": true})
	box := CardBox(u, kr.keeper, change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}, kr.latch, &CodesVoid{}, testAuthority())
	cfg := box.Card
	cfg.Generate = func(rd io.Reader) (*card.Card, error) {
		c, err := card.Generate(rd)
		if err == nil {
			cp := *c
			kr.shown = &cp
		}
		return c, err
	}
	var err error
	kr.step, err = firstboot.NewCardStep(kr.latch, cfg)
	if err != nil {
		t.Fatal(err)
	}
	kr.owned = kr.step
	kr.srv = kr.open(&MemStore{})
	return kr
}

func (kr *keeperRig) confirm() *http.Response {
	kr.t.Helper()
	w, g := kr.answers()
	return kr.do("POST", "/setup/card", url.Values{"word": {w}, "group": {g}}).Result()
}

func (kr *keeperRig) latched() bool {
	b, _ := kr.latch.Load()
	return strings.Contains(string(b), `"card_confirmed":true`)
}

// REQ: HW-1, STO-2
//
// OWN-card-flow decision 9: the confirm calls the keeper first, with the
// shown card's passphrase and recovery key and the fingerprint it printed.
// A keeper refusal makes no vault call and does not latch; ok followed by a
// vault failure keeps the card, and the retry hands the same card again,
// then provisions and latches. It catches a latch without a hand-off.
func TestConfirmHandsFactorsBeforeVault(t *testing.T) {
	kr := newKeeperRig(t)
	kr.toCard()
	kr.get("/setup/card")
	kr.keeper.before = func() {
		if kr.vault.body("/card/provision") != nil {
			t.Error("the vault was provisioned before the keeper had the card")
		}
	}
	kr.keeper.set(KeeperTaken, nil)
	if res := kr.confirm(); res.StatusCode != http.StatusSeeOther || kr.latched() || kr.step.Hold() == nil {
		t.Fatalf("a refused hand-off: %d, latched %v", res.StatusCode, kr.latched())
	}
	if kr.vault.body("/card/provision") != nil {
		t.Fatal("a keeper refusal reached the vault")
	}
	want := keeperCall{kr.shown.VaultPassphrase, kr.shown.RecoveryKey, card.Fingerprint(testAuthority())}
	if len(kr.keeper.calls) != 1 || kr.keeper.calls[0] != want {
		t.Fatalf("keeper calls %d: not the shown card's factors and fingerprint", len(kr.keeper.calls))
	}

	kr.keeper.set(KeeperOK, nil)
	kr.vault.set("/card/provision", http.StatusInternalServerError, map[string]any{"error": "canary vault failure"})
	kr.get("/setup") // the refusal's line
	if res := kr.confirm(); res.StatusCode == http.StatusSeeOther || kr.latched() {
		t.Fatalf("a vault failure: %d, latched %v", res.StatusCode, kr.latched())
	}
	kr.keeper.before = nil
	kr.vault.set("/card/provision", 200, map[string]any{"ok": true})
	if res := kr.confirm(); res.StatusCode != http.StatusSeeOther || !kr.latched() || kr.step.Hold() != nil {
		t.Fatalf("the retry: %d, latched %v", res.StatusCode, kr.latched())
	}
	if len(kr.keeper.calls) != 3 || kr.keeper.calls[1] != want || kr.keeper.calls[2] != want {
		t.Fatalf("keeper calls %d: the retry did not hand the same card", len(kr.keeper.calls))
	}
}

// REQ: HW-1
//
// OWN-card-flow decisions 8 and 10: kept latches, makes no vault call and
// shows the keep-that-card line; taken, authority, bad, an unknown word and
// an unreachable keeper each hold with their fixed line, keep the card, and
// show no raw error text. It catches a stuck box after a crash between the
// hand-off and the latch, and raw error text on the page.
func TestConfirmKeptLatchesWithTheKeepLine(t *testing.T) {
	for _, tc := range []struct {
		word string
		err  error
		line string
	}{
		{KeeperTaken, nil, keeperTakenLine},
		{KeeperAuthority, nil, firstboot.ErrNoAuthority.Error()},
		{KeeperBad, nil, keeperBadLine},
		{"canary-unknown-word", nil, keeperUnreachableLine},
		{"", errKeeperUnreachable, keeperUnreachableLine},
	} {
		kr := newKeeperRig(t)
		kr.toCard()
		kr.get("/setup/card")
		kr.keeper.set(tc.word, tc.err)
		res := kr.confirm()
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/setup" || kr.latched() || kr.step.Hold() == nil {
			t.Fatalf("%q: %d %q, latched %v", tc.word, res.StatusCode, res.Header.Get("Location"), kr.latched())
		}
		page := html.UnescapeString(kr.get("/setup"))
		if !strings.Contains(page, tc.line) || strings.Contains(page, "canary") || strings.Contains(page, "localui:") {
			t.Fatalf("%q: the setup page does not say the fixed line alone:\n%s", tc.word, page)
		}
		if strings.Contains(html.UnescapeString(kr.get("/setup")), tc.line) {
			t.Fatalf("%q: the line stayed after it was shown", tc.word)
		}
		if p := kr.get("/setup/card"); !strings.Contains(p, kr.shown.VaultPassphrase) {
			t.Fatalf("%q: the card was not kept for a retry", tc.word)
		}
		if kr.vault.body("/card/provision") != nil {
			t.Fatalf("%q: a refusal reached the vault", tc.word)
		}
	}

	kr := newKeeperRig(t)
	kr.toCard()
	kr.get("/setup/card")
	kr.keeper.set(KeeperKept, nil)
	res := kr.confirm()
	if res.StatusCode != http.StatusSeeOther || !kr.latched() || kr.step.Hold() != nil {
		t.Fatalf("kept: %d, latched %v, hold %v", res.StatusCode, kr.latched(), kr.step.Hold())
	}
	if kr.vault.body("/card/provision") != nil {
		t.Fatal("kept provisioned the vault with a card the owner throws away")
	}
	if page := html.UnescapeString(kr.get("/setup")); !strings.Contains(page, string(firstboot.ErrKept)) {
		t.Fatalf("kept: no keep-that-card line:\n%s", page)
	}
	if rec := kr.do("GET", "/setup/card", nil); rec.Code == http.StatusOK || kr.cardText(rec.Body.String()) {
		t.Fatalf("kept: the thrown-away card is still shown: %d", rec.Code)
	}
}
