package page

// REQ: NET-2, NET-4, KEY-7, STO-4

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

type fakeAlerts struct {
	st       Status
	resolved []uint64
	err      error
}

func (f *fakeAlerts) Status() Status { return f.st }
func (f *fakeAlerts) Resolve(id uint64) error {
	f.resolved = append(f.resolved, id)
	return f.err
}

type fakeCore struct {
	revoked bool
	sigs    [][]byte
	err     error
}

func (f *fakeCore) RevokeMsg(owner key.PublicKey) []byte {
	return append([]byte("revoke the core\x00"), owner.Encode()...)
}
func (f *fakeCore) Revoke(sig []byte) error {
	f.sigs = append(f.sigs, sig)
	if f.err == nil {
		f.revoked = true
	}
	return f.err
}
func (f *fakeCore) Revoked() bool { return f.revoked }

// stateRig is newRig's page with the enforcer's state wired in: two open
// alerts (a trip, sent; a paused channel, not), the core silent and the
// light red, and a core key.
func stateRig(t *testing.T) (*rig, *fakeAlerts, *fakeCore) {
	t.Helper()
	g := newRig(t)
	at := time.Date(2026, 11, 8, 20, 30, 0, 0, time.UTC)
	al := &fakeAlerts{st: Status{CoreDown: true, Red: true, Open: []Alert{
		{ID: 7, Text: "Enforcer: core touched a decoy or broke a limit, a known attack.", At: at, Count: 3, Sent: true},
		{ID: 9, Text: "Enforcer: the core's channel sent too much and is paused.", At: at, Count: 1, Fixed: true},
		{ID: 11, Text: "Enforcer: the core's log does not match the copy the enforcer keeps.", At: at, Count: 1, Revoke: true},
	}}}
	co := &fakeCore{}
	cfg := g.s.cfg
	cfg.Alerts, cfg.Core, cfg.Lock = al, co, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return g, al, co
}

// tapState draws action's challenge on target and taps it with a.
func (g *rig) tapState(a *authenticator, action, target string) (int, map[string]any) {
	g.t.Helper()
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": action, "target": target})
	c := answer(g.t, w)
	if w.Code != http.StatusOK {
		return w.Code, c
	}
	as := a.get(c["challenge"].(string))
	w = g.do(http.MethodPost, "/act", map[string]any{"id": c["id"], "action": action,
		"authenticator_data": as.AuthenticatorData, "client_data_json": as.ClientDataJSON, "signature": as.Signature})
	return w.Code, answer(g.t, w)
}

func (g *rig) homeHTML() string {
	g.t.Helper()
	w := g.do(http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		g.t.Fatalf("home: %d", w.Code)
	}
	return w.Body.String()
}

// #4750 (NET-2 Texts and calls, KRN-12 Silence): home shows every open
// alert with when it began, how often, and whether the core took its
// text; a silent core; and the light's colour. Each alert but a paused
// channel's has a clear; with no alerts wired, none of it shows.
func TestHomeShowsStatus(t *testing.T) {
	g, al, _ := stateRig(t)
	h := g.homeHTML()
	for _, want := range []string{
		"The light is red", "The core is down",
		"core touched a decoy or broke a limit", "Since Sun 8 Nov 2026 12:30 PST, 3 times.", "the core may not have sent it",
		"the core&#39;s channel sent too much and is paused", "Not texted: the core has not taken it.",
		`data-action="clear" data-target="7"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if strings.Contains(h, `data-target="9"`) {
		t.Error("a paused channel's alert has a clear")
	}
	// A forked log's card names the choice and leads to the revoke step
	// (UX on #5101); no other card does.
	if strings.Count(h, `href="#revoke"`) != 1 || !strings.Contains(h, `id="revoke"`) || !strings.Contains(h, "if you trust the core, clear this and keep it") {
		t.Error("the forked log's card does not name the choice to revoke the core's key")
	}
	al.st = Status{}
	h = g.homeHTML()
	if !strings.Contains(h, "The light is off") || !strings.Contains(h, "No open alerts.") || strings.Contains(h, "The core is down") {
		t.Errorf("home with nothing open:\n%s", h)
	}
	g = newRig(t)
	if h := g.homeHTML(); strings.Contains(h, "<h2>Alerts</h2>") || strings.Contains(h, "revoke-core") {
		t.Error("home shows state it was not given")
	}
}

// #4750: an alert clears only with the passkey's tap, and only an open
// one that a clear may close; each refusal leaves it open.
func TestClearAlert(t *testing.T) {
	g, al, _ := stateRig(t)
	if code, _ := g.tapState(newAuthenticator(t), ActClear, "7"); code != http.StatusForbidden || len(al.resolved) != 0 {
		t.Fatalf("a stranger's clear: %d %v", code, al.resolved)
	}
	for target, want := range map[string]int{"9": http.StatusConflict, "8": http.StatusNotFound, "x": http.StatusBadRequest, "": http.StatusBadRequest} {
		if code, _ := g.tapState(g.a, ActClear, target); code != want {
			t.Errorf("clear %q: %d, want %d", target, code, want)
		}
	}
	if code, res := g.tapState(g.a, ActClear, "7"); code != http.StatusOK || res["done"] != true || len(al.resolved) != 1 || al.resolved[0] != 7 {
		t.Fatalf("clear: %d %v %v", code, res, al.resolved)
	}
	al.err = errors.New("alert: journal full")
	if code, res := g.tapState(g.a, ActClear, "7"); code != http.StatusConflict || res["error"] != "alert: journal full" {
		t.Errorf("a failed clear: %d %v", code, res)
	}
	cfg := g.s.cfg
	cfg.Alerts, cfg.Lock = nil, nil
	g.s, _ = New(cfg)
	if code, _ := g.tapState(g.a, ActClear, "7"); code != http.StatusNotFound {
		t.Errorf("a clear with no alerts wired: %d", code)
	}
}

// #4751 (KEY-7, STO-4's stolen core): the page draws the revocation's
// challenge from the core's own message for the passkey in force, so the
// tap the daemon gets is the heads store's to check; a stranger's tap,
// a target, a second revocation and a page with no core are refused.
func TestRevokeCore(t *testing.T) {
	g, _, co := stateRig(t)
	h := g.homeHTML()
	if !strings.Contains(h, `data-action="revoke-core"`) {
		t.Fatal("home offers no revocation")
	}
	// It says what it does and no more (Potency on #5101): the channel
	// closes, network access stays, texts stop, and it is final.
	for _, want := range []string{"takes no message from the core over its channel", "network access stays as your rules set it",
		"texts stop too", "cannot be undone", "its texts to you stop, and this cannot be undone"} {
		if !strings.Contains(h, want) {
			t.Errorf("the revoke step lacks %q", want)
		}
	}
	if strings.Contains(h, "refuses everything") {
		t.Error("the revoke step claims the core is cut off")
	}
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActRevokeCore})
	if c := answer(t, w); w.Code != http.StatusOK || c["challenge"] != chal(co.RevokeMsg(g.a.Public())) {
		t.Fatalf("revoke challenge: %d %v", w.Code, c)
	}
	if code, _ := g.tapState(newAuthenticator(t), ActRevokeCore, ""); code != http.StatusForbidden || len(co.sigs) != 0 {
		t.Fatalf("a stranger's revocation: %d", code)
	}
	if code, _ := g.tapState(g.a, ActRevokeCore, "x"); code != http.StatusNotFound {
		t.Errorf("a revocation with a target: %d", code)
	}
	co.err = errors.New("revoked until the enforcer restarts, but not saved")
	if code, res := g.tapState(g.a, ActRevokeCore, ""); code != http.StatusConflict || res["error"] != co.err.Error() {
		t.Errorf("an unsaved revocation: %d %v", code, res)
	}
	co.err = nil
	if code, _ := g.tapState(g.a, ActRevokeCore, ""); code != http.StatusOK || !co.revoked {
		t.Fatalf("revoke: %d", code)
	}
	if !g.a.Public().Verify(co.RevokeMsg(g.a.Public()), co.sigs[len(co.sigs)-1]) {
		t.Error("the daemon was handed a signature that is not the owner's over the core's message")
	}
	if h := g.homeHTML(); !strings.Contains(h, "key is revoked") || strings.Contains(h, `data-action="revoke-core"`) || strings.Contains(h, `href="#revoke"`) {
		t.Error("home does not show the key revoked, or still offers the choice")
	}
	if code, _ := g.tapState(g.a, ActRevokeCore, ""); code != http.StatusConflict {
		t.Errorf("a second revocation: %d", code)
	}
	g = newRig(t)
	if code, _ := g.tapState(g.a, ActRevokeCore, ""); code != http.StatusNotFound {
		t.Errorf("a revocation with no core: %d", code)
	}
}

type fakeCaps struct {
	day          CapsDay
	saved        bool
	err          error
	fresh, cncl  int
	lastFreshNow int64
}

func (f *fakeCaps) Day() CapsDay { return f.day }
func (f *fakeCaps) Fresh(nowMS int64) (int64, bool, error) {
	f.fresh++
	f.lastFreshNow = nowMS
	if f.err != nil {
		return 0, false, f.err
	}
	f.day.DueMS = nowMS + 600_000
	return f.day.DueMS, f.saved, nil
}
func (f *fakeCaps) CancelFresh() (bool, error) {
	f.cncl++
	if f.err != nil {
		return false, f.err
	}
	f.day.DueMS = 0
	return f.saved, nil
}

// #5013 (NET-2 Byte caps, NET-4, D-255): an unreadable byte-cap day shows
// why every cap is spent and offers a fresh day after a tap; one waiting
// is listed under Waiting to apply with its cancel; a start being retried
// and a step the disk has not confirmed say so. Each step takes the
// passkey's tap, carries no target, and is drawn only when it applies.
func TestFreshDayPage(t *testing.T) {
	g := newRig(t)
	if h := g.homeHTML(); strings.Contains(h, "<h2>Byte caps</h2>") {
		t.Fatal("home shows byte caps it was not given")
	}
	if code, _ := g.tapState(g.a, ActFreshDay, ""); code != http.StatusNotFound {
		t.Errorf("a fresh day with no caps wired: %d", code)
	}
	ca := &fakeCaps{saved: true}
	cfg := g.s.cfg
	cfg.Caps, cfg.Lock = ca, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	if h := g.homeHTML(); strings.Contains(h, "<h2>Byte caps</h2>") {
		t.Fatal("home shows a day that reads back as spent")
	}
	if code, _ := g.tapState(g.a, ActFreshDay, ""); code != http.StatusConflict || ca.fresh != 0 {
		t.Errorf("a fresh day for a day that reads back: %d", code)
	}
	ca.day.Spent = true
	h := g.homeHTML()
	if !strings.Contains(h, "could not read its record of today's bytes") || !strings.Contains(h, "it waits 10 minutes") ||
		!strings.Contains(h, `data-action="fresh-day"`) || strings.Contains(h, `data-action="cancel-fresh"`) {
		t.Fatalf("home does not show the spent day and its step:\n%s", h)
	}
	for _, c := range []struct {
		action, target string
		want           int
	}{{ActFreshDay, "x", http.StatusNotFound}, {ActCancelFresh, "", http.StatusNotFound}} {
		if code, _ := g.tapState(g.a, c.action, c.target); code != c.want {
			t.Errorf("%s %q: %d, want %d", c.action, c.target, code, c.want)
		}
	}
	if code, _ := g.tapState(newAuthenticator(t), ActFreshDay, ""); code != http.StatusForbidden || ca.fresh != 0 {
		t.Fatalf("a stranger's fresh day: %d", code)
	}
	code, res := g.tapState(g.a, ActFreshDay, "")
	if code != http.StatusOK || res["done"] != true || res["saved"] != true || res["due"] == nil || ca.lastFreshNow != g.s.nowMS() {
		t.Fatalf("fresh day: %d %v", code, res)
	}
	h = g.homeHTML()
	waiting := h[strings.Index(h, "<h2>Waiting to apply</h2>"):]
	if !strings.Contains(waiting, "A fresh byte-cap day starts at") || !strings.Contains(waiting, `data-action="cancel-fresh"`) ||
		strings.Contains(waiting, "<p>Nothing.</p>") || strings.Contains(h, `data-action="fresh-day"`) {
		t.Fatalf("the waiting fresh day is not under Waiting to apply:\n%s", h)
	}
	if code, _ := g.tapState(g.a, ActFreshDay, ""); code != http.StatusConflict {
		t.Errorf("a second fresh day: %d", code)
	}
	ca.saved = false
	if code, res := g.tapState(g.a, ActCancelFresh, ""); code != http.StatusOK || res["saved"] != false {
		t.Fatalf("a cancel the disk has not confirmed: %d %v", code, res)
	}
	ca.day.Unsaved = true
	if h := g.homeHTML(); !strings.Contains(h, "the disk has not confirmed it yet") {
		t.Error("home does not say the step is not confirmed")
	}
	ca.day = CapsDay{Spent: true, Starting: true, Retrying: true}
	h = g.homeHTML()
	if !strings.Contains(h, "could not be saved. The enforcer tries again every second") || strings.Contains(h, `data-action="fresh-day"`) {
		t.Errorf("home does not say the start is retried:\n%s", h)
	}
	for _, action := range []string{ActFreshDay, ActCancelFresh} {
		if code, res := g.tapState(g.a, action, ""); code != http.StatusConflict || !strings.Contains(res["error"].(string), "starting") {
			t.Errorf("%s while starting: %d %v", action, code, res)
		}
	}
	ca.day.Retrying = false
	if h := g.homeHTML(); !strings.Contains(h, "The enforcer restarts to take it up") {
		t.Error("home does not say the saved fresh day is being taken up")
	}
	ca.day, ca.err = CapsDay{Spent: true, DueMS: 1}, errors.New("byte caps: no")
	if code, res := g.tapState(g.a, ActCancelFresh, ""); code != http.StatusConflict || res["error"] != "byte caps: no" {
		t.Errorf("a refused cancel: %d %v", code, res)
	}
}
