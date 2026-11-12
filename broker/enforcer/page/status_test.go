package page

// REQ: NET-2, NET-4, KEY-7, STO-4, KRN-12

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
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
	revoked, unsaved bool
	sigs             [][]byte
	err              error
}

func (f *fakeCore) RevokeMsg(owner key.PublicKey) []byte {
	return append([]byte("revoke the core\x00"), owner.Encode()...)
}
func (f *fakeCore) Revoke(sig []byte) error {
	f.sigs = append(f.sigs, sig)
	if f.err == nil {
		f.revoked, f.unsaved = true, false
	}
	return f.err
}
func (f *fakeCore) Revoked() (bool, bool) { return f.revoked, !f.unsaved }

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
	if strings.Contains(h, "No core is set up") || !strings.Contains(h, `<details id="revoke" open>`) {
		t.Error("a forked log does not open the revoke step, or a pinned core reads as none")
	}
	// #5106 item 3: with nothing open, home has no Alerts section, no
	// light line and the revoke step closed; with no core pinned, a
	// silent core is not "down" but has its own words, once.
	al.st = Status{}
	h = g.homeHTML()
	for _, gone := range []string{"<h2>Alerts</h2>", "The light is", "No open alerts", "The core is down", "No core is set up", "<details id=\"revoke\" open>"} {
		if strings.Contains(h, gone) {
			t.Errorf("home with nothing open shows %q", gone)
		}
	}
	if !strings.Contains(h, `<details id="revoke"><summary>Revoke the core's key</summary>`) {
		t.Error("the revoke step is not behind a closed details")
	}
	al.st = Status{CoreDown: true}
	cfg := g.s.cfg
	cfg.Core, cfg.Lock = nil, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	h = g.homeHTML()
	if strings.Contains(h, "<h2>Alerts</h2>") || strings.Contains(h, "The core is down") || strings.Count(h, "No core is set up, so the enforcer's texts cannot reach your phone") != 1 {
		t.Errorf("home with no core pinned:\n%s", h)
	}
	al.st.Red = true
	if h = g.homeHTML(); !strings.Contains(h, "<h2>Alerts</h2>") || !strings.Contains(h, "The light is red") || strings.Contains(h, "The core is down") {
		t.Error("a red light with no core pinned is not shown alone")
	}
	g = newRig(t)
	if h := g.homeHTML(); strings.Contains(h, "<h2>Alerts</h2>") || strings.Contains(h, "revoke-core") || strings.Contains(h, "No core is set up") {
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
	// #5106 item 1: a revocation in force but not saved is a third state
	// on home, never "live" and never "revoked", and is offered again.
	co.revoked, co.unsaved = true, true
	h = g.homeHTML()
	if !strings.Contains(h, "revoked only until the enforcer restarts: the revocation was not saved") ||
		!strings.Contains(h, `data-action="revoke-core"`) || strings.Contains(h, "If the core box was stolen") ||
		strings.Contains(h, "key is revoked: the enforcer takes no message") || strings.Contains(h, `href="#revoke"`) {
		t.Errorf("home with an unsaved revocation:\n%s", h)
	}
	co.err = nil
	if code, _ := g.tapState(g.a, ActRevokeCore, ""); code != http.StatusOK || !co.revoked || co.unsaved {
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
	// #5445 item 4: a table the last load could not read holds every cap
	// spent, with a line of its own and no button: it clears by itself.
	ca.day.Unread = true
	if h := g.homeHTML(); !strings.Contains(h, "could not read the firewall's count of today's bytes") || strings.Contains(h, `data-action="fresh-day"`) || strings.Contains(h, "nor its own record") {
		t.Errorf("home does not say the caps are held while the table is unread:\n%s", h)
	}
	ca.day.Unread = false
	if h := g.homeHTML(); strings.Contains(h, "could not read the firewall's count") {
		t.Error("home still says the table is unread")
	}
	// #5491 item 2: the day and the table both unread are one card under
	// one heading, with the step for the day.
	ca.day.Unread, ca.day.Spent = true, true
	if h := g.homeHTML(); strings.Count(h, "<h2>Byte caps</h2>") != 1 || strings.Count(h, `class="pending warn"`) != 1 ||
		!strings.Contains(h, "nor its own record of them") || !strings.Contains(h, `data-action="fresh-day"`) ||
		strings.Count(h, "could not read its record") != 0 {
		// #5504 item 1: the record's own sentence is not said a second time.
		t.Errorf("home does not show one card for the day and the table both unread:\n%s", h)
	} else if strings.Count(h, "<p>")+strings.Count(h, "<p ") != strings.Count(h, "</p>") {
		t.Errorf("home's paragraphs do not balance with the day and the table both unread (%d open, %d close):\n%s", strings.Count(h, "<p>")+strings.Count(h, "<p "), strings.Count(h, "</p>"), h)
	}
	ca.day.Unread = false
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

type fakeResolver struct{ stop ResolverStop }

func (f *fakeResolver) Stopped() ResolverStop { return f.stop }

// #5164 R1 (NET-2 Segments, ASSUMPTIONS ENF-l-11 and ENF-l-21 at the
// daemon): a stopped resolver shows on home with each stray address and
// its interface, any other setup failure, and a policy it cannot serve;
// with none of those, the refused load that keeps it stopped; a running
// one, or none wired, shows nothing. Text the core could have
// chosen is shown in printable ASCII.
func TestHomeShowsStoppedResolver(t *testing.T) {
	g := newRig(t)
	res := &fakeResolver{}
	cfg := g.s.cfg
	cfg.Resolver = res
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	if h := g.homeHTML(); strings.Contains(h, "Names and addresses") || strings.Contains(h, "stopped answering") {
		t.Fatal("home shows a running resolver as stopped")
	}
	res.stop = ResolverStop{Stopped: true, Load: LoadFirewall, Strays: []Stray{
		{Iface: "own0", Addr: netip.MustParsePrefix("10.99.0.1/24"), Nets: "10.10.0.0/24 and fd00:10::/64"},
		{Iface: "dev0", Addr: netip.MustParsePrefix("fd00:99::7/64"), Nets: "10.20.0.0/24"},
		// An interface name past ASCII is quoted and escaped (#5307).
		{Iface: "own\u202e0", Addr: netip.MustParsePrefix("10.98.0.1/24"), Nets: "10.10.0.0/24"},
	}}
	h := g.homeHTML()
	for _, want := range []string{
		"<h2>Names and addresses</h2>", "stopped answering name lookups and handing out addresses on every home network",
		"Interface own0 holds the address 10.99.0.1/24, outside its network 10.10.0.0/24 and fd00:10::/64.",
		"Interface dev0 holds the address fd00:99::7/64, outside its network 10.20.0.0/24.",
		"Interface &#34;own\\u202e0&#34; holds the address 10.98.0.1/24, outside its network 10.10.0.0/24.",
		"within 10 seconds of the last such address being removed",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("home with stray addresses lacks %q", want)
		}
	}
	if strings.Contains(h, "could not turn off") || strings.Contains(h, "has no words for") || strings.Contains(h, "The policy in force") || strings.Contains(h, "The firewall refused") || strings.Contains(h, "with its next load of your rules") || strings.ContainsRune(h, '\u202e') {
		t.Error("home shows a cause the resolver does not have, a refused load beside a listed cause, or an override")
	}
	// With no listed cause, the step that refused the load keeping it
	// stopped, in its own words and never the error's text (#5243 L3
	// item 1, #5164 R5 d, #5307): a policy that did not compile is no
	// refusal by the firewall, and an untyped failure claims neither.
	for step, want := range map[LoadStep]string{
		LoadFirewall:     "<p>The firewall refused the enforcer&#39;s last load of your rules; the enforcer&#39;s log has the detail. Names and addresses come back only with a load it takes. The enforcer keeps trying.</p>",
		LoadCompile:      "<p>The enforcer could not make firewall rules of the policy in force, so it loaded nothing; its log has the detail. The firewall keeps the rules it had, and names and addresses come back only with a policy it can load. The enforcer keeps trying.</p>",
		LoadUntyped:      "<p>The enforcer&#39;s last load of your rules failed; its log has the detail. Names and addresses come back only with a load that works. The enforcer keeps trying.</p>",
		LoadFirewall + 1: "<p>The enforcer&#39;s last load of your rules failed; its log has the detail.",
	} {
		res.stop = ResolverStop{Stopped: true, Load: step}
		if h = g.homeHTML(); !strings.Contains(h, want) || strings.Count(h, "keeps trying") != 1 || strings.Contains(h, "with its next load of your rules") {
			t.Errorf("load refused at step %d is not in its own words:\n%s", step, h)
		}
	}
	// Stopped with no cause recorded (between a check that passes and
	// the next load): the card still says when it ends (Lens on #5243).
	res.stop = ResolverStop{Stopped: true}
	if h = g.homeHTML(); !strings.Contains(h, "The enforcer serves names and addresses again with its next load of your rules, within 10 seconds.") || strings.Contains(h, "a few seconds") {
		t.Errorf("a stop with no cause gives no reason:\n%s", h)
	}
	res.stop = ResolverStop{Strays: []Stray{{Iface: "own0", Addr: netip.MustParsePrefix("10.99.0.1/24"), Nets: "10.10.0.0/24"}}, Load: LoadUntyped}
	if h = g.homeHTML(); strings.Contains(h, "Names and addresses") {
		t.Error("home shows a resolver whose instances run as stopped")
	}
	// Instances that run but keep exiting show, each in its words with
	// its count, and not as a stop (#5164 R5 b); with the resolver
	// stopped, the stop alone shows.
	res.stop = ResolverStop{Restarting: []Restart{{Part: PartListed, Iface: "vlan10\u202e", Exits: 3}, {Part: PartPeople, Exits: 1}, {Part: PartDHCP, Exits: 2}, {Exits: 4}}}
	h = g.homeHTML()
	for _, want := range []string{
		"<h2>Names and addresses</h2>",
		"<p>The enforcer&#39;s name answers on interface &#34;vlan10\\u202e&#34;, which only a listed name gets, stopped or could not start 3 times in a row and has not stayed up since.",
		"<p>The enforcer&#39;s name answers on the Owner, Household and Guests networks stopped or could not start and has not stayed up since.",
		"<p>The enforcer&#39;s address service, which hands out addresses on the home networks, stopped or could not start 2 times in a row",
		"<p>Part of the enforcer&#39;s name and address service stopped or could not start 4 times in a row",
		"up to 30 seconds",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("home with restarting instances lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "stopped answering name lookups") || strings.ContainsRune(h, '\u202e') {
		t.Error("restarting instances show as a stopped resolver, or carry an override")
	}
	res.stop.Stopped = true
	if h = g.homeHTML(); strings.Contains(h, "stopped or could not start") || !strings.Contains(h, "stopped answering name lookups") {
		t.Error("a stopped resolver shows restarts beside the stop")
	}
	// A lease file the last load could not read shows in one line,
	// whether or not the resolver runs (#5394 item 3), and only then.
	const unseeded = "<p>When the enforcer last loaded your rules, it could not read its list of the addresses it had handed out, so a device on the Owner, Household or Guests network may reach nothing until it next asks for its address, which every device does within 6 hours. The enforcer's log has the detail.</p>"
	if strings.Contains(h, "Addresses handed out") {
		t.Error("home shows an unread lease file the load read")
	}
	for _, stopped := range []bool{false, true} {
		res.stop = ResolverStop{Stopped: stopped, Unseeded: true}
		if h = g.homeHTML(); !strings.Contains(h, "<h2>Addresses handed out</h2>") || strings.Count(h, unseeded) != 1 {
			t.Errorf("home (stopped %v) does not show an unread lease file in its words:\n%s", stopped, h)
		}
	}
	// A setting that did not take shows in plain words, never the raw
	// error, and an error said twice shows once (#5280).
	ra := Unset{Kind: UnsetSetting, Iface: "own0", Setting: RouterAds}
	res.stop = ResolverStop{Stopped: true, Unset: []Unset{ra, ra}}
	h = g.homeHTML()
	if !strings.Contains(h, "<p>The enforcer could not turn off router advertisements on interface own0, so a device on that network could set a route or address the enforcer did not check. It tries again every 10 seconds.</p>") || strings.Contains(h, "Interface own0 holds") {
		t.Errorf("a setting that did not take is not shown alone:\n%s", h)
	}
	if strings.Count(h, "router advertisements") != 1 || strings.Contains(h, "/proc/sys") || strings.Contains(h, "&#34;") || strings.Contains(h, "still applies") {
		t.Errorf("home shows the raw error, or one error twice:\n%s", h)
	}
	// A policy the resolver cannot serve, by its typed cause, with any
	// name in printable ASCII; a refused load is not shown beside it.
	const still = "<p>The policy still applies; names and addresses come back with the next policy the enforcer can serve.</p>"
	for cause, want := range map[PolicyCause]string{
		{Kind: PolicyVLAN, Name: "plug", WiFi: "vlan109"}:      "<p>The policy in force puts device plug on Wi-Fi network vlan109, and the enforcer&#39;s setup serves no names or addresses there.</p>",
		{Kind: PolicyVLAN, Name: "pl\u202eug", WiFi: "vlan 9"}: "<p>The policy in force puts device &#34;pl\\u202eug&#34; on Wi-Fi network &#34;vlan 9&#34;, and the enforcer&#39;s setup serves no names or addresses there.</p>",
		{Kind: PolicyName, Name: "gro.live\u202e"}:             "<p>The policy in force lists &#34;gro.live\\u202e&#34;, which is not a name the enforcer can look up.</p>",
		{Kind: PolicyUntyped, Name: "x\u202e"}:                 "<p>The policy in force names something the enforcer cannot serve; the enforcer&#39;s log has the detail.</p>",
		{Kind: PolicySetup, Name: "no upstream\u202e"}:         "<p>The network setup could not be applied: the enforcer&#39;s own setup of its names and addresses is not one it can serve. The enforcer&#39;s log has the detail.</p>",
		{Kind: PolicySetup + 1, Name: "x"}:                     "<p>The policy in force names something the enforcer cannot serve; the enforcer&#39;s log has the detail.</p>",
	} {
		res.stop = ResolverStop{Stopped: true, Policy: []PolicyCause{cause}, Load: LoadFirewall}
		h = g.homeHTML()
		if !strings.Contains(h, want+"\n"+still) || strings.Contains(h, "The firewall refused") || strings.Contains(h, "with its next load of your rules") {
			t.Errorf("a policy the resolver cannot serve (%+v) is not in its words:\n%s", cause, h)
		}
		if strings.ContainsRune(h, '\u202e') {
			t.Error("home carries a right-to-left override from the policy")
		}
	}
	// Every reason shows, each once, in the order given, and the policy
	// still applies is said once after them (#5405): a setup fault beside
	// two devices and two names, and an untyped reason given twice. The
	// setup fault has its own words, apart from the untyped one's (#5431).
	res.stop = ResolverStop{Stopped: true, Policy: []PolicyCause{
		{Kind: PolicySetup}, {Kind: PolicyUntyped}, {Kind: PolicyVLAN, Name: "plug", WiFi: "vlan109"}, {Kind: PolicyVLAN, Name: "lamp", WiFi: "vlan110"},
		{Kind: PolicyName, Name: "Abc.example"}, {Kind: PolicyName, Name: "Zed.example"}, {Kind: PolicyUntyped}, {Kind: PolicySetup},
	}}
	h = g.homeHTML()
	want := "<p>The network setup could not be applied: the enforcer&#39;s own setup of its names and addresses is not one it can serve. The enforcer&#39;s log has the detail.</p>\n" +
		"<p>The policy in force names something the enforcer cannot serve; the enforcer&#39;s log has the detail.</p>\n" +
		"<p>The policy in force puts device plug on Wi-Fi network vlan109, and the enforcer&#39;s setup serves no names or addresses there.</p>\n" +
		"<p>The policy in force puts device lamp on Wi-Fi network vlan110, and the enforcer&#39;s setup serves no names or addresses there.</p>\n" +
		"<p>The policy in force lists &#34;Abc.example&#34;, which is not a name the enforcer can look up.</p>\n" +
		"<p>The policy in force lists &#34;Zed.example&#34;, which is not a name the enforcer can look up.</p>\n" + still
	if !strings.Contains(h, want) || strings.Count(h, "cannot serve;") != 1 || strings.Count(h, "could not be applied") != 1 || strings.Count(h, "still applies") != 1 || strings.Contains(h, "more reason") {
		t.Errorf("home does not list every reason the policy cannot be served, each once:\n%s", h)
	}
	// A name longer than PolicyNameMax shows its first PolicyNameMax
	// bytes, cut at a character's start, then "...", so each line is
	// bounded whatever the name (#5431); one of PolicyNameMax shows whole.
	whole := strings.Repeat("a", PolicyNameMax-1) + "z"
	long := strings.Repeat("a", PolicyNameMax-1) + "\u00e9" + strings.Repeat("b", 1<<16)
	res.stop = ResolverStop{Stopped: true, Policy: []PolicyCause{{Kind: PolicyName, Name: whole}, {Kind: PolicyName, Name: long}, {Kind: PolicyVLAN, Name: long, WiFi: long}}}
	h = g.homeHTML()
	if !strings.Contains(h, "&#34;"+whole+"&#34;") || !strings.Contains(h, "&#34;"+strings.Repeat("a", PolicyNameMax-1)+"...&#34;, which") ||
		!strings.Contains(h, "device "+strings.Repeat("a", PolicyNameMax-1)+"... on Wi-Fi network "+strings.Repeat("a", PolicyNameMax-1)+"..., and") || strings.Contains(h, "bbb") || len(h) > 16<<10 {
		t.Errorf("a long name is not cut at PolicyNameMax (%d bytes):\n%.3000s", len(h), h)
	}
	if got := clip(strings.Repeat("\x80", 2*PolicyNameMax)); got != "..." {
		t.Errorf("a name of continuation bytes clips to %.40q", got)
	}
	// More reasons than PolicyShown (#5431): the first PolicyShown show,
	// each once, then one line with the exact count of the rest, each
	// counted once; the page stays bounded however many the policy holds.
	for _, tc := range []struct {
		names int
		more  string
	}{
		{PolicyShown, ""},
		{PolicyShown + 1, "<p>There is 1 more reason the policy in force cannot be served. This page and the enforcer&#39;s log name only the first " + strconv.Itoa(PolicyShown) + "; the rest are named once those are fixed.</p>\n" + still},
		{PolicyShown + 37, "<p>There are 37 more reasons the policy in force cannot be served. This page and the enforcer&#39;s log name only the first " + strconv.Itoa(PolicyShown) + "; the rest are named once those are fixed.</p>\n" + still},
		{5000, "<p>There are " + strconv.Itoa(5000-PolicyShown) + " more reasons the policy in force cannot be served. This page and the enforcer&#39;s log name only the first " + strconv.Itoa(PolicyShown) + "; the rest are named once those are fixed.</p>\n" + still},
	} {
		var causes []PolicyCause
		for i := range tc.names {
			c := PolicyCause{Kind: PolicyName, Name: "N" + strconv.Itoa(i) + ".example"}
			causes = append(causes, c, c) // each given twice counts once
		}
		res.stop = ResolverStop{Stopped: true, Policy: causes}
		h = g.homeHTML()
		listed := strings.Count(h, "which is not a name the enforcer can look up")
		if listed != PolicyShown || !strings.Contains(h, "&#34;N0.example&#34;") || !strings.Contains(h, "&#34;N"+strconv.Itoa(PolicyShown-1)+".example&#34;") || strings.Contains(h, "&#34;N"+strconv.Itoa(PolicyShown)+".example&#34;") {
			t.Errorf("%d reasons: home lists %d, want the first %d", tc.names, listed, PolicyShown)
		}
		if (tc.more == "") == strings.Contains(h, "more reason") || !strings.Contains(h, tc.more) || strings.Count(h, "still applies") != 1 {
			t.Errorf("%d reasons: the count of the rest is not %q:\n%s", tc.names, tc.more, h)
		}
		if tc.names == 5000 && len(h) > 16<<10 {
			t.Errorf("%d reasons: home is %d bytes, not bounded", tc.names, len(h))
		}
	}
	if got := sentence("a\tb\x00c é"); got != `a\tb\x00c \u00e9` {
		t.Errorf("sentence = %q", got)
	}
	g = newRig(t)
	if h := g.homeHTML(); strings.Contains(h, "Names and addresses") {
		t.Error("home shows a resolver it was not given")
	}
}

// #5528 (NET-3; nft ASSUMPTIONS ENF-shared-src-1): a host the firewall
// kept from an address another host had until recently shows on home in
// one line, whether or not the resolver runs, beside an unread lease file
// under one heading, and only while the daemon says so. The line is a
// finding with a step: it names how long the wait lasts and what the
// owner can do sooner, and names no address, hardware address, counter or
// other identifier.
func TestHomeShowsAHeldHost(t *testing.T) {
	g := newRig(t)
	res := &fakeResolver{}
	cfg := g.s.cfg
	cfg.Resolver = res
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	const held = "<p>In the last 12 hours, a device on the Owner, Household or Guests network was offered an address another device had until recently and may still use, so the enforcer held that offer back. Such a device cannot join until the address is free, within 12 hours. To join it sooner, turn its private (random) Wi-Fi address off, or on, for that network and join again: it then usually gets another address.</p>"
	if h := g.homeHTML(); strings.Contains(h, "Addresses handed out") || strings.Contains(h, "held that offer") {
		t.Fatal("home shows a held host the daemon did not report")
	}
	for _, stopped := range []bool{false, true} {
		res.stop = ResolverStop{Stopped: stopped, Held: true}
		h := g.homeHTML()
		if !strings.Contains(h, "<h2>Addresses handed out</h2>") || strings.Count(h, held) != 1 || strings.Contains(h, "could not read its list") {
			t.Errorf("home (stopped %v) does not show a held host in its words alone:\n%s", stopped, h)
		}
	}
	res.stop = ResolverStop{Held: true, Unseeded: true}
	if h := g.homeHTML(); strings.Count(h, "<h2>Addresses handed out</h2>") != 1 || strings.Count(h, held) != 1 || !strings.Contains(h, "could not read its list") {
		t.Errorf("home does not show a held host and an unread lease file under one heading:\n%s", h)
	}
	line := strings.TrimSuffix(strings.TrimPrefix(held, "<p>"), "</p>")
	for _, step := range []string{"within 12 hours", "To join it sooner, turn its private (random) Wi-Fi address off, or on"} {
		if !strings.Contains(line, step) {
			t.Errorf("the held host's line names no %q", step)
		}
	}
	if regexp.MustCompile(`[0-9a-f]{2}:[0-9a-f]{2}|[0-9]+\.[0-9]+\.[0-9]|[a-z][A-Z]|_|/|\.go|[0-9a-f]{8}`).MatchString(line) {
		t.Errorf("the held host's line names an identifier: %s", line)
	}
}

// #5280, #5284 (NET-2 Segments; split from #5164 R4): each typed cause
// of the served check reads in the owner's words, with any name in
// printable ASCII; a cause with no words is one generic line.
func TestPlainUnset(t *testing.T) {
	const again = " It tries again every 10 seconds."
	for u, want := range map[Unset]string{
		{Kind: UnsetSetting, Iface: "own0", Setting: RouterAds}: "The enforcer could not turn off router advertisements on interface own0, so a device on that network could set a route or address the enforcer did not check." + again,
		// A redirect sets a route, never an address (#5307).
		{Kind: UnsetSetting, Iface: "dev0", Setting: Redirects4}:    "The enforcer could not turn off IPv4 redirects on interface dev0, so a device on that network could set a route the enforcer did not check." + again,
		{Kind: UnsetSetting, Iface: "gst0", Setting: Redirects6}:    "The enforcer could not turn off IPv6 redirects on interface gst0, so a device on that network could set a route the enforcer did not check." + again,
		{Kind: UnsetSetting, Iface: "default", Setting: RouterAds}:  "The enforcer could not turn off router advertisements for interfaces made from now on, so a home network's interface made again could take a route or address the enforcer did not check." + again,
		{Kind: UnsetSetting, Iface: "default", Setting: Redirects4}: "The enforcer could not turn off IPv4 redirects for interfaces made from now on, so a home network's interface made again could take a route the enforcer did not check." + again,
		{Kind: UnsetSetting, Iface: "default", Setting: Redirects6}: "The enforcer could not turn off IPv6 redirects for interfaces made from now on, so a home network's interface made again could take a route the enforcer did not check." + again,
		// An empty interface name is said without one (#5307).
		{Kind: UnsetSetting, Setting: RouterAds}:                "The enforcer could not turn off router advertisements on a home network's interface, so a device on that network could set a route or address the enforcer did not check." + again,
		{Kind: UnsetSetting, Setting: Redirects4}:               "The enforcer could not turn off IPv4 redirects on a home network's interface, so a device on that network could set a route the enforcer did not check." + again,
		{Kind: UnsetSetting, Setting: Redirects6}:               "The enforcer could not turn off IPv6 redirects on a home network's interface, so a device on that network could set a route the enforcer did not check." + again,
		{Kind: UnsetAddrs}:                                      "The enforcer could not read the addresses on a home network's interface, so it cannot check that each lies in that network." + again,
		{Kind: UnsetChanged}:                                    "The addresses on a home network's interface changed while the enforcer read them. It reads them again within 10 seconds.",
		{Kind: UnsetIPv6}:                                       "The enforcer could not read whether the kernel has IPv6 settings, so it could not check that redirects and router advertisements are off on the home networks' interfaces: a device on a home network could set a route or address the enforcer did not check." + again,
		{Kind: UnsetSetting, Iface: "all", Setting: Redirects4}: "The enforcer could not turn off IPv4 redirects for all interfaces at once, so a device on a home network could set a route the enforcer did not check." + again,
		{Kind: UnsetName, Iface: "own\u202e0"}:                  `The enforcer's setup names "own\u202e0" as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		{Kind: UnsetName, Iface: ""}:                            `The enforcer's setup names "" as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		{Kind: UnsetName, Iface: ".."}:                          `The enforcer's setup names ".." as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		{Kind: UnsetChanged, Iface: "own0"}:                     "The addresses on interface own0 changed while the enforcer read them. It reads them again within 10 seconds.",
		{Kind: UnsetAddrs, Iface: "dev0"}:                       "The enforcer could not read the addresses on interface dev0, so it cannot check that each lies in that network." + again,
		// A name past ASCII is quoted and escaped (ascii), never bare.
		{Kind: UnsetSetting, Iface: "own\u00e9", Setting: RouterAds}: `The enforcer could not turn off router advertisements on interface "own\u00e9", so a device on that network could set a route or address the enforcer did not check.` + again,
		{Kind: UnsetAddrs, Iface: "own\u00e9"}:                       `The enforcer could not read the addresses on interface "own\u00e9", so it cannot check that each lies in that network.` + again,
		{Kind: UnsetChanged, Iface: "own \u202e0"}:                   `The addresses on interface "own \u202e0" changed while the enforcer read them. It reads them again within 10 seconds.`,
		// No words: an untyped failure, a setting the page does not
		// know, a kind past the last.
		{}:                                           "",
		{Iface: "own0", Setting: RouterAds}:          "",
		{Kind: UnsetSetting, Iface: "own0"}:          "",
		{Kind: UnsetSetting, Iface: "all"}:           "",
		{Kind: UnsetSetting, Iface: "default"}:       "",
		{Kind: UnsetSetting, Setting: RouterAds + 1}: "",
		{Kind: UnsetIPv6 + 1, Iface: "own0"}:         "",
	} {
		if want == "" {
			want = "A home network's interface is not as set up, in a way this page has no words for; the enforcer's log has the detail. It checks again every 10 seconds."
		}
		if got := plainUnset(u); got != want {
			t.Errorf("plainUnset(%+v)\n = %q\nwant %q", u, got, want)
		}
	}
}

type fakeEdge struct {
	cut    bool
	reason string
	err    error
	lifts  int
}

func (f *fakeEdge) Cut() (bool, string) { return f.cut, f.reason }
func (f *fakeEdge) LiftEdge() error {
	f.lifts++
	if f.err != nil {
		return f.err
	}
	f.cut, f.reason = false, ""
	return nil
}

// #5014 (NET-2 Byte caps, KRN-12): a cut edge shows on home with why and
// what lifting it does, escaped as page text; the lift takes the owner's
// passkey, carries no target, is drawn only while the edge is cut, and a
// lift that fails leaves the card.
func TestLiftEdgeCut(t *testing.T) {
	g := newRig(t)
	if code, _ := g.tapState(g.a, ActLiftEdge, ""); code != http.StatusNotFound {
		t.Errorf("a lift with no edge wired: %d", code)
	}
	ed := &fakeEdge{}
	cfg := g.s.cfg
	cfg.Edge, cfg.Lock = ed, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	if h := g.homeHTML(); strings.Contains(h, "<h2>Edge box</h2>") {
		t.Fatal("home shows an edge that is not cut")
	}
	if code, _ := g.tapState(g.a, ActLiftEdge, ""); code != http.StatusConflict || ed.lifts != 0 {
		t.Errorf("a lift of an edge not cut: %d", code)
	}
	ed.cut, ed.reason = true, "byte cap passed: 6000 of 5000 bytes today <b>. Lift the cut once you trust the edge again."
	h := g.homeHTML()
	if !strings.Contains(h, "The edge box is cut off: byte cap passed: 6000 of 5000 bytes today &lt;b&gt;. Lift the cut once you trust the edge again.</p>") ||
		!strings.Contains(h, `data-action="lift-edge"`) {
		t.Fatalf("home does not show the cut edge and its lift:\n%s", h)
	}
	// #5399 item 1: the advice is the reason's own, so a cut whose record
	// is missing says to check the enforcer, never to trust the edge.
	ed.reason = "the record of the edge's cut is missing. Someone may have tampered with the enforcer: check it before you lift the cut."
	if h := g.homeHTML(); !strings.Contains(h, "The edge box is cut off: the record of the edge&#39;s cut is missing. Someone may have tampered with the enforcer: check it before you lift the cut.</p>") ||
		strings.Contains(h, "trust the edge") {
		t.Fatalf("a missing record's card:\n%s", h)
	}
	ed.reason = "byte cap passed: 6000 of 5000 bytes today <b>. Lift the cut once you trust the edge again."
	if code, _ := g.tapState(g.a, ActLiftEdge, "x"); code != http.StatusNotFound {
		t.Errorf("a lift with a target: %d", code)
	}
	if code, _ := g.tapState(newAuthenticator(t), ActLiftEdge, ""); code != http.StatusForbidden || ed.lifts != 0 {
		t.Fatalf("a stranger's lift: %d", code)
	}
	ed.err = errors.New("disk full")
	if code, _ := g.tapState(g.a, ActLiftEdge, ""); code != http.StatusConflict || !strings.Contains(g.homeHTML(), "<h2>Edge box</h2>") {
		t.Fatalf("a failed lift: %d", code)
	}
	ed.err = nil
	if code, res := g.tapState(g.a, ActLiftEdge, ""); code != http.StatusOK || res["done"] != true {
		t.Fatalf("lift: %d %v", code, res)
	}
	if h := g.homeHTML(); strings.Contains(h, "<h2>Edge box</h2>") {
		t.Fatal("home still shows a lifted cut")
	}
}
