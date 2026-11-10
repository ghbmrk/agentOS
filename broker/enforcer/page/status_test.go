package page

// REQ: NET-2, NET-4, KEY-7, STO-4, KRN-12

import (
	"errors"
	"net/http"
	"net/netip"
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
	res.stop = ResolverStop{Stopped: true, Load: "an older refusal", Strays: []Stray{
		{Iface: "own0", Addr: netip.MustParsePrefix("10.99.0.1/24"), Nets: "10.10.0.0/24 and fd00:10::/64"},
		{Iface: "dev0", Addr: netip.MustParsePrefix("fd00:99::7/64"), Nets: "10.20.0.0/24"},
	}}
	h := g.homeHTML()
	for _, want := range []string{
		"<h2>Names and addresses</h2>", "stopped answering name lookups and handing out addresses on every home network",
		"Interface own0 holds the address 10.99.0.1/24, outside its network 10.10.0.0/24 and fd00:10::/64.",
		"Interface dev0 holds the address fd00:99::7/64, outside its network 10.20.0.0/24.",
		"within 10 seconds of the last such address being removed",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("home with stray addresses lacks %q", want)
		}
	}
	if strings.Contains(h, "could not turn off") || strings.Contains(h, "has no words for") || strings.Contains(h, "The policy in force names") || strings.Contains(h, "an older refusal") || strings.Contains(h, "with its next load of your rules") {
		t.Error("home shows a cause the resolver does not have, or a refused load beside a listed cause")
	}
	// With no listed cause, the refused load that keeps it stopped
	// (#5243 L3 item 1); and a cause while instances run shows nothing.
	res.stop = ResolverStop{Stopped: true, Load: "nft: load refused \u202e"}
	if h = g.homeHTML(); !strings.Contains(h, "The firewall refused the enforcer's last load of your rules (nft: load refused \\u202e), and names and addresses come back only with a load it takes.") {
		t.Errorf("a refused load is not shown, or not in ASCII:\n%s", h)
	}
	// Stopped with no cause recorded (between a check that passes and
	// the next load): the card still says when it ends (Lens on #5243).
	res.stop = ResolverStop{Stopped: true}
	if h = g.homeHTML(); !strings.Contains(h, "The enforcer serves names and addresses again with its next load of your rules, within a few seconds.") {
		t.Errorf("a stop with no cause gives no reason:\n%s", h)
	}
	res.stop = ResolverStop{Strays: []Stray{{Iface: "own0", Addr: netip.MustParsePrefix("10.99.0.1/24"), Nets: "10.10.0.0/24"}}, Load: "x"}
	if h = g.homeHTML(); strings.Contains(h, "Names and addresses") {
		t.Error("home shows a resolver whose instances run as stopped")
	}
	// A setting that did not take shows in plain words, never the raw
	// error, and an error said twice shows once (#5280).
	ra := "/proc/sys/net/ipv6/conf/own0/accept_ra not set to 0 (reads \"1\"): <nil>"
	res.stop = ResolverStop{Stopped: true, Unset: []string{ra, ra}}
	h = g.homeHTML()
	if !strings.Contains(h, "<p>The enforcer could not turn off router advertisements on interface own0, so a device on that network could set a route or address the enforcer did not check. It tries again every 10 seconds.</p>") || strings.Contains(h, "Interface own0 holds") {
		t.Errorf("a setting that did not take is not shown alone:\n%s", h)
	}
	if strings.Count(h, "router advertisements") != 1 || strings.Contains(h, "/proc/sys") || strings.Contains(h, "&#34;") {
		t.Errorf("home shows the raw error, or one error twice:\n%s", h)
	}
	res.stop = ResolverStop{Stopped: true, Policy: "device plug: vlan109 is not a served VLAN ‮gro.live"}
	h = g.homeHTML()
	if !strings.Contains(h, "The policy in force names something the enforcer cannot serve (device plug: vlan109 is not a served VLAN \\u202egro.live).") {
		t.Errorf("a policy the resolver cannot serve is not shown, or not in ASCII:\n%s", h)
	}
	if strings.ContainsRune(h, '‮') {
		t.Error("home carries a right-to-left override from the policy's error")
	}
	if got := sentence("a\tb\x00c é"); got != `a\tb\x00c \u00e9` {
		t.Errorf("sentence = %q", got)
	}
	g = newRig(t)
	if h := g.homeHTML(); strings.Contains(h, "Names and addresses") {
		t.Error("home shows a resolver it was not given")
	}
}

// #5280 (NET-2 Segments; split from #5164 R4): each error the served
// check writes reads in the owner's words, with any name in printable
// ASCII; an error with no words is one generic line, never its text.
func TestPlainUnset(t *testing.T) {
	const again = " It tries again every 10 seconds."
	for raw, want := range map[string]string{
		"/proc/sys/net/ipv6/conf/own0/accept_ra not set to 0 (reads \"1\\n\"): <nil>":                                                                    "The enforcer could not turn off router advertisements on interface own0, so a device on that network could set a route or address the enforcer did not check." + again,
		"/proc/sys/net/ipv4/conf/dev0/accept_redirects not set to 0 (reads \"\"): open /proc/sys/net/ipv4/conf/dev0/accept_redirects: permission denied": "The enforcer could not turn off IPv4 redirects on interface dev0, so a device on that network could set a route or address the enforcer did not check." + again,
		"/proc/sys/net/ipv6/conf/gst0/accept_redirects not set to 0 (reads \"1\\n\"): <nil>":                                                             "The enforcer could not turn off IPv6 redirects on interface gst0, so a device on that network could set a route or address the enforcer did not check." + again,
		"/proc/sys/net/ipv6/conf/default/accept_ra not set to 0 (reads \"2\\n\"): <nil>":                                                                 "The enforcer could not turn off router advertisements for interfaces made from now on, so a home network's interface made again could take a route or address the enforcer did not check." + again,
		"/proc/sys/net/ipv4/conf/all/accept_redirects not set to 0 (reads \"1\\n\"): <nil>":                                                              "The enforcer could not turn off IPv4 redirects for all interfaces at once, so a device on a home network could set a route the enforcer did not check." + again,
		`served interface "own\u202e0": not an interface name`:                                                                                           `The enforcer's setup names "own\u202e0" as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		"served interface own0: addresses: interface own0 was made again while its addresses were read (index 4, then 9)":                                "The addresses on interface own0 changed while the enforcer read them. It reads them again within 10 seconds.",
		"served interface dev0: addresses: the kernel's address dump was interrupted by a change":                                                        "The addresses on interface dev0 changed while the enforcer read them. It reads them again within 10 seconds.",
		"served interface dev0: addresses: the kernel's address dump has no end\nnetlink: short":                                                         "The enforcer could not read the addresses on interface dev0, so it cannot check that each lies in that network." + again,
		`served interface "": not an interface name`:                                                                                                     `The enforcer's setup names "" as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		`served interface "..": not an interface name`:                                                                                                   `The enforcer's setup names ".." as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected.`,
		// A name past ASCII is quoted and escaped (ascii), never bare.
		"/proc/sys/net/ipv6/conf/own\u00e9/accept_ra not set to 0 (reads \"1\\n\"): <nil>": `The enforcer could not turn off router advertisements on interface "own\u00e9", so a device on that network could set a route or address the enforcer did not check.` + again,
		"served interface own\u00e9: addresses: x":                                         `The enforcer could not read the addresses on interface "own\u00e9", so it cannot check that each lies in that network.` + again,
		// A name past the kernel's 15 bytes is no kernel's: no words.
		"/proc/sys/net/ipv6/conf/own456789abcdefg/accept_ra not set to 0 (reads \"1\"): <nil>": "",
		"served interface own456789abcdefg: addresses: x":                                      "",
		// No words: an unknown error, a key hold never writes, a path
		// outside /proc/sys/net, a name no kernel gives, a bad quote.
		"stat /proc/sys/net/ipv6: input/output error \u202e":                                                "",
		"/proc/sys/net/ipv4/conf/own0/accept_ra not set to 0 (reads \"1\"): <nil>":                          "",
		"/tmp/x/ipv6/conf/own0/accept_ra not set to 0 (reads \"1\"): <nil>":                                 "",
		"/proc/sys/net/ipv6/conf/own0 x/accept_ra not set to 0 (reads \"1\"): <nil>":                        "",
		"/proc/sys/net/ipv6/conf/own0/accept_ra not set to 1 (reads \"1\"): <nil>":                          "",
		`served interface "own0\x": not an interface name`:                                                  "",
		`served interface "own0": not an interface name, and more`:                                          "",
		"served interface own0 own1: addresses: x":                                                          "",
		"x served interface own0: addresses: x":                                                             "",
		"served interface own0: addresses: interface own1 x was made again while its addresses were read (": "The enforcer could not read the addresses on interface own0, so it cannot check that each lies in that network." + again,
	} {
		if want == "" {
			want = "A home network's interface is not as set up, in a way this page has no words for; the enforcer's log has the detail. It checks again every 10 seconds."
		}
		if got := plainUnset(raw); got != want {
			t.Errorf("plainUnset(%q)\n = %q\nwant %q", raw, got, want)
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
	ed.cut, ed.reason = true, "byte cap passed: 6000 of 5000 bytes today <b>"
	h := g.homeHTML()
	if !strings.Contains(h, "The edge box is cut off: byte cap passed: 6000 of 5000 bytes today &lt;b&gt;.") ||
		!strings.Contains(h, `data-action="lift-edge"`) {
		t.Fatalf("home does not show the cut edge and its lift:\n%s", h)
	}
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
