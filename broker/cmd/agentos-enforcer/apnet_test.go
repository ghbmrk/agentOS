package main

// REQ: NET-3, NET-4, HW-10

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// twoAPs is a box whose configuration has a second access point.
func twoAPs(t *testing.T) (*box, string) {
	t.Helper()
	x := newBox(t, false)
	x.d.Close()
	second := "10.70.0.3:22"
	x.cfg.Layout.APAdmin = append(x.cfg.Layout.APAdmin, netip.MustParseAddr("10.70.0.3"))
	p := x.cfg.AP.Points[0]
	p.Addr = netip.MustParseAddrPort(second)
	x.cfg.AP.Points = append(x.cfg.AP.Points, p)
	if err := x.cfg.check(); err != nil {
		t.Fatal(err)
	}
	x.ap = &fakeAP{}
	x.start()
	return x, second
}

// NET-3, ENF-g-8 (#4569): over many ticks, enrolment's hand-over and a
// policy reload, the daemon makes one pusher per access point and drives
// every push through it, each Watch on the minute. A fresh pusher per
// push would reset the count of abandoned opens, and so the stall cap.
func TestOnePusherPerAccessPoint(t *testing.T) {
	x, second := twoAPs(t)
	a := newAuthenticator(t)
	x.b.enrol(a, caseCode)
	for i := 0; i < 30; i++ {
		x.advance(10 * time.Second)
	}
	if w := x.b.approve(a, home()); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	// The reload reaches both access points at once, with the tv's own
	// password.
	tv := func() string { return x.apKeys().Device["tv"].Password }
	waitFor(t, func() bool {
		return tv() != "" && strings.Contains(x.ap.wireless(apAddr), tv()) && strings.Contains(x.ap.wireless(second), tv())
	})
	for i := 0; i < 30; i++ {
		x.advance(10 * time.Second)
	}
	x.ap.mu.Lock()
	defer x.ap.mu.Unlock()
	for _, addr := range []string{apAddr, second} {
		ps := x.ap.made[addr]
		if len(ps) != 1 {
			t.Fatalf("%s: %d pushers made in one run, want 1", addr, len(ps))
		}
		if len(ps[0].every) < 3 {
			t.Errorf("%s: %d pushes, want one at start, at enrolment and at the reload", addr, len(ps[0].every))
		}
		for _, e := range ps[0].every {
			if e != apEvery {
				t.Errorf("%s: Watch every %v, want %v", addr, e, apEvery)
			}
		}
	}
}

// NET-4, HW-10: enrolment enrols nothing until every access point holds
// the four networks. A push that fails leaves the setup network on every
// access point, the sticker's password working and the new passwords kept
// for the retry, which then succeeds with the same Owner password.
func TestEnrolmentWaitsForEveryAccessPoint(t *testing.T) {
	x, second := twoAPs(t)
	waitFor(t, func() bool {
		return strings.Contains(x.ap.wireless(apAddr), setupPW) && strings.Contains(x.ap.wireless(second), setupPW)
	})
	x.ap.mu.Lock()
	x.ap.failing = errors.New("push: dial: connection refused")
	x.ap.mu.Unlock()
	a := newAuthenticator(t)
	r := x.b.json(http.MethodPost, "/enrol/begin", map[string]string{"code": caseCode, "public_key": a.spki()}, http.StatusOK)
	w := x.b.do(http.MethodPost, "/enrol/finish", a.assertion(r["id"].(string), r["challenge"].(string)))
	if w.Code == http.StatusOK || x.d.book.Owner() == a.Public() || x.d.ap.Replaced() {
		t.Fatalf("enrolled with no access point holding the Owner network: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"network"`) {
		t.Fatalf("a card for a network no access point holds: %s", w.Body)
	}
	if !x.logContains(": push failed: push: dial: connection refused") {
		t.Fatal("the failed push is not in the log")
	}
	owner := x.apKeys().Owner
	x.ap.mu.Lock()
	x.ap.failing = nil
	x.ap.mu.Unlock()
	// The undo pushes the setup network again.
	waitFor(t, func() bool {
		return strings.Contains(x.ap.wireless(apAddr), setupPW) && strings.Contains(x.ap.wireless(second), setupPW)
	})
	res := x.b.enrol(a, caseCode)
	card := res["network"].(map[string]any)
	if card["password"] != grouped4(owner) || x.apKeys().Owner != owner {
		t.Fatalf("the retry made new passwords: %v", card)
	}
	for _, addr := range []string{apAddr, second} {
		if w := x.ap.wireless(addr); strings.Contains(w, setupPW) || !strings.Contains(w, owner) {
			t.Fatalf("%s after enrolment:\n%s", addr, w)
		}
	}
	// A restart keeps the hand-over: no setup network comes back.
	x.restart()
	if !x.d.ap.Replaced() {
		t.Fatal("the hand-over did not survive a restart")
	}
	x.d.ap.nudge()
	time.Sleep(20 * time.Millisecond)
	if strings.Contains(x.ap.wireless(apAddr), setupPW) {
		t.Fatal("the setup network came back after a restart")
	}
}

// finishEnrol runs the page's two enrolment steps for a with the case
// code and returns the finish's answer, failing the test if it takes more
// than bound.
func finishEnrol(x *box, a *authenticator, bound time.Duration) *httptest.ResponseRecorder {
	x.t.Helper()
	r := x.b.json(http.MethodPost, "/enrol/begin", map[string]string{"code": caseCode, "public_key": a.spki()}, http.StatusOK)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- x.b.do(http.MethodPost, "/enrol/finish", a.assertion(r["id"].(string), r["challenge"].(string)))
	}()
	select {
	case w := <-done:
		return w
	case <-time.After(bound):
		x.t.Fatalf("enrolment did not answer within %v", bound)
		return nil
	}
}

// NET-4, HW-10, ENF-l-ap-5: a hand-over one access point never reports
// ends at the deadline: nothing enrols, and the access point that took
// the four networks is pushed the setup network back, sticker password
// and all. A wait with no deadline would hold the book, and so its Tick,
// for good.
func TestEnrolmentHandOverTimesOut(t *testing.T) {
	x, second := twoAPs(t)
	x.d.Close()
	x.waits.APWait = 100 * time.Millisecond
	x.ap = &fakeAP{}
	x.start()
	waitFor(t, func() bool {
		return strings.Contains(x.ap.wireless(apAddr), setupPW) && strings.Contains(x.ap.wireless(second), setupPW)
	})
	x.ap.mu.Lock()
	x.ap.silent = map[string]bool{second: true}
	x.ap.mu.Unlock()
	a := newAuthenticator(t)
	w := finishEnrol(x, a, 5*time.Second)
	if w.Code == http.StatusOK || x.d.book.Owner() == a.Public() || x.d.ap.Replaced() {
		t.Fatalf("enrolled with an access point that never answered: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "did not take the new networks within") {
		t.Fatalf("not the deadline's refusal: %s", w.Body)
	}
	owner := x.apKeys().Owner
	waitFor(t, func() bool {
		h := x.ap.wireless(apAddr)
		return strings.Contains(h, setupPW) && !strings.Contains(h, owner)
	})
}

// ENF-l-ap-5 (rollback): one access point takes the four networks and
// another refuses them; the first is pushed the setup network back, so
// the sticker is not the only way in on one and dead on the other.
func TestEnrolmentFailureRollsBackEveryAccessPoint(t *testing.T) {
	x, second := twoAPs(t)
	waitFor(t, func() bool { return strings.Contains(x.ap.wireless(second), setupPW) })
	x.ap.mu.Lock()
	x.ap.failAt = map[string]error{second: errors.New("push: ssh: handshake failed")}
	x.ap.mu.Unlock()
	a := newAuthenticator(t)
	if w := finishEnrol(x, a, 5*time.Second); w.Code == http.StatusOK || x.d.ap.Replaced() {
		t.Fatalf("enrolled with one access point refusing: %d %s", w.Code, w.Body)
	}
	owner := x.apKeys().Owner
	waitFor(t, func() bool {
		h := x.ap.wireless(apAddr)
		return strings.Contains(h, setupPW) && !strings.Contains(h, owner)
	})
}

// HW-10, ENF-l-ap-5: the hand-over is saved before enrolment goes on. A
// failed save of it enrols nothing, pushes the setup network back, and a
// restart still pushes the setup network: the saved state never says
// replaced when it is not, nor the reverse.
func TestEnrolmentReplacedSaveFails(t *testing.T) {
	x := newBox(t, false)
	waitFor(t, func() bool { return strings.Contains(x.ap.wireless(apAddr), setupPW) })
	x.failOn(fileAPKeys, 2) // the first save is the four passwords, the second the hand-over
	a := newAuthenticator(t)
	if w := finishEnrol(x, a, 5*time.Second); w.Code == http.StatusOK || x.d.ap.Replaced() || x.d.book.Owner() == a.Public() {
		t.Fatalf("enrolled with the hand-over unsaved: %d %s", w.Code, w.Body)
	}
	owner := x.apKeys().Owner
	if owner == "" {
		t.Fatal("the four passwords were not kept for the retry")
	}
	waitFor(t, func() bool { return strings.Contains(x.ap.wireless(apAddr), setupPW) })
	x.restart()
	if x.d.ap.Replaced() {
		t.Fatal("a restart reads an unsaved hand-over as done")
	}
	x.d.ap.nudge()
	waitFor(t, func() bool {
		x.ap.mu.Lock()
		n := len(x.ap.made[apAddr])
		x.ap.mu.Unlock()
		h := x.ap.wireless(apAddr)
		return n == 2 && strings.Contains(h, setupPW) && !strings.Contains(h, owner)
	})
}

// HW-10, ENF-l-ap-4: the four passwords are saved before any access point
// is pushed them. A failed save pushes none and enrols nothing.
func TestEnrolmentPasswordSaveFails(t *testing.T) {
	x := newBox(t, false)
	waitFor(t, func() bool { return strings.Contains(x.ap.wireless(apAddr), setupPW) })
	x.fail(fileAPKeys, true)
	a := newAuthenticator(t)
	if w := finishEnrol(x, a, 5*time.Second); w.Code == http.StatusOK || x.d.ap.Replaced() {
		t.Fatalf("enrolled with the passwords unsaved: %d %s", w.Code, w.Body)
	}
	if x.apKeys().Owner != "" {
		t.Fatal("the passwords' save failed, yet the file holds them")
	}
	x.ap.mu.Lock()
	defer x.ap.mu.Unlock()
	for _, h := range x.ap.history {
		if !strings.Contains(h, setupPW) || strings.Contains(h, "'Home family'") {
			t.Fatalf("the access point was pushed passwords no file holds:\n%s", h)
		}
	}
}

// NET-3, ENF-l-ap-4: a device's own password is saved before any access
// point is pushed it. While its save fails, the access point gets no
// password for the device and the log says why; once it saves, the
// password the access point holds is the one on disk.
func TestDevicePasswordSavedBeforePush(t *testing.T) {
	x, a := enrolled(t, false)
	waitFor(t, func() bool {
		tv := x.apKeys().Device["tv"].Password
		return tv != "" && strings.Contains(x.ap.wireless(apAddr), tv)
	})
	next := x.current()
	next.Version++
	next.Devices = append(next.Devices, policy.Device{ID: "speaker", Network: policy.NetDevices, WiFi: "vlan102", Everyday: true})
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.fail(fileAPKeys, true)
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if x.current().Device("speaker") == nil {
		t.Fatal("the speaker is not in force")
	}
	waitFor(t, func() bool { return x.logContains("device Wi-Fi passwords not saved, so not pushed") })
	x.d.ap.nudge()
	time.Sleep(20 * time.Millisecond)
	if strings.Count(x.ap.wireless(apAddr), "config wifi-station") != 1 {
		t.Fatalf("the access point holds a device password no file holds:\n%s", x.ap.wireless(apAddr))
	}
	x.fail(fileAPKeys, false)
	x.d.ap.nudge()
	waitFor(t, func() bool {
		sp := x.apKeys().Device["speaker"].Password
		return sp != "" && strings.Contains(x.ap.wireless(apAddr), sp)
	})
}

// The configuration refuses an access point the daemon could not reach
// or pin, and a layout that names the enforcer's key, which is the
// daemon's own.
func TestAPConfigRefuses(t *testing.T) {
	for name, f := range map[string]func(*Config){
		"address not the layout's": func(c *Config) { c.AP.Points[0].Addr = netip.MustParseAddrPort("10.70.0.9:22") },
		"no port":                  func(c *Config) { c.AP.Points[0].Addr = netip.AddrPortFrom(netip.MustParseAddr("10.70.0.2"), 0) },
		"twice":                    func(c *Config) { c.AP.Points = append(c.AP.Points, c.AP.Points[0]) },
		"host key":                 func(c *Config) { c.AP.Points[0].HostKey = "ssh-ed25519 not-a-key" },
		"enforcer key":             func(c *Config) { c.AP.Layout.EnforcerKey = "ssh-ed25519 AAAA" },
		"layout":                   func(c *Config) { c.AP.Layout.Owner = c.AP.Layout.Guests },
		"no admin interface":       func(c *Config) { c.Layout.APMgmt = "" },
	} {
		c := testConfig(t)
		f(&c)
		if err := c.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
