package main

// REQ: NET-3, NET-4, HW-10

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
	"github.com/ghbmrk/agentos/broker/enforcer/ap/push"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"golang.org/x/crypto/ssh"
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
	x.d.Close()
	x.ap.mu.Lock()
	defer x.ap.mu.Unlock()
	for _, addr := range []string{apAddr, second} {
		ps := x.ap.made[addr]
		if len(ps) > 0 && (ps[0].overlapped || ps[0].active != 0) {
			t.Errorf("%s: Watch calls overlapped (%v) or ran on after close (%d)", addr, ps[0].overlapped, ps[0].active)
		}
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
	// The second access point refuses only once the first holds the four
	// networks, so the rollback has something to undo.
	x.ap.mu.Lock()
	x.ap.failAt = map[string]error{second: errors.New("push: ssh: handshake failed")}
	x.ap.silent = map[string]bool{second: true}
	x.ap.mu.Unlock()
	a := newAuthenticator(t)
	go func() {
		waitFor(t, func() bool { return strings.Contains(x.ap.wireless(apAddr), "'Home family'") })
		x.ap.mu.Lock()
		delete(x.ap.silent, second)
		x.ap.mu.Unlock()
		// Only the second pushes again: the first keeps the four networks
		// until the rollback's own nudge.
		for _, p := range x.d.ap.points {
			if p.addr == second {
				p.kick <- struct{}{}
			}
		}
	}()
	if w := finishEnrol(x, a, 5*time.Second); w.Code == http.StatusOK || x.d.ap.Replaced() {
		t.Fatalf("enrolled with one access point refusing: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(x.ap.wireless(apAddr), "'Home family'") && !strings.Contains(strings.Join(x.ap.history, ""), "'Home family'") {
		t.Fatal("the first access point never held the four networks, so no rollback was tested")
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
		if err := c.AP.check(c.Layout); err == nil {
			t.Errorf("%s: the access point check accepted it", name)
		}
	}
}

// HW-10, ENF-l-ap-4: first boot checks the setup password before it
// provisions anything, so a password the access point would refuse leaves
// the state directory empty and a corrected re-run can provision it.
func TestProvisionChecksSetupFirst(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(files, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	code, bad, good := write("case", caseCode), write("bad", "short"), write("good", setupPW)
	if err := provisionFiles(dir, code, bad); err == nil {
		t.Fatal("a setup password the access point refuses was provisioned")
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("a refused setup password left %d files in the state directory", len(left))
	}
	if err := provisionFiles(dir, code, good); err != nil {
		t.Fatalf("the corrected re-run: %v", err)
	}
}

// HW-10: first boot refuses a state directory that already holds Wi-Fi
// passwords, or one it cannot read, and a setup password the access point
// would refuse, writing nothing.
func TestProvisionAPRefuses(t *testing.T) {
	dir := t.TempDir()
	st := fileStore{path: filepath.Join(dir, fileAPKeys)}
	if err := provisionAP(st, "short"); err == nil {
		t.Fatal("a setup password the access point refuses was provisioned")
	}
	if b, _ := st.Load(); b != nil {
		t.Fatalf("a refused setup password was saved: %s", b)
	}
	if err := provisionAP(st, setupPW); err != nil {
		t.Fatal(err)
	}
	if err := provisionAP(st, setupPW); err == nil || !strings.Contains(err.Error(), "already provisioned") {
		t.Fatalf("provisioned twice: %v", err)
	}
	unreadable := fileStore{path: t.TempDir()} // a directory: Load fails
	if err := provisionAP(unreadable, setupPW); err == nil {
		t.Fatal("provisioned over a state file it could not read")
	}
}

// First boot's file checks (ENF-l-ap-4): each missing or refused input
// fails, and so does a state directory already provisioned.
func TestProvisionFilesRefuses(t *testing.T) {
	files := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(files, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	code, setup, missing := write("case", caseCode), write("setup", setupPW), filepath.Join(files, "missing")
	notExist := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	for name, tc := range map[string]struct {
		f    func(dir string) error
		want func(error) bool
	}{
		"no case file":    {func(dir string) error { return provisionFiles(dir, missing, setup) }, notExist},
		"no -ap-setup":    {func(dir string) error { return provisionFiles(dir, code, "") }, func(err error) bool { return strings.Contains(fmt.Sprint(err), "-ap-setup") }},
		"no setup file":   {func(dir string) error { return provisionFiles(dir, code, missing) }, notExist},
		"enrolment twice": {func(dir string) error { _ = provisionState(dir, caseCode); return provisionFiles(dir, code, setup) }, func(err error) bool { return err != nil }},
	} {
		dir := t.TempDir()
		if err := tc.f(dir); !tc.want(err) {
			t.Errorf("%s: provisioning gave %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, fileAPKeys)); err == nil {
			t.Errorf("%s: the setup password was saved", name)
		}
	}
}

// -provision needs -ap-setup, and -ap-pub refuses a key file it cannot
// read rather than printing another key.
func TestRunAPFlagsRefuse(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run refuses root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	code := filepath.Join(t.TempDir(), "case")
	if err := os.WriteFile(code, []byte(caseCode), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-state", dir, "-provision", code}); err == nil || !strings.Contains(err.Error(), "-ap-setup") {
		t.Fatalf("-provision with no -ap-setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileAPSSH), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-state", dir, "-ap-pub"}); err == nil {
		t.Fatal("-ap-pub printed a key from a file that holds none")
	}
}

// The enforcer's access point key: a file that holds no key is refused,
// never replaced.
func TestAPSSHKeyRefusesBadFile(t *testing.T) {
	st := fileStore{path: filepath.Join(t.TempDir(), fileAPSSH)}
	if err := st.Save([]byte("not a key\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := apSSHKey(st, rand.Reader); err == nil {
		t.Fatal("a key file holding no key was accepted")
	}
}

// Start refuses access points it cannot drive: no setup password
// provisioned, a password file it cannot read, an SSH key file that holds
// no key, or a host key that does not parse. With no access point
// configured it starts with nothing provisioned, and enrolment refuses.
func TestOpenAPRefuses(t *testing.T) {
	x := newBox(t, false)
	x.d.Close()
	keys := filepath.Join(x.dir, fileAPKeys)
	saved, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	expect := func(name, want string) {
		t.Helper()
		if _, err := x.open(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: start gave %v, want %q", name, err, want)
		}
	}
	os.Remove(keys)
	expect("not provisioned", "-ap-setup")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	expect("unreadable", "is a directory")
	os.Remove(keys)
	if err := os.WriteFile(keys, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("not JSON", "unexpected end of JSON input")
	os.Remove(keys)
	if err := os.WriteFile(keys, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.dir, fileAPSSH), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expect("ssh key", "access point key")
	os.Remove(filepath.Join(x.dir, fileAPSSH))
	good := x.cfg.AP.Points[0].HostKey
	x.cfg.AP.Points[0].HostKey = "ssh-ed25519 not-a-key"
	expect("host key", "host key")
	x.cfg.AP.Points[0].HostKey = good

	x.cfg.AP = APConfig{}
	if err := x.cfg.check(); err != nil {
		t.Fatalf("a configuration with no access point: %v", err)
	}
	os.Remove(keys)
	x.start()
	if _, err := x.d.ap.Replace(); err == nil || x.d.ap.Replaced() {
		t.Fatal("enrolment handed over with no access point configured")
	}
}

// NET-4: a hand-over already done answers with the Owner card at once,
// pushing nothing; a second hand-over while one runs is refused; and
// before the hand-over home shows no Wi-Fi card, even with the four
// passwords made by a failed try.
func TestReplaceOnceAtATime(t *testing.T) {
	x := newBox(t, false)
	x.d.Close()
	x.waits.APWait = 300 * time.Millisecond
	x.start()
	x.ap.mu.Lock()
	x.ap.silent = map[string]bool{apAddr: true}
	x.ap.mu.Unlock()
	first := make(chan error, 1)
	go func() { _, err := x.d.ap.Replace(); first <- err }()
	waitFor(t, func() bool { x.d.ap.mu.Lock(); defer x.d.ap.mu.Unlock(); return x.d.ap.replacing })
	if _, err := x.d.ap.Replace(); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second hand-over while one runs: %v", err)
	}
	if err := <-first; err == nil {
		t.Fatal("a hand-over no access point answered succeeded")
	}
	if x.apKeys().Owner == "" {
		t.Fatal("fixture: the failed try made no passwords")
	}
	if c := (pageAPs{x.d.ap}).Cards(); c != nil {
		t.Fatalf("Wi-Fi cards before the hand-over: %v", c)
	}
	x.ap.mu.Lock()
	x.ap.silent = nil
	x.ap.mu.Unlock()
	x.b.enrol(newAuthenticator(t), caseCode)
	owner := x.apKeys().Owner
	x.ap.mu.Lock()
	x.ap.silent = map[string]bool{apAddr: true}
	x.ap.mu.Unlock()
	start := time.Now()
	c, err := x.d.ap.Replace()
	if err != nil || c.Shown != grouped4(owner) || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("a hand-over already done: %v %q in %v, want the Owner card at once", err, c.Shown, time.Since(start))
	}
}

// ENF-g-8: once the device passwords are synced, the daemon's clock
// pushes nothing more until the policy changes.
func TestTickPushesOnlyOnChange(t *testing.T) {
	x, _ := enrolled(t, false)
	pushes := func() int { p := x.ap.last(apAddr); x.ap.mu.Lock(); defer x.ap.mu.Unlock(); return len(p.every) }
	waitFor(t, func() bool { return strings.Contains(x.ap.wireless(apAddr), x.apKeys().Device["tv"].Password) })
	time.Sleep(20 * time.Millisecond)
	before := pushes()
	for i := 0; i < 5; i++ {
		x.advance(time.Second)
	}
	time.Sleep(50 * time.Millisecond)
	if got := pushes(); got != before {
		t.Fatalf("%d pushes on ticks with no policy change", got-before)
	}
}

// bareAP is an apNet over the given watchers alone, logging to log.
func bareAP(log *[]string, mu *sync.Mutex, ws ...watcher) *apNet {
	d := &Enforcer{dp: deps{Logf: func(s string) { mu.Lock(); *log = append(*log, s); mu.Unlock() }}}
	n := &apNet{d: d, every: time.Hour, wait: time.Second}
	n.cond = sync.NewCond(&n.mu)
	for i, w := range ws {
		n.points = append(n.points, &apPoint{addr: fmt.Sprint("ap", i), w: w, kick: make(chan struct{}, 1)})
	}
	return n
}

// NET-3 (#4569): each report is kept for the page and logged when it
// changes; a push a nudge cut short is neither.
func TestReportLogsChanges(t *testing.T) {
	var log []string
	var mu sync.Mutex
	n := bareAP(&log, &mu, nil)
	p := n.points[0]
	n.report(p, 1, push.Result{}, context.Canceled)
	if p.reported || len(log) != 0 {
		t.Fatalf("a push cut short was kept (%v) or logged (%v)", p.reported, log)
	}
	fail := errors.New("dial: refused")
	for _, r := range []struct {
		err error
		res push.Result
	}{{nil, push.Result{}}, {nil, push.Result{}}, {fail, push.Result{}}, {fail, push.Result{}}, {push.ErrStalled, push.Result{Abandoned: 16}}, {nil, push.Result{}}} {
		n.report(p, 1, r.res, r.err)
	}
	// The first success is no change: a point starts as pushed.
	want := []string{"access point ap0: push failed: dial: refused",
		"access point ap0: stalled, 16 session opens waiting: " + push.ErrStalled.Error(), "access point ap0: pushed"}
	if !slices.Equal(log, want) {
		t.Fatalf("log:\n%q\nwant\n%q", log, want)
	}
}

// slowStop is a watcher whose Watch returns only when release closes,
// after its context ends: a push.Pusher in the middle of a slow push.
type slowStop struct{ release chan struct{} }

func (s slowStop) Watch(ctx context.Context, _ time.Duration, _ func() ([]ap.File, error), _ func(push.Result, error)) {
	<-ctx.Done()
	<-s.release
}

// A nudge never waits on an access point: while its Watch is still
// ending, further nudges return at once.
func TestNudgeNeverBlocks(t *testing.T) {
	var log []string
	var mu sync.Mutex
	s := slowStop{release: make(chan struct{})}
	n := bareAP(&log, &mu, s)
	n.start()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			n.nudge()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nudge blocked on an access point")
	}
	close(s.release)
	n.close()
}

// Home lists the device cards by device id.
func TestCardsSortedByDevice(t *testing.T) {
	var log []string
	var mu sync.Mutex
	n := bareAP(&log, &mu)
	n.layout = testAP(t).Layout
	n.st = apState{Keys: ap.Keys{Setup: setupPW}, Replaced: true}
	if err := n.st.Keys.Enrol(); err != nil {
		t.Fatal(err)
	}
	n.st.Keys.Device = map[string]ap.DeviceKey{}
	var ids []string
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("dev%02d", 11-i)
		ids = append(ids, id)
		n.st.Keys.Device[id] = ap.DeviceKey{VLAN: 101, Password: fmt.Sprintf("CANARYDEVICEPW%02d", i)}
	}
	slices.Sort(ids)
	var got []string
	for _, c := range (pageAPs{n}).Cards() {
		if c.Device != "" {
			got = append(got, c.Device)
		}
	}
	if !slices.Equal(got, ids) {
		t.Fatalf("device cards %v, want %v", got, ids)
	}
}

// cloneKeys copies the device map, so a change to the copy leaves the
// saved state as it was; keysEqual tells every field apart.
func TestKeysCloneAndEqual(t *testing.T) {
	k := ap.Keys{Setup: "s", Owner: "o", Household: "h", Guests: "g", Devices: "d", Device: map[string]ap.DeviceKey{"tv": {VLAN: 101, Password: "p"}}}
	c := cloneKeys(k)
	if !keysEqual(k, c) {
		t.Fatal("a clone differs")
	}
	c.Device["tv"] = ap.DeviceKey{VLAN: 101, Password: "q"}
	if k.Device["tv"].Password != "p" {
		t.Fatal("a change to the clone reached the original")
	}
	for name, f := range map[string]func(*ap.Keys){
		"setup": func(k *ap.Keys) { k.Setup = "x" }, "owner": func(k *ap.Keys) { k.Owner = "x" },
		"household": func(k *ap.Keys) { k.Household = "x" }, "guests": func(k *ap.Keys) { k.Guests = "x" },
		"devices":         func(k *ap.Keys) { k.Devices = "x" },
		"device password": func(k *ap.Keys) { k.Device["tv"] = ap.DeviceKey{VLAN: 101, Password: "x"} },
		"device added":    func(k *ap.Keys) { k.Device["lamp"] = ap.DeviceKey{VLAN: 102, Password: "x"} },
		"device renamed":  func(k *ap.Keys) { delete(k.Device, "tv"); k.Device["lamp"] = ap.DeviceKey{VLAN: 101, Password: "p"} },
	} {
		o := cloneKeys(k)
		f(&o)
		if keysEqual(k, o) || keysEqual(o, k) {
			t.Errorf("%s: keysEqual missed the change", name)
		}
	}
}

// ENF-g-8: the production pusher dials through the access point's admin
// interface alone: a dial bound to an interface that does not exist fails
// however near the address, and the pusher carries the address and keys.
func TestNewPusherBindsTheInterface(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	w := newPusher("nosuchif0")(ln.Addr().String(), signer.PublicKey(), signer)
	p, ok := w.(*push.Pusher)
	if !ok || p.Addr != ln.Addr().String() || p.HostKey == nil || !bytes.Equal(p.HostKey.Marshal(), signer.PublicKey().Marshal()) || p.Signer != signer || p.Dial == nil {
		t.Fatalf("pusher %#v", w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := p.Dial(ctx, "tcp", ln.Addr().String()); err == nil {
		c.Close()
		t.Fatal("a dial bound to an interface that does not exist reached the address")
	}
}

// fakeUID has run see uid as its user id until the test ends.
func fakeUID(t *testing.T, uid int) {
	old := getuid
	getuid = func() int { return uid }
	t.Cleanup(func() { getuid = old })
}

// run refuses a missing -state, root, and a state directory others can
// read, before it reads or makes any key.
func TestRunRefuses(t *testing.T) {
	fakeUID(t, 1000)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "-state is required") {
		t.Fatalf("no -state: %v", err)
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-state", open, "-ap-pub"}); !errors.Is(err, errStateDir) {
		t.Fatalf("a state directory others can read: %v", err)
	}
	fakeUID(t, 0)
	if err := run([]string{"-state", dir, "-ap-pub"}); err == nil || !strings.Contains(err.Error(), "refusing to run as root") {
		t.Fatalf("as root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileAPSSH)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused run made a key: %v", err)
	}
}

// -ap-pub prints the key the enforcer logs in to the access points with,
// as one authorized_keys line, and exits.
func TestRunAPPubPrintsTheKey(t *testing.T) {
	fakeUID(t, 1000)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	err = run([]string{"-state", dir, "-ap-pub"})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatalf("-ap-pub: %v", err)
	}
	s, err := apSSHKey(fileStore{path: filepath.Join(dir, fileAPSSH)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizedKey(s) + "\n"; string(out) != want {
		t.Fatalf("-ap-pub printed %q, want the saved key %q", out, want)
	}
}

// rawConn is a socket whose Control fails, as a closed one's does, or
// runs f on fd.
type rawConn struct {
	err error
	fd  uintptr
}

func (c rawConn) Control(f func(uintptr)) error {
	if c.err == nil {
		f(c.fd)
	}
	return c.err
}
func (rawConn) Read(func(uintptr) bool) error  { return errors.New("unused") }
func (rawConn) Write(func(uintptr) bool) error { return errors.New("unused") }

// ENF-g-8: the dialer refuses a socket it cannot reach or bind, rather
// than dialling from whatever interface routing picks.
func TestBindToRefuses(t *testing.T) {
	closed := errors.New("use of closed file")
	if err := bindTo("eth9")("tcp", "10.70.0.2:22", rawConn{err: closed}); !errors.Is(err, closed) {
		t.Fatalf("a socket Control cannot reach: %v", err)
	}
	if err := bindTo("eth9")("tcp", "10.70.0.2:22", rawConn{fd: ^uintptr(0)}); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("a bind that failed: %v", err)
	}
}

// NET-4: enrolment waits for every access point longer than one push may
// take (push.Pusher's default bound, 30 seconds), so a slow but working
// access point is not taken for a failed one.
func TestOpenAPWaitsPastOnePush(t *testing.T) {
	x := newBox(t, false)
	if w := x.d.ap.wait; w <= 30*time.Second {
		t.Fatalf("enrolment waits %v for the access points, no longer than one push", w)
	}
}

// NET-4: a failure making the four passwords fails the hand-over before
// anything is saved or pushed, and leaves the access points usable.
func TestReplaceRefusesAFailedEnrol(t *testing.T) {
	x := newBox(t, false)
	n := x.d.ap
	fail := errors.New("two passwords alike")
	n.mu.Lock()
	n.enrol = func(*ap.Keys) error { return fail }
	n.mu.Unlock()
	if _, err := n.Replace(); !errors.Is(err, fail) {
		t.Fatalf("Replace with a failed Enrol: %v", err)
	}
	done := make(chan bool, 1)
	go func() { done <- n.Replaced() }()
	select {
	case r := <-done:
		if r {
			t.Fatal("a failed Enrol replaced the setup network")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Replace kept the lock after a failed Enrol")
	}
	n.mu.Lock()
	enrolled, replacing := n.st.Keys.Enrolled(), n.replacing
	n.mu.Unlock()
	if enrolled || replacing {
		t.Fatalf("a failed Enrol left keys enrolled %v, a hand-over running %v", enrolled, replacing)
	}
}

// NET-4: a policy whose device passwords could not be synced is synced
// again on the next push, not taken as done.
func TestFilesRetriesARefusedSync(t *testing.T) {
	x, _ := enrolled(t, false)
	n := x.d.ap
	waitFor(t, func() bool { return x.apKeys().Device["tv"].Password != "" })
	n.mu.Lock()
	good := n.st
	good.Keys = cloneKeys(n.st.Keys)
	n.st.Keys = ap.Keys{Setup: good.Keys.Setup}
	n.hash = ""
	n.mu.Unlock()
	if _, files, err := n.files(); err == nil || files != nil {
		t.Fatalf("a sync that failed gave %d files, %v", len(files), err)
	}
	n.mu.Lock()
	delete(good.Keys.Device, "tv")
	n.st = good
	n.mu.Unlock()
	if _, _, err := n.files(); err != nil {
		t.Fatalf("the sync was not retried: %v", err)
	}
	n.mu.Lock()
	pw := n.st.Keys.Device["tv"].Password
	n.mu.Unlock()
	if pw == "" {
		t.Fatal("the tv was given no password on the retry")
	}
}
