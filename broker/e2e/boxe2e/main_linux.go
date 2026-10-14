// Command box-e2e drives the box's first-boot setup inside the booted image,
// as an owner's phone does (#1688): it claims the box, pairs a phone by SMS
// through a simulated modem, enrolls the code generator, confirms the Owner
// Card, and goes on through setup. image/ci_boot.sh injects it with a
// one-shot unit and reads its console lines (report.go).
//
// It changes the booted system only in ways a test VM allows: a veth pair
// stands in for the access point's wlan0 with the phone in its own network
// namespace, and agentos-modem is pointed (by a drop-in from ci_boot.sh) at
// a sysfs tree whose AT port is a pseudo-terminal behind the AT simulator.
// It prints no claim code, card value, recovery key, code-generator seed or
// page body: details are status codes, locations and page headings.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// xfail names the steps known not to pass yet, each with its work-item
// issue. A listed step that passes fails the run (XPASS), so the list
// shrinks as the issues close.
var xfail = map[string]int{"guest-task": 1701}

const (
	box       = "http://10.42.0.1"
	netns     = "e2e-phone"
	sysroot   = "/run/agentos-e2e/sysroot"
	claimDst  = "/var/lib/agentos-localui/claim.json"
	cardLatch = "/var/lib/agentos-localui/card-latch.json"
)

func main() {
	r := newReport(os.Stdout, xfail)
	d := &driver{carrier: modem.NewCarrier()}
	r.step("harness", d.harness)
	r.step("claim", d.claim)
	r.step("sms-pair", d.smsPair)
	r.step("codes", d.codes)
	r.step("card", d.card)
	r.step("recovery", d.recovery)
	r.step("host", d.host)
	r.step("guest-task", d.guestTask)
	r.done()
	if d.modem != nil {
		d.modem.Close()
	}
	if r.failed() {
		os.Exit(1)
	}
}

type driver struct {
	carrier *modem.Carrier
	phone   *http.Client
	modem   *pluggedModem
	seed    []byte
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, oneLine(string(out)))
	}
	return nil
}

// harness puts the phone on the box's Wi-Fi: a veth pair whose box end is
// wlan0 at the access point's address, its other end in the phone's
// namespace, and wlan0 in the inbound exempt set as ap-exempt would add it.
// QEMU has no radio, so agentos-ap is stopped first.
func (d *driver) harness() error {
	for _, c := range [][]string{
		{"systemctl", "stop", "agentos-ap.service"},
		{"ip", "netns", "add", netns},
		{"ip", "link", "add", "wlan0", "type", "veth", "peer", "name", "phone0", "netns", netns},
		{"ip", "addr", "add", "10.42.0.1/24", "dev", "wlan0"},
		{"ip", "link", "set", "wlan0", "up"},
		{"ip", "-n", netns, "addr", "add", "10.42.0.23/24", "dev", "phone0"},
		{"ip", "-n", netns, "link", "set", "phone0", "up"},
		{"ip", "-n", netns, "link", "set", "lo", "up"},
		{"nft", "add", "element", "inet", "agentos_inbound", "exempt", `{ "wlan0" }`},
	} {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	dial, err := nsDialer("/run/netns/" + netns)
	if err != nil {
		return err
	}
	jar, _ := cookiejar.New(nil)
	d.phone = &http.Client{
		Jar:           jar,
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: dial, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

// nsDialer dials from the given network namespace: one locked thread
// enters it and makes every connection. The thread is never unlocked, so
// it ends with the process rather than going back to the scheduler.
func nsDialer(path string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	type req struct {
		ctx           context.Context
		network, addr string
		out           chan net.Conn
		errc          chan error
	}
	reqs := make(chan req)
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			err = unix.Setns(fd, unix.CLONE_NEWNET)
			unix.Close(fd)
		}
		ready <- err
		if err != nil {
			return
		}
		for q := range reqs {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(q.ctx, q.network, q.addr)
			if err != nil {
				q.errc <- err
				continue
			}
			q.out <- c
		}
	}()
	if err := <-ready; err != nil {
		return nil, fmt.Errorf("enter %s: %w", path, err)
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		q := req{ctx, network, addr, make(chan net.Conn, 1), make(chan error, 1)}
		reqs <- q
		select {
		case c := <-q.out:
			return c, nil
		case err := <-q.errc:
			return nil, err
		}
	}, nil
}

// get fetches a page as the phone. The body is for parsing only.
func (d *driver) get(path string) (int, string, []byte, error) {
	req, _ := http.NewRequest("GET", box+path, nil)
	return d.do(req)
}

func (d *driver) post(path string, form url.Values) (int, string, error) {
	req, _ := http.NewRequest("POST", box+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	code, loc, _, err := d.do(req)
	return code, loc, err
}

func (d *driver) do(req *http.Request) (int, string, []byte, error) {
	req.Header.Set("Origin", box)
	resp, err := d.phone.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, resp.Header.Get("Location"), b, err
}

// until polls f until it reports done, or returns its last error.
func until(limit time.Duration, f func() (bool, error)) error {
	end := time.Now().Add(limit)
	for {
		ok, err := f()
		if ok {
			return nil
		}
		if time.Now().After(end) {
			if err == nil {
				err = errors.New("timed out")
			}
			return fmt.Errorf("after %s: %w", limit, err)
		}
		time.Sleep(time.Second)
	}
}

// claim seals a fresh claim code where a preloaded box keeps it, as the
// seller does, restarts the page so localui-claim moves it in, and claims
// the box with it from the phone.
func (d *driver) claim() error {
	code, err := claim.NewCode(rand.Reader)
	if err != nil {
		return err
	}
	if err := run("systemctl", "stop", "agentos-localui.service"); err != nil {
		return err
	}
	if err := claim.Seal(change.FileStore{Path: claim.StatePath}, code, rand.Reader, func(string) {}); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	if err := run("systemctl", "start", "agentos-localui.service"); err != nil {
		return err
	}
	if err := until(2*time.Minute, func() (bool, error) {
		st, loc, _, err := d.get("/")
		if err != nil {
			return false, err
		}
		return st == http.StatusSeeOther && loc == "/claim", fmt.Errorf("GET / %d %q", st, loc)
	}); err != nil {
		return err
	}
	st, loc, err := d.post("/claim", url.Values{"code": {code}})
	if err != nil {
		return err
	}
	if st != http.StatusSeeOther || loc != "/setup" {
		return fmt.Errorf("POST /claim %d %q", st, loc)
	}
	if ok, err := claim.Claimed(change.FileStore{Path: claimDst}); err != nil || !ok {
		return fmt.Errorf("claim state after the claim: claimed=%v err=%v", ok, err)
	}
	return nil
}

// page is the phone's view of /setup now.
func (d *driver) page() ([]byte, error) {
	st, loc, b, err := d.get("/setup")
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("GET /setup %d %q", st, loc)
	}
	return b, nil
}

var errRe = regexp.MustCompile(`(?s)<p class="err">(.*?)</p>`)

// where names the page for a failure: its heading and any error it shows.
func where(page []byte) string {
	s := "at " + heading(page)
	if m := errRe.FindSubmatch(page); m != nil {
		s += " saying " + heading([]byte("<h1>"+string(m[1])+"</h1>"))
	}
	return s
}

// waitStep polls /setup until its numbered step starts with n.
func (d *driver) waitStep(n string, limit time.Duration) ([]byte, error) {
	var b []byte
	err := until(limit, func() (bool, error) {
		var err error
		if b, err = d.page(); err != nil {
			return false, err
		}
		return strings.HasPrefix(heading(b), `"`+n+". "), errors.New(where(b))
	})
	return b, err
}

// smsPair plugs the simulated modem in, waits for the text-your-box step
// (taking the network step over Ethernet if the box asks), texts PAIR from
// the phone's line, and waits for the box's reply and the next step.
func (d *driver) smsPair() error {
	uid, err := exec.Command("id", "-u", "agentos-modem").Output()
	if err != nil {
		return fmt.Errorf("id -u agentos-modem: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(uid)))
	if err != nil {
		return err
	}
	if d.modem, err = plugModem(d.carrier, n); err != nil {
		return fmt.Errorf("plug modem: %w", err)
	}
	if err := buildSysroot(sysroot, d.modem.Slave); err != nil {
		return err
	}
	if err := run("systemctl", "restart", "agentos-modem.service"); err != nil {
		return err
	}
	phone := d.carrier.Line(phoneNum)
	var num, code string
	tookNetwork := false
	if err := until(3*time.Minute, func() (bool, error) {
		b, err := d.page()
		if err != nil {
			return false, err
		}
		var ok bool
		if num, code, ok = smsLink(b); ok {
			return true, nil
		}
		if strings.HasPrefix(heading(b), `"1. `) && !tookNetwork {
			tookNetwork = true
			if st, _, err := d.post("/setup/network", url.Values{"ethernet": {"1"}}); err != nil || st != http.StatusSeeOther {
				return false, fmt.Errorf("POST /setup/network %d %v", st, err)
			}
		}
		return false, fmt.Errorf("no text link %s", where(b))
	}); err != nil {
		return err
	}
	if num != boxNum {
		return errors.New("the page shows a number other than the simulated SIM's")
	}
	if err := phone.Send(boxNum, "PAIR "+code); err != nil {
		return fmt.Errorf("phone send: %w", err)
	}
	select {
	case m := <-phone.Inbox():
		if m.From != boxNum {
			return errors.New("the reply came from another number")
		}
	case <-time.After(2 * time.Minute):
		return errors.New("no reply text reached the phone")
	}
	b, err := d.waitStep("3", 2*time.Minute)
	if err != nil {
		return err
	}
	if d.seed, err = otpSeed(b); err != nil {
		return err
	}
	return nil
}

// codes enrolls the code generator with the code the phone's app would
// show now.
func (d *driver) codes() error {
	if d.seed == nil {
		return errors.New("no code generator link was shown")
	}
	st, _, err := d.post("/setup/codes", url.Values{"code": {owner.TOTP(d.seed, time.Now())}})
	if err != nil || st != http.StatusSeeOther {
		return fmt.Errorf("POST /setup/codes %d %v", st, err)
	}
	_, err = d.waitStep("4", time.Minute)
	return err
}

// card saves the Owner Card, reads the asked word and group off it, and
// confirms, as the owner does from the printed card.
func (d *driver) card() error {
	st, _, sheet, err := d.get("/setup/card?save=1")
	if err != nil || st != http.StatusOK {
		return fmt.Errorf("GET card sheet %d %v", st, err)
	}
	pass, rec, err := sheetSecrets(sheet)
	if err != nil {
		return err
	}
	st, _, pg, err := d.get("/setup/card")
	if err != nil || st != http.StatusOK {
		return fmt.Errorf("GET card page %d %v", st, err)
	}
	wn, gn, err := promptAsks(pg)
	if err != nil {
		return err
	}
	w, g, err := answers(pass, rec, wn, gn)
	if err != nil {
		return err
	}
	st, loc, err := d.post("/setup/card", url.Values{"word": {w}, "group": {g}})
	if err != nil || st != http.StatusSeeOther {
		return fmt.Errorf("POST card confirm %d %q %v", st, loc, err)
	}
	b, err := os.ReadFile(cardLatch)
	if err != nil {
		return err
	}
	var latch struct {
		Confirmed bool `json:"card_confirmed"`
	}
	if err := json.Unmarshal(b, &latch); err != nil || !latch.Confirmed {
		return fmt.Errorf("card latch not confirmed (err %v)", err)
	}
	_, err = d.waitStep("5", time.Minute)
	return err
}

func (d *driver) recovery() error {
	st, _, err := d.post("/setup/recovery", url.Values{"stored": {"1"}})
	if err != nil || st != http.StatusSeeOther {
		return fmt.Errorf("POST /setup/recovery %d %v", st, err)
	}
	_, err = d.waitStep("6", time.Minute)
	return err
}

func (d *driver) host() error {
	st, _, err := d.post("/setup/host", url.Values{})
	if err != nil || st != http.StatusSeeOther {
		return fmt.Errorf("POST /setup/host %d %v", st, err)
	}
	_, err = d.waitStep("7", time.Minute)
	return err
}

// guestTask is the model-backed guest task. CI holds no model credential,
// so it needs a model stub at the provider boundary, which is not built
// yet.
func (d *driver) guestTask() error {
	return errors.New("not driven yet: needs a model stub at the provider boundary")
}
