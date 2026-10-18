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
// It prints no claim code, card value, recovery key, code-generator seed,
// text message or page body: details are status codes, locations, page
// headings and reply kinds.
package main

import (
	"bytes"
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
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
)

const (
	box       = "http://10.42.0.1"
	netns     = "e2e-phone"
	sysroot   = "/run/agentos-e2e-sysroot"
	claimDst  = "/var/lib/agentos-localui/claim.json"
	cardLatch = "/var/lib/agentos-localui/card-latch.json"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "seal" {
		if err := seal(); err != nil {
			fmt.Println("agentos-e2e: FAIL seal " + oneLine(err.Error()))
			os.Exit(1)
		}
		return
	}
	r := newReport(os.Stdout, xfail)
	d := &driver{carrier: modem.NewCarrier(), note: r.note}
	r.step("harness", d.harness)
	r.step("claim", d.claim)
	r.step("sms-pair", d.smsPair)
	r.step("codes", d.codes)
	r.step("card", d.card)
	r.step("recovery", d.recovery)
	r.step("host", d.host)
	r.step("guest-task", d.guestTask)
	r.step("phone-control", d.phoneControl)
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
	// codeStep is the last 30-second code window the driver used: the box
	// takes each window's code once (CH-14).
	codeStep int64
	// stub is the Codex plan provider the agentos_e2e vault process
	// reaches (#1701, ASSUMPTIONS E10).
	stub *codexstub.Stub
	// guestSock is the agent machine's guest-plane socket; "" is the
	// box's (agentSock).
	guestSock string
	// agentosdArgv is agentosd's command line; nil reads the unit's.
	agentosdArgv func() ([]string, error)
	// agentosdLog is agentosd's journal this boot; nil reads the unit's.
	agentosdLog func() string
	// runscLog is agentosd's runsc exec log, where a machine's failed
	// start leaves runsc's message; nil reads the box's.
	runscLog func() string
	// signInOut is the sign-in CLI's output file in a live provider
	// worker's layer, "" for none; nil reads the box's (signInOutFile).
	signInOut func() string
	// runOut is a provider run's result file in a live provider worker's
	// layer, "" for none; nil reads the box's (runOutFile).
	runOut func() string
	// now and sleep are the clock of the codes and of phone-control's
	// waits; nil is the wall clock. The in-process test shares a fake one
	// with the owner channel.
	now   func() time.Time
	sleep func(time.Duration)
	// note prints a non-failing line under the running step; nil prints
	// nothing.
	note func(string)
}

// childEnv is every child's whole environment: systemd's own PATH for
// the system tools the driver runs (ip, systemctl, journalctl).
var childEnv = childproc.NewEnv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

func command(name string, args ...string) *childproc.Cmd {
	return childproc.Command(context.Background(), childEnv, childproc.Options{}, name, args...)
}

func run(name string, args ...string) error {
	out, err := command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, oneLine(string(out)))
	}
	return nil
}

// harness puts the phone on the box's Wi-Fi: a veth pair whose box end is
// wlan0 at the access point's address, its other end in the phone's
// namespace, and wlan0 in the inbound exempt set as ap-exempt would add it.
// QEMU has no radio, so agentos-ap is stopped first. It also serves the
// Codex plan stub and checks the vault process is the build that reaches it.
func (d *driver) harness() error {
	if err := checkVaultBuild(); err != nil {
		return err
	}
	stub, err := serveStub()
	if err != nil {
		return fmt.Errorf("plan stub: %v", err)
	}
	d.stub = stub
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

// codeFile carries the claim code from the seal run to the claim step:
// root's only, on the boot's tmpfs, removed once read.
const codeFile = "/run/agentos-e2e/claim-code"

// seal runs before the setup page's first start (agentos-e2e-seal.service):
// it seals a fresh claim code where a preloaded box keeps it, as the
// seller does before the box ships, so agentos-localui-claim.service
// moves it in before the page's first start and the box boots as a
// preloaded one.
func seal() error {
	code, err := claim.NewCode(rand.Reader)
	if err != nil {
		return err
	}
	if err := claim.Seal(change.FileStore{Path: claim.StatePath}, code, rand.Reader, func(string) {}); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	return os.WriteFile(codeFile, []byte(code), 0o600)
}

// claim claims the box from the phone with the code sealed before boot.
func (d *driver) claim() error {
	b, err := os.ReadFile(codeFile)
	if err != nil {
		return fmt.Errorf("the seal run left no claim code: %w", err)
	}
	if err := os.Remove(codeFile); err != nil {
		return err
	}
	code := string(b)
	if err := until(2*time.Minute, func() (bool, error) {
		st, loc, _, err := d.get("/")
		if err != nil {
			return false, err
		}
		return st == http.StatusSeeOther && loc == "/claim", fmt.Errorf("GET / %d %q", st, loc)
	}); err != nil {
		return fmt.Errorf("%w; %s", err, claimDiag(code))
	}
	st, loc, err := d.post("/claim", url.Values{"code": {code}})
	if err != nil {
		return err
	}
	if st != http.StatusSeeOther || (loc != "/setup" && loc != "/claim/wifi") {
		return fmt.Errorf("POST /claim %d %q", st, loc)
	}
	if loc == "/claim/wifi" {
		if err := d.claimWiFi(); err != nil {
			return err
		}
	}
	if ok, err := claim.Claimed(change.FileStore{Path: claimDst}); err != nil || !ok {
		return fmt.Errorf("claim state after the claim: claimed=%v err=%v", ok, err)
	}
	return nil
}

// claimWiFi takes the claim's Wi-Fi step (HW-10) as an owner does: save
// the new password the page shows, type its last four characters back,
// and switch. The box's setup network may restart; the phone reaches the
// page over the uplink, so setup carries on.
func (d *driver) claimWiFi() error {
	st, _, b, err := d.get("/claim/wifi")
	if err != nil {
		return err
	}
	pw, ok := wifiPassword(b)
	if st != http.StatusOK || !ok || len(pw) < 4 {
		return fmt.Errorf("GET /claim/wifi %d shows no new password: %s", st, heading(b))
	}
	st, loc, err := d.post("/claim/wifi", url.Values{"last": {pw[len(pw)-4:]}})
	if err != nil {
		return err
	}
	if st != http.StatusOK && (st != http.StatusSeeOther || loc != "/setup") {
		return fmt.Errorf("POST /claim/wifi %d %q", st, loc)
	}
	if st, loc, _, err := d.get("/setup"); err != nil || st == http.StatusSeeOther && loc == "/claim/wifi" {
		return fmt.Errorf("setup still waits on the Wi-Fi step: GET /setup %d %q %v", st, loc, err)
	}
	return nil
}

// claimDiag says why the page shows no claim screen: where the sealed
// claim state is, the page's unit state, and its last log lines, with
// the claim code cut out.
func claimDiag(code string) string {
	where := func(p string) string {
		if _, err := os.Lstat(p); err != nil {
			return "absent"
		}
		return "present"
	}
	unit, _ := command("systemctl", "show", "agentos-localui.service",
		"-p", "ActiveState,SubState,NRestarts,Result", "--value").Output()
	hand, _ := command("systemctl", "show", "agentos-localui-claim.service",
		"-p", "ActiveState,Result,ConditionResult", "--value").Output()
	logs, _ := command("journalctl", "-b", "-o", "cat", "--no-pager", "-n", "20",
		"-u", "agentos-localui-claim.service", "-u", "agentos-localui.service",
		"-u", "agentosd.service", "-u", "agentos-egress.service").Output()
	return fmt.Sprintf("diag: sealed=%s moved=%s hand-over=%s unit=%s log: %s", where(claim.StatePath),
		where(claimDst), oneLine(string(hand)), oneLine(string(unit)),
		redactLog(string(logs), 12, code, claim.Normalize(code)))
}

// modemDiag says why setup cannot text: the bridge's and agentosd's unit
// states and their last log lines. The pairing code is not known yet, and
// the numbers and SIM serial are the simulator's synthetic ones.
func modemDiag() string {
	units, _ := command("systemctl", "show", "agentos-modem.service", "agentosd.service",
		"-p", "ActiveState,SubState,NRestarts,Result", "--value").Output()
	logs, _ := command("journalctl", "-b", "-o", "cat", "--no-pager", "-n", "20",
		"-u", "agentos-modem.service", "-u", "agentosd.service").Output()
	return fmt.Sprintf("diag: units=%s log: %s", oneLine(string(units)), redactLog(string(logs), 12))
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
	u, err := user.Lookup("agentos-modem")
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(u.Uid)
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
	var last []byte
	tookNetwork := false
	if err := until(3*time.Minute, func() (bool, error) {
		b, err := d.page()
		if err != nil {
			return false, err
		}
		last = b
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
		return fmt.Errorf("%w; line=%s %s", err, lineState(last), modemDiag())
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
	st, _, err := d.post("/setup/codes", url.Values{"code": {d.freshCode()}})
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
	if err != nil {
		logs, _ := command("journalctl", "-b", "-o", "cat", "--no-pager",
			"-u", "agentos-localui.service").Output()
		if cause := hostCause(string(logs)); cause != "" {
			err = fmt.Errorf("%w: %s", err, cause)
		}
	}
	return err
}

// guestTask is the model-backed guest task on the Codex plan route. It
// first signs in to the plan at step 7, which finishes setup, then runs
// one task through provider_run as the agent machine's guest
// (providerTask, ASSUMPTIONS E12).
func (d *driver) guestTask() error {
	if err := d.planSignIn(); err != nil {
		return err
	}
	return d.providerTask()
}

// signInDiag says why the sign-in did not start: agentosd's setup and
// provagent journal lines, where StartSignIn logs the step that refused it
// (#1701), the end of runsc's exec log, where a worker's failed start
// leaves runsc's message, and the end of out, what the sign-in CLI and
// its forwarder printed (watchSignIn), each cut short with the stub's
// tokens cut out (ASSUMPTIONS E8, E13).
func (d *driver) signInDiag(out string) string {
	return d.workerDiag("sign-in output", out)
}

// workerDiag is signInDiag with out, a provider worker's output, quoted
// under the name what.
func (d *driver) workerDiag(what, out string) string {
	read := d.agentosdLog
	if read == nil {
		read = func() string {
			out, _ := command("journalctl", "-b", "-o", "cat", "--no-pager", "-u", "agentosd.service").Output()
			return string(out)
		}
	}
	var keep []string
	for _, l := range strings.Split(read(), "\n") {
		if strings.Contains(l, "setup: ") || strings.Contains(l, "provagent: ") {
			keep = append(keep, l)
		}
	}
	var tokens []string
	if d.stub != nil {
		tokens = d.stub.Tokens()
	}
	secrets := append(tokens, codexstub.Canary)
	runsc := d.runscLog
	if runsc == nil {
		runsc = func() string {
			argv := d.agentosdArgv
			if argv == nil {
				argv = unitArgv
			}
			args, _ := argv()
			b, _ := os.ReadFile(execLogPath(args))
			return string(b)
		}
	}
	return "diag: agentosd: " + redactLog(chunked(strings.Join(keep, "\n"), secrets), 8, secrets...) +
		"; runsc: " + redactLog(chunked(runsc(), secrets), 8, secrets...) +
		"; " + what + ": " + redactLog(chunked(ansiSeq.ReplaceAllString(out, ""), secrets), 6, secrets...)
}

// ansiSeq is a terminal escape sequence, cut from the CLI's output.
var ansiSeq = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")

// signInWatch keeps the last thing a sign-in worker's output file held.
// agentosd destroys the worker, and the file with it, as soon as its CLI
// exits without a code, and logs only the exit status (CRED-5); this
// driver is root on the box, so it reads the file from the worker's layer
// on the host while the sign-in runs (ASSUMPTIONS E13).
type signInWatch struct {
	mu   sync.Mutex
	last string
	end  chan struct{}
	done chan struct{}
}

// watchSignIn reads the sign-in output every 50ms until stop.
func (d *driver) watchSignIn() *signInWatch {
	return d.watchWorker(d.signInOut, ".agentos-signin")
}

// watchRun reads a provider run's result file every 50ms until stop: the
// CLI's JSON events, which say why a run failed, and which agentosd
// destroys with the worker (ASSUMPTIONS E14).
func (d *driver) watchRun() *signInWatch {
	return d.watchWorker(d.runOut, filepath.Base(provagent.Builtins()[egress.Codex().Provider].ResultPath))
}

// watchWorker reads read, or else the file name in the newest provider
// worker's workspace, every 50ms until stop.
func (d *driver) watchWorker(read func() string, name string) *signInWatch {
	if read == nil {
		argv := d.agentosdArgv
		if argv == nil {
			argv = unitArgv
		}
		args, _ := argv()
		dir := machinesDir(args)
		read = func() string { return workerOutFile(dir, name) }
	}
	w := &signInWatch{end: make(chan struct{}), done: make(chan struct{})}
	poll := func() {
		if s := read(); s != "" {
			w.mu.Lock()
			w.last = s
			w.mu.Unlock()
		}
	}
	go func() {
		defer close(w.done)
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			poll()
			select {
			case <-w.end:
				return
			case <-t.C:
			}
		}
	}()
	return w
}

// stop ends the watch and returns the last output read.
func (w *signInWatch) stop() string {
	close(w.end)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// signInOutMax is how much of the output file is read.
const signInOutMax = 64 << 10

// signInOutFile is the sign-in output file of the newest provider worker
// under the machines directory, at its end, "" for none: the worker's
// guest writes land in its overlay's upper layer (vm Manager.diskDir).
func signInOutFile(machines string) string {
	return workerOutFile(machines, ".agentos-signin")
}

// workerOutFile is file name in the workspace of the newest provider
// worker under the machines directory, at its end, "" for none.
func workerOutFile(machines, name string) string {
	cwd := provagent.Builtins()[egress.Codex().Provider].Cwd
	paths, _ := filepath.Glob(filepath.Join(machines, "machines", vm.ProviderPrefix+"*", "disk", "upper", cwd, name))
	var best string
	var at time.Time
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && !fi.ModTime().Before(at) {
			best, at = p, fi.ModTime()
		}
	}
	if best == "" {
		return ""
	}
	f, err := os.Open(best)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > signInOutMax {
		f.Seek(fi.Size()-signInOutMax, io.SeekStart)
	}
	b, _ := io.ReadAll(io.LimitReader(f, signInOutMax))
	return string(b)
}

// execLogPath is runsc's exec log under agentosd's -machines directory
// (gvisor.Runtime's StateDir is its runsc subdirectory), the flag's
// default when args set none.
func execLogPath(args []string) string {
	return filepath.Join(machinesDir(args), "runsc", "exec.log")
}

// machinesDir is agentosd's -machines directory, the flag's default when
// args set none.
func machinesDir(args []string) string {
	dir := "/var/lib/agentos/machines"
	for i, a := range args {
		v, ok := strings.CutPrefix(strings.TrimLeft(a, "-"), "machines=")
		if !ok && strings.TrimLeft(a, "-") == "machines" && i+1 < len(args) {
			v, ok = args[i+1], true
		}
		if ok {
			dir = v
		}
	}
	return dir
}

// chunked is log with secrets cut out and each line split into
// logLineMax pieces, so redactLog's cut keeps a long runsc message whole.
func chunked(log string, secrets []string) string {
	for _, s := range secrets {
		if s != "" {
			log = strings.ReplaceAll(log, s, "[redacted]")
		}
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		for len(l) > logLineMax {
			out, l = append(out, l[:logLineMax]), l[logLineMax:]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// planSignIn is the owner signing in to the Codex plan at step 7, as the
// page offers it once agentosd serves the device-code sign-in (#1264): the
// owner ticks private content, presses sign in, opens the link the page
// shows on the provider's own host and enters its code there (the stub's
// Approve), then reloads until setup finishes. The provider's tokens reach
// only the stub; no page the phone sees may show one (ASSUMPTIONS E11).
func (d *driver) planSignIn() error {
	route := egress.Codex()
	// pages is every page the phone saw after the post, by request, so a
	// token on one names where it showed.
	type seen struct {
		req  string
		body []byte
	}
	var pages []seen
	var pg []byte
	err := until(2*time.Minute, func() (bool, error) {
		var err error
		if pg, err = d.page(); err != nil {
			return false, err
		}
		return bytes.Contains(pg, []byte(aiOpen)), errors.New(where(pg))
	})
	// aiOpen is on step 7 whenever the first-boot update has finished,
	// whatever providers it lists, so a timeout here means step 7 never
	// opened or the page kept failing: a product failure, not XFAIL.
	if err != nil {
		return fmt.Errorf("step 7 did not open: %w", err)
	}
	if !deviceOffer(pg, route.Provider) {
		return errors.New(notDriven + " step 7 offers no " + route.Provider + " sign-in (#1264; gate: #809, #1877; image: #1721) " + where(pg))
	}
	if d.stub == nil {
		return errors.New("no plan stub")
	}
	form := url.Values{"provider": {route.Provider}, "private": {"1"}}
	w := d.watchSignIn()
	st, _, err := d.post("/setup/ai-device", form)
	out := w.stop()
	if err != nil || st != http.StatusSeeOther {
		return fmt.Errorf("POST /setup/ai-device %d %v", st, err)
	}
	if pg, err = d.page(); err != nil {
		return err
	}
	pages = append(pages, seen{"GET /setup after POST /setup/ai-device", pg})
	link, code, ok := deviceLink(pg)
	if !ok {
		// The sign-in runs the CLI in a worker built from the provider's
		// image; a box that registers none cannot start it (#1721), the
		// case where #809 and #1877 land first (ASSUMPTIONS E11).
		image := provagent.Builtins()[route.Provider].Image
		if has, err := d.hasImage(image); err == nil && !has {
			return errors.New(notDriven + " step 7's " + route.Provider + " sign-in cannot start: agentosd registers no " + image + " image (#1721) " + where(pg))
		}
		return errors.New("no sign-in link after sign in " + where(pg) + "; " + d.signInDiag(out))
	}
	if want := "https://" + route.AuthHost + route.DevicePage; link != want {
		// The host alone is safe to print; the rest may carry the code.
		host := "an unparsable link"
		if u, err := url.Parse(link); err == nil {
			host = fmt.Sprintf("host %q", u.Host)
		}
		return fmt.Errorf("the sign-in link is not %s: the page showed %s", want, host)
	}
	if !bytes.Contains(pg, []byte("This code is from OpenAI")) {
		return errors.New("the sign-in link does not name its provider " + where(pg))
	}
	if !d.stub.Approve(code) {
		return errors.New("the code on the page is not the provider's")
	}
	reloads := 0
	err = until(2*time.Minute, func() (bool, error) {
		st, loc, b, err := d.get("/setup")
		if err != nil {
			return false, err
		}
		reloads++
		pages = append(pages, seen{fmt.Sprintf("GET /setup reload %d", reloads), b})
		if st == http.StatusSeeOther && loc == "/status" {
			return true, nil
		}
		return false, fmt.Errorf("GET /setup %d %q %s", st, loc, where(b))
	})
	if err != nil {
		return fmt.Errorf("sign-in did not finish setup: %w (stub %v refused %d)", err, d.stub.Hits(), d.stub.Refused())
	}
	st, _, b, err := d.get("/status")
	if err != nil || st != http.StatusOK {
		return fmt.Errorf("GET /status %d %v", st, err)
	}
	pages = append(pages, seen{"GET /status", b})
	if n := d.stub.Refused(); n != 0 {
		return fmt.Errorf("the provider refused %d calls on the plan route: stub %v", n, d.stub.Hits())
	}
	if d.stub.Hits()["code"] == 0 {
		return fmt.Errorf("sign-in skipped the provider: stub %v", d.stub.Hits())
	}
	for _, p := range pages {
		if bytes.Contains(p.body, []byte(codexstub.Canary)) {
			return errors.New("a page showed a provider token: " + p.req)
		}
	}
	return nil
}

// phoneControl is the owner texting the box after setup (CH-1, CH-3,
// CH-14; E9). It first checks that setup has finished, since agentosd
// answers texts only then. The paired phone texts HELP, which needs no
// code, until it is answered; then one STATUS with a code from a window
// not used before, which must draw the unlock and then the status reply.
// Only then does the unpaired number text STATUS with a fresh code, and
// the paired phone texts HELP again as a barrier. Texts are handled in
// arrival order, but replies are not sent in that order: STATUS and HELP
// are run routes, each answered from its own goroutine, so a reply the
// stranger's text drew can land after the barrier's. Once the barrier is
// answered the stranger's text has been handled, and the step keeps
// reading the log for settle; any reply to either number then fails it.
// Probing with HELP first means the code is sent only once texts are
// read: a code left unread goes stale, and a stale code is a wrong one
// that counts toward CH-11's lockout.
func (d *driver) phoneControl() error {
	if d.seed == nil {
		return errors.New("no code generator seed")
	}
	st, loc, b, err := d.get("/setup")
	if err != nil {
		return fmt.Errorf("setup not finished: GET /setup: %w", err)
	}
	if st != http.StatusSeeOther || loc != "/status" {
		return fmt.Errorf("setup not finished: GET /setup %d %q at %s", st, loc, heading(b))
	}
	start := len(d.carrier.Log())
	defer func() {
		// The notices the step passed over, pass or fail (#2170).
		if n := readPhoneRun(d.carrier.Log(), start).noticeNote(); n != "" && d.note != nil {
			d.note(n)
		}
	}()
	phone := d.carrier.Line(phoneNum)
	// agentosd takes the modem from setup's line only after setup
	// finishes, and the hand-over can lose texts: after setup the bridge
	// has no OWNER_NUMBER, so the owner's texts are offered once and one
	// refused meanwhile is gone (BOARD P2-2w c4c r1; bridge B9). So HELP
	// repeats until answered, and a timeout names the attempts.
	deadline := d.clock().Add(3 * time.Minute)
	for attempts := 1; ; attempts++ {
		if err := phone.Send(boxNum, "HELP"); err != nil {
			return fmt.Errorf("phone send: %w", err)
		}
		r := d.await(start, 45*time.Second, func(r phoneRun) bool { return r.probed })
		if err := r.failed(); err != nil {
			return err
		}
		if r.probed {
			break
		}
		if !d.clock().Before(deadline) {
			return fmt.Errorf("no reply to the paired number after %d HELP attempts (BOARD P2-2w c4c r1, the bridge's hand-over from setup); %s",
				attempts, modemDiag())
		}
	}
	if err := phone.Send(boxNum, "STATUS "+d.freshCode()); err != nil {
		return fmt.Errorf("phone send: %w", err)
	}
	r := d.await(start, time.Minute, func(r phoneRun) bool { return r.status })
	if err := r.failed(); err != nil {
		return err
	}
	if !r.status {
		return fmt.Errorf("%w; %s", controlErr(d.carrier.Log(), start), modemDiag())
	}
	if err := d.carrier.Line(strangerNum).Send(boxNum, "STATUS "+d.freshCode()); err != nil {
		return fmt.Errorf("stranger send: %w", err)
	}
	if err := phone.Send(boxNum, "HELP"); err != nil {
		return fmt.Errorf("phone send: %w", err)
	}
	r = d.await(start, time.Minute, func(r phoneRun) bool { return r.barrier })
	if err := r.failed(); err != nil {
		return err
	}
	if !r.barrier {
		return fmt.Errorf("%w; %s", controlErr(d.carrier.Log(), start), modemDiag())
	}
	// A reply drawn by the stranger's text may still be on its way: the
	// box gives no point after which its run routes have all replied, so
	// the log is read until settle has passed (await returns early on a
	// failure).
	d.await(start, settle, func(phoneRun) bool { return false })
	return controlErr(d.carrier.Log(), start)
}

// settle is how long phoneControl keeps reading the log after the
// barrier's reply. The stranger's text was handled before the barrier's,
// and STATUS and HELP are answered from memory with no model or network
// call, so their replies start within milliseconds of each other; the
// rest is the modem's send and the carrier's delivery, which the step
// already waits on for the barrier's reply. 15 seconds covers that many
// times over while adding little to a step that allows minutes per stage.
const settle = 15 * time.Second

// await reads the log from start each second, for up to limit, until done
// holds or the run has failed, and returns what it read last.
func (d *driver) await(start int, limit time.Duration, done func(phoneRun) bool) phoneRun {
	end := d.clock().Add(limit)
	for {
		r := readPhoneRun(d.carrier.Log(), start)
		if r.failed() != nil || done(r) || !d.clock().Before(end) {
			return r
		}
		d.pause(time.Second)
	}
}

// freshCode is the code the phone's app shows now, from a window the
// driver has not used, waiting for the next window when it has.
func (d *driver) freshCode() string {
	for d.clock().Unix()/30 <= d.codeStep {
		d.pause(time.Second)
	}
	now := d.clock()
	d.codeStep = now.Unix() / 30
	return owner.TOTP(d.seed, now)
}

func (d *driver) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func (d *driver) pause(t time.Duration) {
	if d.sleep != nil {
		d.sleep(t)
		return
	}
	time.Sleep(t)
}
