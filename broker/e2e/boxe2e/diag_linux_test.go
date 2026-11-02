package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: HW-10, ONB-3. The console is a public CI log, so a diag quotes
// whole journal lines only from the units ASSUMPTIONS E8 names: the page,
// its claim move and the modem bridge. agentosd and the vault process hold
// what E8 never prints (G1-e2e-later #1740 item 2), so claimDiag and
// modemDiag give only their unit states, and journalTail refuses them.
func TestDiagsQuoteNoAgentosdOrVaultJournal(t *testing.T) {
	var calls [][]string
	defer func(o func(string, ...string) string) { output = o }(output)
	output = func(name string, args ...string) string {
		calls = append(calls, append([]string{name}, args...))
		if name == "journalctl" {
			return "a journal line\n"
		}
		return "active\nrunning\n"
	}
	journalUnits := func() (units []string) {
		for _, c := range calls {
			if c[0] != "journalctl" {
				continue
			}
			for i, a := range c {
				if a == "-u" && i+1 < len(c) {
					units = append(units, c[i+1])
				}
			}
		}
		return units
	}
	shown := func() (units []string) {
		for _, c := range calls {
			if c[0] == "systemctl" {
				for _, a := range c[1:] {
					if strings.HasSuffix(a, ".service") {
						units = append(units, a)
					}
				}
			}
		}
		return units
	}
	for _, tc := range []struct {
		name    string
		diag    func() string
		journal []string
		states  []string
	}{
		{"claim", func() string { return claimDiag("ABCD-EFGH") },
			[]string{"agentos-localui-claim.service", "agentos-localui.service"},
			[]string{"agentosd.service", "agentos-egress.service"}},
		{"modem", modemDiag, []string{"agentos-modem.service"}, []string{"agentosd.service"}},
	} {
		calls = nil
		got := tc.diag()
		if u := journalUnits(); !slices.Equal(u, tc.journal) {
			t.Errorf("%s diag quotes the journals of %v, want %v", tc.name, u, tc.journal)
		}
		for _, s := range tc.states {
			if !slices.Contains(shown(), s) {
				t.Errorf("%s diag does not give %s's unit state (shows %v)", tc.name, s, shown())
			}
		}
		if !strings.Contains(got, "a journal line") {
			t.Errorf("%s diag drops the quotable lines: %q", tc.name, got)
		}
	}
	for _, u := range []string{"agentosd.service", "agentos-egress.service", "agentos-egress-setup.service"} {
		calls = nil
		got := journalTail(20, "agentos-localui.service", u)
		if len(calls) != 0 || strings.Contains(got, "a journal line") {
			t.Errorf("journalTail read %s's journal: calls %v, got %q", u, calls, got)
		}
	}
}

// journalCanary is a journal line no filtered reader keeps: the stand-in
// for a line that holds a secret E8 never prints.
const journalCanary = "journal-canary-0f3a: a line no filtered reader keeps"

// filteredJournal is a box journal that holds a line each filtered reader
// keeps, each next to the canary; the hook line also carries the canary
// before localui's hook text.
var filteredJournal = strings.Join([]string{
	journalCanary,
	journalCanary + " " + hostHookLog + "localui: synthetic hook error",
	journalCanary,
	"agentosd: agent machine guest-1: no socket",
	journalCanary,
	"agentosd: worker tools: not offered",
	journalCanary,
	"agentosd: setup: StartSignIn refused at step 6",
	journalCanary,
	"agentosd: provagent: worker exited 1",
	journalCanary,
	modemlink.MissedLog + " kind=request via owner.(*Channel).sendRequest",
	journalCanary,
}, "\n") + "\n"

// stubJournal makes output answer journalctl with filteredJournal and
// returns the units each journalctl call read.
func stubJournal(t *testing.T) *[][]string {
	t.Helper()
	var units [][]string
	old := output
	t.Cleanup(func() { output = old })
	output = func(name string, args ...string) string {
		if name != "journalctl" {
			return ""
		}
		var u []string
		for i, a := range args {
			if a == "-u" && i+1 < len(args) {
				u = append(u, args[i+1])
			}
		}
		units = append(units, u)
		return filteredJournal
	}
	return &units
}

// REQ: HW-10, ONB-3. Every journal read that reaches the console is
// filtered as ASSUMPTIONS E8 states (#4544 items 1 and 3): driven against
// a journal where each kept line sits next to a canary line, host quotes
// only localui's hook text, agentDiag only agentosd's agent-machine and
// worker-tools lines, and workerDiag only its setup and provagent lines;
// phoneControl's lost-send notes are pinned the same way in
// TestPhoneControlAgainstTheOwnerChannel. Each reads only its own unit,
// through output. It catches a reader that regresses to quoting its
// unit's whole journal.
func TestFilteredJournalReadersQuoteOnlyTheirLines(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		units := stubJournal(t)
		const page = `<h2>5. This PC</h2><p class="err">Could not save.</p>`
		box := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.Path {
			case "POST /setup/host":
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
			case "GET /setup":
				w.Write([]byte(page))
			default:
				http.NotFound(w, r)
			}
		})
		clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
		d := &driver{now: clk.now, sleep: clk.sleep, phone: &http.Client{Transport: handlerRT{box},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
		err := d.host()
		want := fmt.Sprintf("after %s: %s: %slocalui: synthetic hook error", time.Minute, where([]byte(page)), hostHookLog)
		if err == nil || err.Error() != want {
			t.Fatalf("host error\n %v\nwant\n %s", err, want)
		}
		if !slices.EqualFunc(*units, [][]string{{"agentos-localui.service"}}, slices.Equal) {
			t.Errorf("host read the journals of %v, want localui's once", *units)
		}
	})
	for _, c := range []struct {
		name string
		diag func() string
		keep []string
	}{
		{"agentDiag", func() string { return agentDiag(nil) },
			[]string{"agent machine guest-1: no socket", "worker tools: not offered"}},
		{"workerDiag", func() string {
			d := &driver{runscLog: func() string { return "" }}
			return d.workerDiag("sign-in output", "")
		}, []string{"setup: StartSignIn refused at step 6", "provagent: worker exited 1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			units := stubJournal(t)
			got := c.diag()
			if strings.Contains(got, "journal-canary") {
				t.Errorf("%s quotes a line it does not keep: %q", c.name, got)
			}
			for _, k := range c.keep {
				if !strings.Contains(got, k) {
					t.Errorf("%s drops its line %q: %q", c.name, k, got)
				}
			}
			for _, other := range []string{"synthetic hook error", "kind=request", "agent machine", "provagent"} {
				if !slices.ContainsFunc(c.keep, func(k string) bool { return strings.Contains(k, other) }) && strings.Contains(got, other) {
					t.Errorf("%s quotes another reader's line %q: %q", c.name, other, got)
				}
			}
			if !slices.EqualFunc(*units, [][]string{{"agentosd.service"}}, slices.Equal) {
				t.Errorf("%s read the journals of %v, want agentosd's once", c.name, *units)
			}
		})
	}
}

type answer func(*http.Request) (*http.Response, error)

func (f answer) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fixedAnswer is a box that answers the request at with status and a page
// whose step heading and error line are known, and passes every other
// request to next.
type fixedAnswer struct {
	at     string
	status int
	next   http.Handler
}

const (
	answerPage = `<h2>4. Store your recovery key</h2><p class="err">Tick the box to say it is stored.</p>`
	answerAt   = `at "4. Store your recovery key" saying "Tick the box to say it is stored."`
)

func (f fixedAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method+" "+r.URL.RequestURI() == f.at || f.next == nil {
		w.WriteHeader(f.status)
		w.Write([]byte(answerPage))
		return
	}
	f.next.ServeHTTP(w, r)
}

// REQ: ONB-3. Every request the driver makes through answerErr (codes,
// the card's sheet, page and confirm, recovery, host, the AI sign-in and
// /status) says where setup stood when setup answers it wrongly: the
// page's step heading and its error line, never a bare status
// (G1-e2e-later #1740 item 1, G1-e2e-tidy #1715 item 3, #4517 item 1); a
// request with no answer names its error.
func TestFailedRequestsSayWhereSetupStood(t *testing.T) {
	disp, auth, _ := realCard(t)
	for _, c := range []struct {
		req  string
		at   string // the request the box answers wrongly
		st   int
		next http.Handler
		box  *fakeBox // the sign-in box, whose stub the driver uses
		step func(*driver) error
	}{
		{"POST /setup/codes", "POST /setup/codes", 200, nil, nil, (*driver).codes},
		{"GET card sheet", "GET /setup/card?save=1", 500, disp, nil, (*driver).card},
		{"GET card page", "GET /setup/card", 500, disp, nil, (*driver).card},
		{"POST card confirm", "POST /setup/card", 200, disp, nil, (*driver).card},
		{"POST /setup/recovery", "POST /setup/recovery", 200, nil, nil, (*driver).recovery},
		{"POST /setup/host", "POST /setup/host", 200, nil, nil, (*driver).host},
		{"POST /setup/ai-device", "POST /setup/ai-device", 200, nil, signInBox(), (*driver).planSignIn},
		{"GET /status", "GET /status", 500, nil, signInBox(), (*driver).planSignIn},
	} {
		box := c.box
		if box == nil {
			box = &fakeBox{stub: codexstub.New()}
		} else {
			c.next = box
		}
		d := fakeDriver(box)
		d.phone.Transport = handlerRT{fixedAnswer{c.at, c.st, c.next}}
		d.seed = []byte("synthetic-seed-canary")
		usePublished(t, auth)
		err := c.step(d)
		if want := fmt.Sprintf("%s %d %s", c.req, c.st, answerAt); err == nil || err.Error() != want {
			t.Errorf("%s error\n %v\nwant\n %s", c.req, err, want)
		}
	}
	if got := answerErr("GET /status", 0, nil, errors.New("connection refused")).Error(); got != "GET /status 0: connection refused" {
		t.Fatalf("transport error line %q", got)
	}
}

// signInBox is fakeBox at step 6 offering the codex sign-in.
func signInBox() *fakeBox {
	return &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
}

// realCard is a real Owner Card display under the box's page paths, the
// authority it prints, and a copy of the card it generated (the display
// wipes its own once confirmed).
func realCard(t *testing.T) (http.Handler, []byte, card.Card) {
	t.Helper()
	auth := cardAuthority(t)
	var made card.Card
	d, err := card.NewDisplay(card.DisplayConfig{Authority: auth, Provision: func(*card.Card) error { return nil },
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if c != nil {
				made = *c
			}
			return c, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	return d.Handler(func(*http.Request) bool { return true }, "/setup"), auth, made
}

// usePublished points the card step's published certificate at auth.
func usePublished(t *testing.T, auth []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "authority.der")
	if err := os.WriteFile(p, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	old := publishedAuthority
	publishedAuthority = p
	t.Cleanup(func() { publishedAuthority = old })
}

// realAnswer passes the request at to next, then answers it with next's
// page under status; wrong, if set, changes the request first.
type realAnswer struct {
	at     string
	status int
	wrong  func(*http.Request)
	next   http.Handler
	got    *int // the status next answered
}

func (f realAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method+" "+r.URL.RequestURI() != f.at {
		f.next.ServeHTTP(w, r)
		return
	}
	if f.wrong != nil {
		f.wrong(r)
	}
	rr := httptest.NewRecorder()
	f.next.ServeHTTP(rr, r)
	*f.got = rr.Code
	w.WriteHeader(f.status)
	w.Write(rr.Body.Bytes())
}

// REQ: ONB-3, HW-10. A failed card request's line is read off the card's
// own pages, which hold every printed card secret: the saved sheet, the
// display page and the wrong-answer page of a real display each give
// their step heading only, with no passphrase word, and no group or whole
// value of the recovery key, setup code or reset secret (#4517 item 4,
// #4544 item 4). It catches a card heading or error line that gains a
// secret.
func TestCardAnswerErrQuotesNoCardSecret(t *testing.T) {
	disp, auth, made := realCard(t)
	get := func(target string) []byte {
		w := httptest.NewRecorder()
		disp.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		return w.Body.Bytes()
	}
	sheet := string(get("/setup/card?save=1"))
	pass, rec, err := sheetSecrets([]byte(sheet))
	if err != nil {
		t.Fatal(err)
	}
	if pass != made.VaultPassphrase || rec != made.RecoveryKey {
		t.Fatal("the sheet's passphrase or recovery key is not the generated card's")
	}
	// The secrets are the generated card's printed values: the setup code
	// and reset secret (the card's SetupSecret) are on the sheet too.
	whole := []string{made.RecoveryKey, made.SetupCode, made.SetupSecret}
	for _, v := range whole {
		if v == "" {
			t.Fatal("the generated card has an empty printed value")
		}
		if !strings.Contains(sheet, v) {
			t.Fatalf("the sheet does not print the card value %q", v)
		}
	}
	// A secret is a whole passphrase word, in any case, or a full group of
	// the recovery key, setup code or reset secret as printed. A short
	// last group (two symbols of the reset secret) is caught as part of
	// the whole value only, since a two-letter token can be ordinary text.
	secret := map[string]bool{}
	for _, w := range strings.Fields(pass) {
		secret[strings.ToLower(w)] = true
	}
	for _, v := range whole {
		for _, g := range strings.FieldsFunc(v, func(r rune) bool { return !strings.ContainsRune(card.Alphabet, r) }) {
			if len(g) >= 4 {
				secret[g] = true
			}
		}
	}
	for _, c := range []struct {
		req, at string
		status  int
		wrong   func(*http.Request)
		real    int // the status the display answers
	}{
		{"GET card sheet", "GET /setup/card?save=1", 500, nil, 200},
		{"GET card page", "GET /setup/card", 500, nil, 200},
		{"POST card confirm", "POST /setup/card", http.StatusUnprocessableEntity, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(url.Values{"word": {"wrong"}, "group": {"ZZZZ"}}.Encode()))
		}, http.StatusUnprocessableEntity},
	} {
		var got int
		d := fakeDriver(&fakeBox{stub: codexstub.New()})
		d.phone.Transport = handlerRT{realAnswer{c.at, c.status, c.wrong, disp, &got}}
		usePublished(t, auth)
		err := d.card()
		if got != c.real {
			t.Fatalf("%s: the display answered %d, want its %d page", c.req, got, c.real)
		}
		prefix := fmt.Sprintf("%s %d at ", c.req, c.status)
		if err == nil || !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("%s: %v", c.req, err)
		}
		// Only what the page gave is checked: the request's own name has
		// words a passphrase may hold (confirm, sheet).
		page := strings.TrimPrefix(err.Error(), prefix)
		for _, v := range whole {
			if strings.Contains(page, v) || strings.Contains(card.Normalize(page), card.Normalize(v)) {
				t.Errorf("%s line %q carries the card value %q", c.req, err, v)
			}
		}
		for _, w := range strings.FieldsFunc(page, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if secret[strings.ToLower(w)] || secret[w] {
				t.Errorf("%s line %q carries the card's %q", c.req, err, w)
			}
		}
	}
}

// journalReaders are the only functions that may read a journal, and the
// functions that may call each: readJournal alone runs journalctl, and
// journal is agentosd's whole journal, so only callers that keep lines of
// one shape take it. ASSUMPTIONS E8 names each.
var journalReaders = map[string][]string{
	"readJournal": {"journalTail", "host", "agentDiag", "journal"},
	"journal":     {"workerDiag", "phoneControl"},
}

// runners are the package's ways to run a system tool. Each takes the
// tool's name first; run and output pass their own name and args
// parameters on to command.
var runners = map[string]bool{"command": true, "run": true, "output": true}

// spawners start a process, or make a raw system call that can, other
// than through a runner, keyed by import path and name, so an alias or
// dot import of the package is the same use; command alone calls
// childproc.Command.
var spawners = map[string]bool{
	"github.com/ghbmrk/agentos/broker/childproc.Command": true,
	"os.StartProcess": true,
	"syscall.Exec":    true, "syscall.ForkExec": true, "syscall.StartProcess": true,
	"syscall.Syscall": true, "syscall.Syscall6": true, "syscall.RawSyscall": true, "syscall.RawSyscall6": true,
	"golang.org/x/sys/unix.Exec": true, "golang.org/x/sys/unix.Syscall": true, "golang.org/x/sys/unix.Syscall6": true,
	"golang.org/x/sys/unix.RawSyscall": true, "golang.org/x/sys/unix.RawSyscall6": true,
}

// barred are imports no file of the driver takes: os/exec starts a
// process outside command, and unsafe, plugin and cgo reach code the
// source test cannot read.
var barred = map[string]bool{"os/exec": true, "unsafe": true, "plugin": true, "C": true}

// REQ: HW-10, ONB-3. The console is a public CI log, so no diag reads a
// journal but through the readers ASSUMPTIONS E8 names (#4517 item 3):
// journalctl is named only in readJournal, and each reader is called
// only by the functions E8 names for it. A tool runs only through a
// direct call of command, run or output, and only the tools E8 allows,
// under constant names and arguments: ip link, addr or netns add, and
// systemctl show, restart or daemon-reload; journalctl only in
// readJournal (#4544 item 2, #4571). The test type-checks the driver, so
// it matches runners, readers and spawners by what they are, not by
// spelling: a runner taken as a value, an aliased or dot-imported
// spawner, and a wrapper tool such as sh or env each fail it, and so does
// systemctl status, which prints the unit's journal.
func TestJournalIsReadOnlyByNamedReaders(t *testing.T) {
	for _, tags := range [][]string{nil, {"agentos_e2e"}} {
		fset, files, imp := driverSources(t, tags)
		for _, p := range sourceProblems(fset, files, imp) {
			t.Errorf("tags %v: %s", tags, p)
		}
	}
	e8 := assumptionRow(t, "E8")
	for reader, callers := range journalReaders {
		for _, n := range append([]string{reader}, callers...) {
			if !strings.Contains(e8, "`"+n+"`") {
				t.Errorf("ASSUMPTIONS E8 does not name the journal reader `%s`", n)
			}
		}
	}
	for _, tool := range []string{"`ip`", "`systemctl`", "`journalctl`", "`show`", "`restart`", "`daemon-reload`"} {
		if !strings.Contains(e8, tool) {
			t.Errorf("ASSUMPTIONS E8 does not name the allowed tool word %s", tool)
		}
	}
}

// REQ: HW-10, ONB-3. Each shape that #4547's reviews and #4571 name, and
// the ones #4544 closed, added to the driver as one more file, fails the
// source test with its own reason; the driver as it stands has none.
func TestSourceTestRefusesEachBypass(t *testing.T) {
	fset, files, imp := driverSources(t, nil)
	const cp = `"github.com/ghbmrk/agentos/broker/childproc"`
	for _, c := range []struct{ name, src, want string }{
		{"runner as a value", `func zz() { f := output; f("systemctl", "status", "agentosd.service") }`, "uses output other than as a direct call"},
		{"runner in a package var", `var zz = run`, "uses run other than as a direct call"},
		{"aliased spawner", `import cp ` + cp + "\n" + `func zz() { cp.Command(nil, childEnv, cp.Options{}, "systemctl", "status") }`, "starts a process through github.com/ghbmrk/agentos/broker/childproc.Command"},
		{"dot-imported spawner", `import . ` + cp + "\n" + `func zz() { Command(nil, childEnv, Options{}, "id") }`, "starts a process through github.com/ghbmrk/agentos/broker/childproc.Command"},
		{"aliased syscall", `import sc "syscall"` + "\n" + `func zz() { sc.Exec("/bin/sh", nil, nil) }`, "starts a process through syscall.Exec"},
		{"spawner as a value", `import "os"` + "\n" + `var zz = os.StartProcess`, "starts a process through os.StartProcess"},
		{"os/exec alias", `import x "os/exec"` + "\n" + `var zz = x.Command`, "imports os/exec"},
		{"unsafe", `import _ "unsafe"`, "imports unsafe"},
		{"sh wrapper", `func zz() { output("sh", "-c", "systemctl status agentosd.service") }`, `runs "sh", which ASSUMPTIONS E8 does not allow`},
		{"env wrapper", `func zz() { output("env", "systemctl", "status", "agentosd.service") }`, `runs "env", which ASSUMPTIONS E8 does not allow`},
		{"absolute path", `func zz() { output("/usr/bin/systemctl", "show") }`, `runs "/usr/bin/systemctl"`},
		{"systemctl status", `func zz() { output("systemctl", "status", "-n", "50", "agentosd.service") }`, "runs systemctl status"},
		{"computed verb", `func zz() { output("systemctl", "sta"+"tus", "agentosd.service") }`, "runs systemctl status"},
		{"verb after an option", `func zz() { output("systemctl", "-p", "x", "status") }`, "runs systemctl -p"},
		{"variable systemctl argument", `func zz(v string) { output("systemctl", "show", v) }`, "runs systemctl with an argument that is not a constant"},
		{"spread systemctl arguments", `func zz() { a := []string{"status"}; run("systemctl", a...) }`, "runs systemctl with an argument that is not a constant"},
		{"variable tool name", `func zz(n string) { run(n, "status") }`, "with a tool name that is not a constant"},
		{"computed journalctl", `func zz() { output("journal"+"ctl", "-u", "agentosd.service") }`, "names journalctl"},
		{"journalctl constant", `const zz = "journalctl"`, "names journalctl"},
		{"ip netns exec", `func zz() { run("ip", "netns", "exec", netns, "sh") }`, "runs ip netns exec"},
		{"ip batch", `func zz() { run("ip", "-b", "/tmp/x") }`, "runs ip -b"},
		{"readJournal from an unnamed caller", `func zz() string { return readJournal(0, "agentosd.service") }`, "zz reads through readJournal"},
		{"journal as a value", `func zz(d *driver) { f := d.journal; _ = f }`, "uses journal other than as a direct call"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(fset, "zz_bypass.go", "package main\n"+c.src+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			got := sourceProblems(fset, append(slices.Clone(files), f), imp)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("source test does not refuse it with %q; it says %q", c.want, got)
			}
		})
	}
}

var (
	sourceOnce sync.Once
	sourceFset *token.FileSet
	sourceImp  types.Importer
)

// driverSources is the driver's non-test files that a Linux build with
// tags compiles, parsed, and an importer that type-checks their imports
// from source, shared by every caller so each package is read once.
func driverSources(t *testing.T, tags []string) (*token.FileSet, []*ast.File, types.Importer) {
	t.Helper()
	sourceOnce.Do(func() {
		sourceFset = token.NewFileSet()
		sourceImp = importer.ForCompiler(sourceFset, "source", nil)
	})
	ctx := build.Default
	ctx.GOOS, ctx.BuildTags = "linux", tags
	bp, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(bp.CgoFiles) > 0 {
		t.Errorf("the driver has cgo files %v, which the source test cannot read", bp.CgoFiles)
	}
	var files []*ast.File
	for _, n := range bp.GoFiles {
		f, err := parser.ParseFile(sourceFset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return sourceFset, files, sourceImp
}

// sourceProblems type-checks the driver's files and names each way they
// run a tool, start a process or read a journal outside what
// ASSUMPTIONS E8 allows. A driver that does not type-check is itself a
// problem, so the test fails closed.
func sourceProblems(fset *token.FileSet, files []*ast.File, imp types.Importer) []string {
	var bad []string
	add := func(at token.Pos, format string, a ...any) {
		bad = append(bad, fset.Position(at).String()+": "+fmt.Sprintf(format, a...))
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
	pkg, err := (&types.Config{Importer: imp}).Check("main", fset, files, info)
	if err != nil {
		return []string{"the driver does not type-check: " + err.Error()}
	}
	runner := map[types.Object]string{}
	for n := range runners {
		if o := pkg.Scope().Lookup(n); o != nil {
			runner[o] = n
		}
	}
	reader := map[types.Object]string{}
	if o := pkg.Scope().Lookup("readJournal"); o != nil {
		reader[o] = "readJournal"
	}
	if tn, ok := pkg.Scope().Lookup("driver").(*types.TypeName); ok {
		if o, _, _ := types.LookupFieldOrMethod(types.NewPointer(tn.Type()), true, pkg, "journal"); o != nil {
			reader[o] = "journal"
		}
	}
	if len(runner) != len(runners) || len(reader) != len(journalReaders) {
		return []string{fmt.Sprintf("the driver lacks a runner or reader the test names: runners %v, readers %v", runner, reader)}
	}
	uses := map[string][]string{} // reader -> the declarations that use it
	named := false                // readJournal names journalctl
	for _, f := range files {
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); barred[p] {
				add(im.Pos(), "imports %s", p)
			}
		}
		for _, decl := range f.Decls {
			in := declName(decl)
			called := map[*ast.Ident]bool{} // the idents that are a call's function
			ast.Inspect(decl, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok {
					if v := info.Types[e].Value; v != nil && v.Kind() == constant.String && strings.Contains(constant.StringVal(v), "journalctl") {
						if in != "readJournal" {
							add(e.Pos(), "%s names journalctl, which only readJournal runs", in)
						}
						named = true
					}
				}
				switch n := n.(type) {
				case *ast.CallExpr:
					switch fn := n.Fun.(type) {
					case *ast.Ident:
						called[fn] = true
						if name, ok := runner[info.Uses[fn]]; ok {
							if why := runnerCall(info, in, name, n); why != "" {
								add(n.Pos(), "%s calls %s %s", in, name, why)
							}
						}
					case *ast.SelectorExpr:
						called[fn.Sel] = true
					}
				case *ast.Ident:
					obj := info.Uses[n]
					if obj == nil {
						break
					}
					if name, ok := runner[obj]; ok && !called[n] {
						add(n.Pos(), "%s uses %s other than as a direct call", in, name)
					}
					if name, ok := reader[obj]; ok {
						if !called[n] {
							add(n.Pos(), "%s uses %s other than as a direct call", in, name)
						}
						uses[name] = append(uses[name], in)
					}
					if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil && fn.Signature().Recv() == nil {
						sp := fn.Pkg().Path() + "." + fn.Name()
						if spawners[sp] && (sp != "github.com/ghbmrk/agentos/broker/childproc.Command" || in != "command") {
							add(n.Pos(), "%s starts a process through %s, not command", in, sp)
						}
					}
				}
				return true
			})
		}
	}
	if !named {
		bad = append(bad, "readJournal does not name journalctl: the test reads the wrong files")
	}
	for reader, callers := range journalReaders {
		for _, in := range uses[reader] {
			if !slices.Contains(callers, in) {
				bad = append(bad, fmt.Sprintf("%s reads through %s, which ASSUMPTIONS E8 does not name it for (callers %v)", in, reader, callers))
			}
		}
	}
	return bad
}

// runnerCall says why a call of the runner name, in the declaration in,
// runs a tool ASSUMPTIONS E8 does not allow, or "". run and output may
// pass their own name and args parameters on to command; every other
// call names its tool by a constant, and ip and systemctl take only
// constant arguments: ip link, addr or netns add, after an optional -n
// and namespace, and systemctl show, restart or daemon-reload as its
// first argument. journalctl runs only in readJournal, with the
// arguments readJournal builds.
func runnerCall(info *types.Info, in, name string, call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return "with no tool name"
	}
	param := func(e ast.Expr, want string) bool {
		id, ok := e.(*ast.Ident)
		v, isVar := info.Uses[id].(*types.Var)
		return ok && isVar && id.Name == want && v.Parent() != nil && v.Parent().Parent() != types.Universe
	}
	if name == "command" && (in == "run" || in == "output") && len(call.Args) == 2 && call.Ellipsis.IsValid() &&
		param(call.Args[0], "name") && param(call.Args[1], "args") {
		return ""
	}
	vals, allConst := constStrings(info, call.Args)
	if vals[0] == nil {
		return "with a tool name that is not a constant"
	}
	tool, args := *vals[0], vals[1:]
	switch tool {
	case "journalctl":
		if in != "readJournal" {
			return "with journalctl outside readJournal"
		}
		return ""
	case "ip", "systemctl":
	default:
		return fmt.Sprintf("and runs %q, which ASSUMPTIONS E8 does not allow", tool)
	}
	if !allConst || call.Ellipsis.IsValid() {
		return "and runs " + tool + " with an argument that is not a constant"
	}
	a := make([]string, len(args))
	for i, v := range args {
		a[i] = *v
	}
	if tool == "systemctl" {
		if len(a) == 0 || !slices.Contains([]string{"show", "restart", "daemon-reload"}, a[0]) {
			return "and runs systemctl " + strings.Join(a, " ") + ", not show, restart or daemon-reload"
		}
		return ""
	}
	obj := a
	if len(obj) >= 2 && obj[0] == "-n" {
		obj = obj[2:]
	}
	if len(obj) == 0 || !(obj[0] == "link" || obj[0] == "addr" || len(obj) >= 2 && obj[0] == "netns" && obj[1] == "add") {
		return "and runs ip " + strings.Join(a, " ") + ", not link, addr or netns add"
	}
	return ""
}

// constStrings is each argument's constant string value, nil where it
// has none, and whether every argument has one.
func constStrings(info *types.Info, args []ast.Expr) ([]*string, bool) {
	vals := make([]*string, len(args))
	all := true
	for i, a := range args {
		if v := info.Types[a].Value; v != nil && v.Kind() == constant.String {
			s := constant.StringVal(v)
			vals[i] = &s
		} else {
			all = false
		}
	}
	return vals, all
}

// declName is a declaration's name for the source test: a function's
// name, or a package-level variable's or constant's (output is one).
func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, sp := range d.Specs {
			if vs, ok := sp.(*ast.ValueSpec); ok {
				for _, n := range vs.Names {
					names = append(names, n.Name)
				}
			}
		}
		if len(names) > 0 {
			return strings.Join(names, ",")
		}
	}
	return "(package level)"
}

// assumptionRow is ASSUMPTIONS.md's row whose first cell is id.
func assumptionRow(t *testing.T, id string) string {
	t.Helper()
	b, err := os.ReadFile("ASSUMPTIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "| "+id+" |") {
			return l
		}
	}
	t.Fatalf("ASSUMPTIONS.md has no %s row", id)
	return ""
}
