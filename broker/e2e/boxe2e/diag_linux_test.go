package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// tool's name first; run and output pass their caller's name on to
// command, so only they may give it a name that is not a literal.
var runners = map[string]bool{"command": true, "run": true, "output": true}

// spawners start a process other than through a runner; command alone
// calls childproc.Command.
var spawners = map[string]bool{
	"childproc.Command": true, "os.StartProcess": true,
	"syscall.Exec": true, "syscall.ForkExec": true, "syscall.StartProcess": true,
	"unix.Exec": true,
}

// REQ: HW-10, ONB-3. The console is a public CI log, so no diag reads a
// journal but through the readers ASSUMPTIONS E8 names (#4517 item 3):
// journalctl appears only in readJournal, and each reader is called only
// by the functions E8 names for it. A tool runs only through command, run
// or output, under a literal name, and systemctl only with literal
// arguments, never status, which prints the unit's journal (#4544 item
// 2). It catches a new diag that runs journalctl itself, under a computed
// name or as systemctl status, or takes agentosd's whole journal, and
// quotes it.
func TestJournalIsReadOnlyByNamedReaders(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string][]string{} // reader or "journalctl" -> where it appears
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); p == "os/exec" {
				t.Errorf("%s imports os/exec: a tool runs only through command", name)
			}
		}
		for _, decl := range f.Decls {
			in := declName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					checkRunnerCall(t, fset, in, n)
				case *ast.BasicLit:
					if n.Kind == token.STRING && strings.Contains(n.Value, "journalctl") {
						uses["journalctl"] = append(uses["journalctl"], in)
					}
				case *ast.Ident:
					// readJournal is a function, used by its bare name.
					if n.Name == "readJournal" && !isDeclName(decl, n) {
						uses[n.Name] = append(uses[n.Name], in)
					}
				case *ast.SelectorExpr:
					// journal is the driver's method; a parameter or
					// variable of that name is not a use.
					if n.Sel.Name == "journal" {
						uses["journal"] = append(uses["journal"], in)
					}
					// command alone starts a child process.
					if x, ok := n.X.(*ast.Ident); ok {
						sel := x.Name + "." + n.Sel.Name
						if spawners[sel] && (sel != "childproc.Command" || in != "command") {
							t.Errorf("%s: %s starts a process through %s, not command", fset.Position(n.Pos()), in, sel)
						}
					}
				}
				return true
			})
		}
	}
	if got := uses["journalctl"]; !slices.Equal(got, []string{"readJournal"}) {
		t.Errorf("journalctl appears in %v, want readJournal alone", got)
	}
	for reader, callers := range journalReaders {
		for _, in := range uses[reader] {
			if !slices.Contains(callers, in) {
				t.Errorf("%s reads through %s, which ASSUMPTIONS E8 does not name it for (callers %v)", in, reader, callers)
			}
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
}

// checkRunnerCall refuses a call of a runner, in the declaration named
// in, whose tool name is not a string literal (outside run and output,
// which pass their own name parameter on), or that runs systemctl with an
// argument that is not a literal or is status. A call with no arguments
// is not a runner's: each takes the name first (report.step's run is a
// parameter).
func checkRunnerCall(t *testing.T, fset *token.FileSet, in string, call *ast.CallExpr) {
	t.Helper()
	fn, ok := call.Fun.(*ast.Ident)
	if !ok || !runners[fn.Name] || len(call.Args) == 0 {
		return
	}
	at := fset.Position(call.Pos())
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		if id, isID := call.Args[0].(*ast.Ident); isID && id.Name == "name" && fn.Name == "command" && (in == "run" || in == "output") {
			return
		}
		t.Errorf("%s: %s calls %s with a tool name that is not a literal", at, in, fn.Name)
		return
	}
	if lit.Value != `"systemctl"` {
		return
	}
	for _, a := range call.Args[1:] {
		l, ok := a.(*ast.BasicLit)
		if !ok || l.Kind != token.STRING {
			t.Errorf("%s: %s runs systemctl with an argument that is not a literal", at, in)
			continue
		}
		if l.Value == `"status"` {
			t.Errorf("%s: %s runs systemctl status, which prints the unit's journal", at, in)
		}
	}
}

// declName is a declaration's name for the source test: a function's
// name, or a package-level variable's (output is one).
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

// isDeclName reports whether id is decl's own name, not a use of it.
func isDeclName(decl ast.Decl, id *ast.Ident) bool {
	fd, ok := decl.(*ast.FuncDecl)
	return ok && fd.Name == id
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
