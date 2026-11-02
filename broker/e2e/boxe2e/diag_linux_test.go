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
	"unicode"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
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
	disp, auth := realCard(t)
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

// realCard is a real Owner Card display under the box's page paths, and
// the authority it prints.
func realCard(t *testing.T) (http.Handler, []byte) {
	t.Helper()
	auth := cardAuthority(t)
	d, err := card.NewDisplay(card.DisplayConfig{Authority: auth, Provision: func(*card.Card) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return d.Handler(func(*http.Request) bool { return true }, "/setup"), auth
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
// own pages, which hold the vault passphrase and recovery key: the saved
// sheet, the display page and the wrong-answer page of a real display
// each give their step heading only, with no word, group or key (#4517
// item 4). It catches a card heading or error line that gains a secret.
func TestCardAnswerErrQuotesNoCardSecret(t *testing.T) {
	disp, auth := realCard(t)
	get := func(target string) []byte {
		w := httptest.NewRecorder()
		disp.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		return w.Body.Bytes()
	}
	pass, rec, err := sheetSecrets(get("/setup/card?save=1"))
	if err != nil {
		t.Fatal(err)
	}
	// A secret is a whole passphrase word, in any case, or a recovery key
	// group as printed.
	secret := map[string]bool{}
	for _, w := range strings.Fields(pass) {
		secret[strings.ToLower(w)] = true
	}
	for _, g := range strings.FieldsFunc(rec, func(r rune) bool { return !strings.ContainsRune(card.Alphabet, r) }) {
		secret[g] = true
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
		if strings.Contains(page, rec) {
			t.Errorf("%s line %q carries the recovery key", c.req, err)
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

// REQ: HW-10, ONB-3. The console is a public CI log, so no diag reads a
// journal but through the readers ASSUMPTIONS E8 names (#4517 item 3):
// journalctl appears only in readJournal, and each reader is called only
// by the functions E8 names for it. It catches a new diag that runs
// journalctl itself, or takes agentosd's whole journal, and quotes it.
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
		for _, decl := range f.Decls {
			in := "(package level)"
			if fd, ok := decl.(*ast.FuncDecl); ok {
				in = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
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
