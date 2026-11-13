package main

import (
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: CRED-1, ADP-10

func TestParseRefusesWhatAHolderCannotKeep(t *testing.T) {
	ok := []string{"-dir", "/run/x", "-credential", "openai", "-adapter", "openai", "-request-uid", "1", "-hand-uid", "2"}
	c, err := parse(ok, io.Discard)
	if err != nil || len(c.adapters) != 1 || c.adapters[0].Credential != "openai" {
		t.Fatalf("%+v %v", c, err)
	}
	// -checker parses into the config; run checks its directory
	// (checkerOK).
	if c, err := parse(append(ok, "-checker", "/x"), io.Discard); err != nil || c.checker != "/x" {
		t.Fatalf("-checker: %q %v", c.checker, err)
	}
	for name, args := range map[string][]string{
		"no uid":          {"-dir", "/run/x", "-credential", "k", "-adapter", "openai"},
		"one uid for two": {"-dir", "/run/x", "-credential", "k", "-adapter", "openai", "-request-uid", "1", "-hand-uid", "1"},
		"unknown adapter": {"-dir", "/run/x", "-credential", "k", "-adapter", "gmail", "-request-uid", "1", "-hand-uid", "2"},
		"no adapter":      {"-dir", "/run/x", "-credential", "k", "-request-uid", "1", "-hand-uid", "2"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A holder never runs as one of its peers: the uid check would admit
// anything under its own uid (SIM-split R3).
func TestRunRefusesItsPeerUID(t *testing.T) {
	me := strconv.Itoa(os.Getuid())
	other := strconv.Itoa(os.Getuid() + 1)
	for _, uids := range [][]string{{me, other}, {other, me}} {
		args := []string{"-dir", t.TempDir(), "-credential", "k", "-adapter", "openai", "-request-uid", uids[0], "-hand-uid", uids[1]}
		if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "peer uid") {
			t.Errorf("uids %v: %v", uids, err)
		}
	}
}

// REQ: ADP-10
// Provider-side fetch is the owner's per-login choice: a holder started
// without -public-fetch holds every body to the strict form, so a server
// tool is refused even from a machine egress labels public (#1061 P1).
func TestPublicFetchIsOffByDefault(t *testing.T) {
	base := []string{"-dir", "/run/x", "-credential", "openai", "-adapter", "openai", "-request-uid", "1", "-hand-uid", "2"}
	serve := func(args []string) int {
		t.Helper()
		c, err := parse(args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		cfg := c.holderConfig(nil)
		cfg.Transport = okUpstream{}
		h, err := holder.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		h.Hand([]byte("CANARY-holder-cmd-0001"))
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"web_search_options":{}}`
		r := httptest.NewRequest("POST", "http://api.openai.com/v1/chat/completions", strings.NewReader(body))
		r.Host = "api.openai.com"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(egress.LabelHeader, egress.LabelPublic)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := serve(base); code != http.StatusForbidden {
		t.Fatalf("no -public-fetch: server tool served (%d)", code)
	}
	if code := serve(append(base, "-public-fetch")); code != http.StatusOK {
		t.Fatalf("-public-fetch: %d", code)
	}
}

type okUpstream struct{}

func (okUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
}

// REQ: CH-4
// The -checker help and the package usage say what empty does and that a
// directory where another uid could listen is refused: a planted redeem
// socket approves every irreversible operation (W-3, H-9, #5633, #5649).
// The usage is read from the package's doc, whichever file holds it.
func TestCheckerHelpNamesTheListenerCaveat(t *testing.T) {
	var out strings.Builder
	parse([]string{"-h"}, &out)
	for _, want := range []string{"leave empty to serve reads only", "is refused at start"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("-checker help lacks %q:\n%s", want, out.String())
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var doc strings.Builder
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments|parser.PackageClauseOnly)
		if err != nil {
			t.Fatal(err)
		}
		if f.Doc != nil {
			doc.WriteString(f.Doc.Text())
		}
	}
	d := strings.Join(strings.Fields(doc.String()), " ")
	for _, want := range []string{"Without -checker the holder serves reads only", "is refused at start"} {
		if !strings.Contains(d, want) {
			t.Errorf("package usage lacks %q:\n%s", want, d)
		}
	}
}

// REQ: CH-4
// -checker fails closed on a socket whose directory a uid other than root
// or this one could plant a listener in (#5649, W-3, H-9).
func TestCheckerRefusesAnUnsafeDirectory(t *testing.T) {
	euid := uint32(os.Geteuid())
	if err := checkerOK("", euid); err != nil {
		t.Errorf("empty -checker: %v", err)
	}
	if checkerOK("redeem.sock", euid) == nil {
		t.Error("accepted a relative -checker")
	}
	ok := filepath.Join(t.TempDir(), "checker")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkerOK(filepath.Join(ok, "redeem.sock"), euid); err != nil {
		t.Fatalf("a directory only this uid writes: %v", err)
	}
	shared := filepath.Join(t.TempDir(), "shared")
	open := filepath.Join(t.TempDir(), "open")
	under := filepath.Join(open, "checker")
	other := filepath.Join(t.TempDir(), "other")
	link := filepath.Join(t.TempDir(), "link")
	for _, d := range []string{shared, open, under, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{shared, open} {
		if err := os.Chmod(d, 0o777); err != nil { // no sticky bit
			t.Fatal(err)
		}
	}
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	trust := euid
	if euid == 0 {
		// root is always trusted, so the owner case needs another owner.
		if err := os.Chown(other, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	} else {
		trust = euid + 1
	}
	for name, c := range map[string]struct {
		dir  string
		euid uint32
	}{
		"writable by others":       {shared, euid},
		"a parent writable by all": {under, euid},
		"another uid's":            {other, trust},
		"a link":                   {link, euid},
		"missing":                  {filepath.Join(ok, "absent"), euid},
	} {
		if checkerOK(filepath.Join(c.dir, "redeem.sock"), c.euid) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
