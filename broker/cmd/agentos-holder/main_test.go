package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
