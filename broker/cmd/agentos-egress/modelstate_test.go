package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: OP-9, A11, CRED-5, CRED-1

// serveState serves the rig's sockets for the broker's uid and returns
// the model socket.
func serveState(t *testing.T, c *custody) string {
	t.Helper()
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	return filepath.Join(run, ModelSocket)
}

// OP-9 C2: the model socket answers the broker's state request with
// whether a model provider is granted and whether the vault is open, on
// the client agentosd links (modelroute), before unlock too.
func TestModelSocketAnswersTheState(t *testing.T) {
	ctx := context.Background()
	none := newFastRig(t, true)
	if got := modelroute.NewStateProbe(serveState(t, none.c))(ctx); got != (modelroute.ModelState{Reachable: true}) {
		t.Fatalf("no grant, locked: %+v", got)
	}
	r := newFastRig(t, true)
	r.c.granted = true
	probe := modelroute.NewStateProbe(serveState(t, r.c))
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true}) {
		t.Fatalf("granted, locked: %+v", got)
	}
	tk := r.unlock(t)
	if got := probe(ctx); got.Open {
		t.Fatalf("open on the passphrase alone: %+v", got)
	}
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true, Open: true}) {
		t.Fatalf("granted, open: %+v", got)
	}
	r.c.lock()
	if got := probe(ctx); got.Open {
		t.Fatalf("open after lock: %+v", got)
	}
}

// CRED-1: the state answer holds the two facts and nothing else; a canary
// key in the open vault is not in it.
func TestModelStateAnswerCarriesNoSecret(t *testing.T) {
	r := newFastRig(t, true)
	r.c.granted = true
	sock := serveState(t, r.c)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	canary := synthetic(t, "sk-canary-state-")
	if err := r.c.put("openai", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://agentos-egress/", nil)
	req.Header.Set(modelroute.HeaderState, "1")
	resp, err := unixClient(sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := strings.TrimSpace(string(body)); got != `{"granted":true,"open":true}` {
		t.Fatalf("answer %q", got)
	}
	for k, v := range resp.Header {
		if strings.Contains(strings.Join(v, " "), canary) {
			t.Fatalf("header %s holds the canary", k)
		}
	}
}

// A11's no-grant cause: granted means some machine has a model provider.
func TestModelGranted(t *testing.T) {
	for _, c := range []struct {
		g    grants
		want bool
	}{
		{grants{}, false},
		{grants{"agent": nil}, false},
		{grants{"agent": {"openai"}}, true},
		{grants{"other": {"anthropic"}}, true},
		{grants{"agent": {"not-a-model"}}, false},
	} {
		if got := modelGranted(c.g); got != c.want {
			t.Errorf("%v: %v", c.g, got)
		}
	}
}

// The state branch answers GET only (L3 and Security point 3 on #566).
func TestModelStateIsGetOnly(t *testing.T) {
	r := newFastRig(t, true)
	r.c.granted = true
	req, _ := http.NewRequest(http.MethodPost, "http://agentos-egress/", strings.NewReader("{}"))
	req.Header.Set(modelroute.HeaderState, "1")
	resp, err := unixClient(serveState(t, r.c)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || strings.Contains(string(body), "granted") {
		t.Fatalf("POST: %d %q", resp.StatusCode, body)
	}
}

// serveCmd builds its custody through withGrants, so the state's granted
// follows the -grant flags (L3 point 2 on #566).
func TestWithGrantsSetsTheGrantState(t *testing.T) {
	for _, c := range []struct {
		g    grants
		want bool
	}{
		{grants{}, false},
		{grants{"agent": {"openai"}}, true},
	} {
		got := withGrants(&custody{}, c.g)
		if got.granted != c.want || got.build == nil {
			t.Errorf("%v: granted %v, build set %v", c.g, got.granted, got.build != nil)
		}
	}
}
