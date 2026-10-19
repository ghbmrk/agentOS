package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/cleanroom"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CRED-5, A11, OP-9, CAP-9, CRED-1

// agentKeyed makes r's custody the one serveCmd builds with no -grant
// flag: the agent machine's grants come only from the keys its vault
// holds (CRED-5f-mr-grant).
func agentKeyed(r *fastRig, tr http.RoundTripper) *custody {
	r.c.modelTransport = tr
	return withGrants(r.c, grants{}, "agent")
}

// reflector is a TLS provider that answers each call with a chat
// completion and records the key it received.
func reflector(t *testing.T) (http.RoundTripper, func() []string) {
	t.Helper()
	return reflecting(t, false)
}

// reflecting is reflector; with echo, its answer's content also echoes
// the key it received and the request body, as a hostile or careless
// provider might, so a test sees whether redaction takes them out.
func reflecting(t *testing.T, echo bool) (http.RoundTripper, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var keys []string
	prov := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		keys = append(keys, key)
		mu.Unlock()
		content := []byte(`"hello"`)
		if echo {
			body, _ := io.ReadAll(r.Body)
			content, _ = json.Marshal("hello " + key + " " + string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":`+string(content)+`},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(prov.Close)
	tr := prov.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := prov.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return tr, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), keys...)
	}
}

// #814 (a): a key stored at setup grants its provider to the agent
// machine, with no -grant flag, through the router and the proxy both,
// from the moment it is stored. It grants no other provider and no other
// machine, and a locked vault serves nothing.
func TestAStoredKeyGrantsTheAgentMachine(t *testing.T) {
	tr, got := reflector(t)
	r := providerRig(t)
	r.c.modelTransport = tr
	// serveCmd's own wiring, over its default -agent-machine and no
	// -grant: the router and custody both come from wireModel (R1).
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	agent := agentFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	mw, err := wireModel(route.Rule{
		"default": {{Provider: "openai", Model: "gpt-test"}},
		"claude":  {{Provider: "anthropic", Model: "claude-test"}},
	}, grants{}, map[string]bool{"openai": true, "anthropic": true}, *agent, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.c, err = mw.bind(r.c); err != nil {
		t.Fatal(err)
	}
	rt := mw.rt
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, rt, nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	fwd := modelroute.Forward(modelroute.Config{
		Socket: filepath.Join(run, ModelSocket),
		Label:  func(string) string { return "private" },
		Denied: func(string, modelroute.Denial) {},
	})
	ask := func(machine, class string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"`+class+`","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer placeholder")
		fwd(machine).ServeHTTP(w, req)
		return w.Code
	}

	if code := ask("agent", "default"); code != http.StatusServiceUnavailable {
		t.Fatalf("locked vault: %d", code)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if code := ask("agent", "default"); code != http.StatusForbidden || len(got()) != 0 {
		t.Fatalf("no key stored: %d, provider calls %d", code, len(got()))
	}
	key := synthetic(t, "sk-canary-grant-")
	if w := setupCall(t, r.c, "POST", "/setup/providers/key", keyBody("openai", key)); w.Code != http.StatusOK {
		t.Fatalf("store key: %d %s", w.Code, w.Body)
	}
	if code := ask("agent", "default"); code != http.StatusOK || !slices.Equal(got(), []string{key}) {
		t.Fatalf("stored key: %d, provider got %d keys", code, len(got()))
	}
	if code := ask("agent", "claude"); code != http.StatusForbidden || len(got()) != 1 {
		t.Fatalf("a provider with no key: %d", code)
	}
	if code := ask("other", "default"); code != http.StatusForbidden || len(got()) != 1 {
		t.Fatalf("another machine: %d", code)
	}
	if code := ask(modelroute.BuilderPrefix+"1", "default"); code != http.StatusForbidden || len(got()) != 1 {
		t.Fatalf("a builder machine: %d", code)
	}
	r.c.lock()
	if code := ask("agent", "default"); code != http.StatusServiceUnavailable || len(got()) != 1 {
		t.Fatalf("locked again: %d", code)
	}
}

// A key already in the vault grants at unlock: the proxy is built over
// the open vault's keys.
func TestAKeyHeldAtUnlockGrants(t *testing.T) {
	tr, got := reflector(t)
	r := newFastRig(t, true) // its vault holds an OpenAI key
	agentKeyed(r, tr)
	var hook privateHook
	hook.bind(r.c)
	_, rt, err := modelRouting(route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}},
		grants{}, map[string]bool{"openai": true}, nil, hook.granted, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`))
	rt.HandlerFor("agent", "private", r.c.model().HandlerFor("agent", "private", noAudit{}), nil).ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(got()) != 1 {
		t.Fatalf("held key: %d %s", w.Code, w.Body)
	}
}

// storedGrant is the grant a stored key gives: only to the agent machine,
// only for the provider whose API key the open vault holds. An entry of
// another kind under a credential's name grants nothing, and with no agent
// machine a stored key grants nothing.
func TestStoredGrantIsTheAgentsOpenKeysOnly(t *testing.T) {
	r := newFastRig(t, true) // its vault holds an OpenAI key
	agentKeyed(r, nil)
	if r.c.storedGrant("agent", "openai") {
		t.Fatal("granted while locked")
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if !r.c.storedGrant("agent", "openai") {
		t.Fatal("the held key grants nothing")
	}
	for _, mp := range [][2]string{{"agent", "anthropic"}, {"other", "openai"}, {modelroute.BuilderPrefix, "openai"}, {"agent", "nope"}} {
		if r.c.storedGrant(mp[0], mp[1]) {
			t.Errorf("%s granted %s", mp[0], mp[1])
		}
	}
	if err := r.c.v.Put("anthropic", "note", []byte(synthetic(t, "note-canary-"))); err != nil {
		t.Fatal(err)
	}
	if r.c.storedGrant("agent", "anthropic") {
		t.Fatal("an entry of another kind grants")
	}
	withGrants(r.c, grants{}, "")
	if r.c.storedGrant("", "openai") || r.c.storedGrant("agent", "openai") {
		t.Fatal("no agent machine, yet a grant")
	}
}

// #814 (a), OP-9 C2: the state's granted follows stored keys, so a box
// set up with a key reads locked, not "no AI plan or key", while the vault
// is locked, after a restart too. The mark that answers while locked
// holds which providers have a key, never a key (CRED-1).
func TestTheModelStateFollowsStoredKeys(t *testing.T) {
	ctx := context.Background()
	r := providerRig(t)
	agentKeyed(r, nil)
	probe := modelroute.NewStateProbe(serveState(t, r.c))
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true}) {
		t.Fatalf("no key, locked: %+v", got)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Open: true}) {
		t.Fatalf("no key, open: %+v", got)
	}
	key := synthetic(t, "sk-canary-mark-")
	if err := r.c.setupKey("openai", []byte(key)); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true, Open: true}) {
		t.Fatalf("key stored, open: %+v", got)
	}
	r.c.lock()
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true}) {
		t.Fatalf("key stored, locked: %+v", got)
	}
	raw, err := os.ReadFile(r.state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), key) {
		t.Fatal("the unlock state holds the key")
	}
	r.build(t)
	agentKeyed(r, nil)
	if got := modelroute.NewStateProbe(serveState(t, r.c))(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true}) {
		t.Fatalf("after a restart, locked: %+v", got)
	}
	// With no agent machine a stored key grants nothing.
	r.build(t)
	withGrants(r.c, grants{}, "")
	if got := modelroute.NewStateProbe(serveState(t, r.c))(ctx); got.Granted {
		t.Fatalf("no agent machine: %+v", got)
	}
}

// #814 (c): serveCmd's custody is serveCustody's, which goes through
// withGrants and binds the router's hook, so granted follows -grant
// (L3 point 2 on #566) and the agent machine follows -agent-machine.
func TestServeCustodyFollowsTheFlags(t *testing.T) {
	for _, tc := range []struct {
		g    grants
		want bool
	}{
		{grants{}, false},
		{grants{"agent": {"openai"}}, true},
	} {
		var hook privateHook
		c, err := serveCustody(&custody{statePath: filepath.Join(t.TempDir(), "unlock.json")}, tc.g, "agent", &hook)
		if err != nil {
			t.Fatal(err)
		}
		if c.granted != tc.want || c.build == nil || c.agent != "agent" || hook.load() != modelSource(c) {
			t.Errorf("%v: granted %v, build set %v, agent %q, hook bound %v", tc.g, c.granted, c.build != nil, c.agent, hook.load() == modelSource(c))
		}
	}
}

// -agent-machine names an agent machine: never a builder's or a replay
// machine, whose grants come from -builder-from and -eval-from.
func TestCheckAgentMachine(t *testing.T) {
	for _, m := range []string{"agent", "work-1", ""} {
		if err := checkAgentMachine(m); err != nil {
			t.Errorf("%q: %v", m, err)
		}
	}
	// Every broker-reserved prefix is refused, pinned to the packages
	// that reserve them (S2).
	for _, p := range []string{modelroute.BuilderPrefix, modelroute.EvalPrefix, vm.BuilderPrefix, vm.EvalPrefix, vm.WorkerPrefix, cleanroom.Prefix} {
		if err := checkAgentMachine(p + "1"); err == nil {
			t.Errorf("reserved prefix %q accepted", p)
		}
	}
	for _, m := range []string{"Agent", "-x", "a/b"} {
		if err := checkAgentMachine(m); err == nil {
			t.Errorf("%q accepted", m)
		}
	}
}
