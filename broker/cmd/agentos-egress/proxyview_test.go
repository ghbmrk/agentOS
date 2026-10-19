package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: ARC-1, CRED-1, CRED-7

// proxyAt serves pv's hand socket in a fresh directory, as the proxy
// process does, and returns the directory.
func proxyAt(t *testing.T, pv *proxyView) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "px")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := holder.Listen(filepath.Join(dir, holder.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: holder.HandHandler(pv, maxView)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return dir
}

// splitRig is a vault process (custody, with -proxy) and a proxy process
// (proxyView) over the same holders, in one test process.
type splitRig struct {
	*fastRig
	pv     *proxyView
	oh, ah *holder.Holder
	got    func() []string
}

func newSplitRig(t *testing.T, g grants, agent string, pok map[string]bool, every time.Duration) *splitRig {
	t.Helper()
	tr, got := reflecting(t, true)
	openaiDir, oh := heldAt(t, egress.OpenAI("openai"), tr)
	anthDir, ah := heldAt(t, egress.Anthropic("anthropic"), tr)
	dirs := holderDirs{"openai": openaiDir, "anthropic": anthDir}
	r := newFastRig(t, true) // its vault holds an OpenAI key
	r.c.holders = dirs
	r.c.keepEvery = every
	r.c.modelTransport = noDial{t}
	r.c.privateFlags = pok
	withGrants(r.c, g, agent)
	pv, err := newProxyView(g, agent, pok, dirs, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.c.view = newViewKeeper(r.c, proxyAt(t, pv))
	ctx, cancel := context.WithCancel(context.Background())
	go r.c.view.run(ctx)
	t.Cleanup(cancel)
	waitUntil(t, "the first view", pv.Held)
	return &splitRig{fastRig: r, pv: pv, oh: oh, ah: ah, got: got}
}

// answers is every model and routing answer a source gives.
func answers(s modelSource) string {
	var b strings.Builder
	b.WriteString(map[bool]string{true: "model ", false: "nomodel "}[s.model() != nil])
	for _, ok := range []bool{s.modelGrantedNow(), s.privateGrantedNow()} {
		b.WriteString(map[bool]string{true: "y", false: "n"}[ok])
	}
	for _, p := range []string{"openai", "anthropic", "nobody"} {
		for _, m := range []string{"agent", "other"} {
			b.WriteString(map[bool]string{true: " g:" + m + "/" + p, false: ""}[s.storedGrant(m, p)])
		}
		b.WriteString(map[bool]string{true: " p:" + p, false: ""}[s.privateAllowed(p)])
	}
	return b.String()
}

// SIM-split-wire: the proxy process answers from the view the vault
// process hands it, and from no vault. It reports locked before the
// unlock, open and granted after it, follows a key stored while open,
// redacts every vault value by keyed hash (CRED-7), and reports locked
// the moment the lock returns (CRED-1).
func TestProxyViewFollowsCustody(t *testing.T) {
	r := newSplitRig(t, grants{}, "agent", nil, 5*time.Millisecond)
	if r.pv.model() != nil || r.pv.storedGrant("agent", "openai") {
		t.Fatal("the proxy reports open before the unlock")
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the open view", func() bool { return r.pv.storedGrant("agent", "openai") })
	waitUntil(t, "the openai holder's key", r.oh.Held)
	r.c.mu.Lock()
	seed, _ := r.c.v.Secret(SeedName)
	other := seed.Reveal()
	r.c.mu.Unlock()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[{"role":"user","content":"`+other+`"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer placeholder")
	r.pv.model().HandlerFor("agent", "private", noAudit{}).ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hello ") {
		t.Fatalf("call through the proxy process: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), other) {
		t.Fatal("a vault value came back unredacted")
	}

	if err := r.c.put("anthropic", []byte(synthetic(t, "sk-ant-canary-"))); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the stored anthropic key", func() bool { return r.pv.storedGrant("agent", "anthropic") })

	r.c.lock()
	if r.pv.model() != nil || r.pv.storedGrant("agent", "openai") || r.pv.privateAllowed("openai") {
		t.Fatal("the proxy reports open after the lock returned")
	}
	if !r.pv.modelGrantedNow() {
		t.Fatal("the proxy forgot the stored-key mark at the lock")
	}
}

// The proxy process gives every answer custody gives, in each state the
// vault passes through, for grants by stored key and by flag.
func TestProxyViewAnswersAsCustodyDoes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		g     grants
		agent string
		pok   map[string]bool
	}{
		{"stored keys", grants{}, "agent", nil},
		{"flags", grants{"agent": {"anthropic"}}, "", map[string]bool{"anthropic": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSplitRig(t, tc.g, tc.agent, tc.pok, 5*time.Millisecond)
			same := func(state string) {
				t.Helper()
				want := answers(r.c)
				waitUntil(t, state+": the proxy's answers "+want, func() bool { return answers(r.pv) == want })
			}
			same("before the unlock")
			if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
				t.Fatal(err)
			}
			same("open")
			if err := r.c.put("anthropic", []byte(synthetic(t, "sk-ant-canary-"))); err != nil {
				t.Fatal(err)
			}
			same("a key stored")
			r.c.mu.Lock()
			err := r.c.v.Put(PrivateOKPrefix+"openai", KindPrivateOK, []byte("synthetic-mark"))
			r.c.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			same("private data allowed")
			r.c.lock()
			if got, want := answers(r.pv), answers(r.c); got != want {
				t.Fatalf("after the lock the proxy answers %q, custody %q", got, want)
			}
		})
	}
}

// A view that does not parse leaves the proxy locked.
func TestBadViewLeavesTheProxyLocked(t *testing.T) {
	pv, err := newProxyView(grants{}, "agent", nil, holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pv.Hand([]byte(`{"open":true,"keys":["openai"],"redactor":"bm90IGEgcmVkYWN0b3I="}`))
	if pv.model() != nil || pv.storedGrant("agent", "openai") {
		t.Fatal("a view whose redactor does not parse opened the proxy")
	}
	if _, err := pv.redactor(); err == nil {
		t.Fatal("a locked proxy gave a redactor")
	}
	if _, err := newProxyView(grants{}, "agent", nil, holderDirs{}, nil); err == nil {
		t.Fatal("a proxy process with no holders would have to hold keys")
	}
}
