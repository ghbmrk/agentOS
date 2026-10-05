package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, CRED-1, CRED-5, CRED-7, ADP-10, REV-5, ARC-6

// TestUnknownHostUnlockThenModelRoute is the P2-4a chain on one host:
// `init` seals a vault under a generated passphrase, the vault process
// starts locked, the model route answers 503, the passphrase plus an
// approval code unlock it through the unlock socket, and the broker's
// forwarder (as agentosd wires it) then reaches a provider with the vault
// key injected, never shown to the guest. Denials come back to the
// broker's journal. Locking again returns the route to 503.
func TestUnknownHostUnlockThenModelRoute(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "state", "vault"), filepath.Join(dir, "state", "vault.keys")
	var card bytes.Buffer
	if err := initCmd([]string{"-vault", vp, "-keys", kp}, &card); err != nil {
		t.Fatal(err)
	}
	pass, seed := readCard(t, card.String())

	// A hostile provider that reflects whatever key it receives.
	var mu sync.Mutex
	var got []string
	prov := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		got = append(got, key)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"key is `+key+`"}}]}`)
	}))
	defer prov.Close()
	tr := prov.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := prov.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	clk := &clock{t: time.Now()}
	c, err := newCustody(&custody{
		statePath: filepath.Join(dir, "state", "unlock.json"),
		open:      func(p string) (*vault.Vault, error) { return vault.OpenSealed(vp, kp, vault.Passphrase(p)) },
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, tr)
		},
		ttl:    15 * time.Minute,
		now:    clk.now,
		notify: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.lock()
	run := filepath.Join(dir, "run")
	srvs, err := serve(run, c, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	if fi, err := os.Stat(run); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("run dir: %v %v", fi.Mode(), err)
	}

	var denied []modelroute.Denial
	fwd := modelroute.Forward(modelroute.Config{
		Socket: filepath.Join(run, ModelSocket),
		Label:  func(string) string { return "private" },
		Denied: func(_ string, d modelroute.Denial) { denied = append(denied, d) },
	})
	ask := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"model":"m","messages":[]}`))
		req.Header.Set("Authorization", "Bearer placeholder")
		fwd("agent").ServeHTTP(w, req)
		return w
	}

	if w := ask("/openai/v1/chat/completions"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("locked vault: %d", w.Code)
	}

	ui := unixClient(filepath.Join(run, UnlockSocket))
	if _, code, _ := post(ui, "/unlock", map[string]string{"passphrase": "wrong " + pass}); code != http.StatusForbidden {
		t.Fatalf("wrong passphrase: %d", code)
	}
	if _, code, _ := post(ui, "/unlock", map[string]string{"passphrase": pass}); code != http.StatusTooManyRequests {
		t.Fatalf("attempt inside the gap: %d", code)
	}
	clk.add(MinAttemptGap)
	res, code, err := post(ui, "/unlock", map[string]string{"passphrase": strings.ToUpper(pass)})
	if err != nil || code != 200 || res["state"] != "pending" {
		t.Fatalf("unlock: %v %d %v", res, code, err)
	}
	ticket, _ := res["ticket"].(string)
	if w := ask("/openai/v1/chat/completions"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("passphrase alone opened the route: %d", w.Code)
	}
	if res, code, _ := post(ui, "/confirm", map[string]string{"ticket": ticket, "code": "000000"}); code != http.StatusForbidden || res["error"] != "wrong code; 2 tries left" {
		t.Fatalf("wrong code: %v %d", res, code)
	}
	if res, code, _ := post(ui, "/confirm", map[string]string{"ticket": ticket, "code": totp(seed, clk.now())}); code != 200 || res["state"] != "open" {
		t.Fatalf("confirm: %v %d", res, code)
	}

	// No key yet: the proxy fails closed.
	if w := ask("/openai/v1/chat/completions"); w.Code != http.StatusServiceUnavailable || len(denied) != 1 || denied[0].Reason != "credential not in vault" {
		t.Fatalf("missing key: %d %+v", w.Code, denied)
	}
	key := synthetic(t, "sk-canary-")
	if err := putCmd([]string{"-run", run, "-name", "openai"}, strings.NewReader(key+"\n")); err != nil {
		t.Fatal(err)
	}
	w := ask("/openai/v1/chat/completions")
	if w.Code != 200 || strings.Contains(w.Body.String(), key) || !strings.Contains(w.Body.String(), "key is") {
		t.Fatalf("model call: %d %s", w.Code, w.Body)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != key {
		t.Fatalf("provider did not get the vault key")
	}
	mu.Unlock()

	if w := ask("/anthropic/v1/messages"); w.Code != http.StatusForbidden || w.Header().Get(modelroute.HeaderDenial) != "" {
		t.Fatalf("ungranted adapter: %d", w.Code)
	}
	if last := denied[len(denied)-1]; last.Adapter != "anthropic" || last.Machine != "agent" || last.Status != 403 {
		t.Fatalf("denial: %+v", last)
	}

	if _, code, _ := post(ui, "/lock", nil); code != 200 {
		t.Fatalf("lock: %d", code)
	}
	if w := ask("/openai/v1/chat/completions"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("after lock: %d", w.Code)
	}
}

func readCard(t *testing.T, card string) (string, []byte) {
	t.Helper()
	var pass, secret string
	for _, line := range strings.Split(card, "\n") {
		if p, ok := strings.CutPrefix(line, "Vault passphrase: "); ok {
			pass = p
		}
		if _, q, ok := strings.Cut(line, "secret="); ok {
			secret, _, _ = strings.Cut(q, "&")
		}
	}
	seed, err := b32().DecodeString(secret)
	if pass == "" || err != nil || len(seed) != 20 {
		t.Fatalf("card: %q", card)
	}
	if n := len(strings.ReplaceAll(pass, " ", "")); n != 20 {
		t.Fatalf("passphrase has %d characters, want 20 (100 bits)", n)
	}
	return pass, seed
}

// The sockets admit one uid each: anyone else is closed unread.
func TestSocketsAdmitOnlyTheirPeer(t *testing.T) {
	c := &custody{now: time.Now, notify: func(string) {}}
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, c, os.Getuid()+1, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	for _, name := range []string{ModelSocket, UnlockSocket, VerifySocket} {
		resp, err := unixClient(filepath.Join(run, name)).Get("http://x/status")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("%s answered a stranger: %d", name, resp.StatusCode)
		}
	}
}

// The model socket takes a machine name only in the broker's shape.
func TestModelSocketNeedsAMachine(t *testing.T) {
	c := &custody{now: time.Now, notify: func(string) {}}
	for _, m := range []string{"", "../x", "Agent", strings.Repeat("a", 41)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
		r.Header.Set(modelroute.HeaderMachine, m)
		modelHandler(c).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("machine %q: %d", m, w.Code)
		}
	}
}

func TestStatusShowsPhaseOnly(t *testing.T) {
	r := newFastRig(t, true)
	h := unlockHandler(r.c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["state"] != "locked" || len(out) != 1 {
		t.Fatalf("status %v", out)
	}
}

// K7: agentosd's owner channel reaches the verify operation through its
// own socket, with the client agentosd links. The answer carries a step
// and a yes or no, never the seed; a locked vault is an error, so the
// channel counts nothing.
func TestVerifySocketForTheBroker(t *testing.T) {
	r := newFastRig(t, true)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	kind := func(err error) modelroute.VerifyFailure {
		var ve *modelroute.VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("not a VerifyError: %v", err)
		}
		return ve.Kind
	}
	if _, _, err := v.VerifyTOTP(r.code(), 0, true); kind(err) != modelroute.VerifyLocked {
		t.Fatalf("locked vault: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	r.clk.add(30 * time.Second)
	if _, ok, err := v.VerifyTOTP("000000", 0, true); ok || err != nil {
		t.Fatalf("wrong code: %v %v", ok, err)
	}
	step, ok, err := v.VerifyTOTP(r.code(), 0, true)
	if !ok || err != nil || step != r.clk.now().Unix()/30 {
		t.Fatalf("right code: %d %v %v", step, ok, err)
	}
	for i := 0; i < MaxWrongSilent; i++ {
		v.VerifyTOTP("000000", 0, false)
	}
	_, _, err = v.VerifyTOTP("000000", 0, false)
	var ve *modelroute.VerifyError
	if kind(err) != modelroute.VerifyPaused || !errors.As(err, &ve) || !ve.Until.Equal(r.clk.now().Add(VerifyWindow).Truncate(time.Second)) {
		t.Fatalf("silent bucket full: %v %+v", err, ve)
	}
	if _, _, err := modelroute.NewVerifier(filepath.Join(run, "absent.sock")).VerifyTOTP("000000", 0, true); kind(err) != modelroute.VerifyDown {
		t.Fatalf("no process: %v", err)
	}

	w := httptest.NewRecorder()
	verifyHandler(r.c).ServeHTTP(w, httptest.NewRequest("POST", "/verify", strings.NewReader(`{"code":"000000"}`)))
	if b := w.Body.String(); strings.Contains(b, string(r.seed)) || strings.Contains(b, "seed") {
		t.Fatalf("verify answer: %s", b)
	}
	w = httptest.NewRecorder()
	verifyHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", "/verify", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
}
