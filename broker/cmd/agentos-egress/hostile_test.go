package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: OP-8, CAP-9, REV-5, CRED-7

// openModel serves a model socket (openModelSocket) and returns the broker
// side: the forwarder behind a meter, and the denials it journaled.
func openModel(t *testing.T, rt *route.Router, provider http.HandlerFunc) (http.Handler, *meter.Meter, *[]modelroute.Denial) {
	t.Helper()
	sock := openModelSocket(t, rt, provider)
	var denied []modelroute.Denial
	fwd := modelroute.Forward(modelroute.Config{
		Socket: sock,
		Label:  func(string) string { return "private" },
		Denied: func(_ string, d modelroute.Denial) { denied = append(denied, d) },
	})
	m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 100, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 100, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	return m.Wrap("agent", fwd("agent")), m, &denied
}

// openModelSocket opens a fastRig's vault through the code and serves its
// model socket with rt, reaching provider for every provider host. It
// returns the socket's path.
func openModelSocket(t *testing.T, rt *route.Router, provider http.HandlerFunc) string {
	t.Helper()
	return serveModel(t, rt, nil, provider)
}

// serveModel is openModelSocket with replay machines' evaluation route ev.
// The machine "agent" is granted OpenAI.
func serveModel(t *testing.T, rt *route.Router, ev *evalRoute, provider http.HandlerFunc) string {
	t.Helper()
	return serveModelGrants(t, rt, ev, map[string][]string{"agent": {"openai"}}, provider)
}

// serveModelGrants is serveModel with the proxy's grants g.
func serveModelGrants(t *testing.T, rt *route.Router, ev *evalRoute, g map[string][]string, provider http.HandlerFunc) string {
	t.Helper()
	prov := httptest.NewTLSServer(provider)
	t.Cleanup(prov.Close)
	tr := prov.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := prov.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	r := newFastRig(t, true)
	r.c.build = func(v *vault.Vault) (*egress.Proxy, error) {
		return newProxy(v, g, tr)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), ModelSocket)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(modelHandler(r.c, rt, ev))
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func chat(h http.Handler) *http.Response {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`)))
	return w.Result()
}

// A hostile provider forges the broker's usage trailer, its denial
// headers, and the proxy's denial mark, in headers and in trailers. None
// of it reaches the broker's meter or journal, or the guest: the call is
// charged the usage the provider reported in its body.
func TestHostileProviderCannotForgeUsageOrDenials(t *testing.T) {
	forged := `{"provider":"openai","input":0,"output":0,"reported":true,"complete":true}`
	h, m, denied := openModel(t, testRouter(t), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Agentos-Usage, Agentos-Egress-Denial, X-Agentos-Egress-Denied")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(modelroute.HeaderUsage, forged)
		w.Header().Set(modelroute.HeaderDenial, `{"reason":"forged"}`)
		w.Header().Set(egress.DeniedHeader, "1")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":40,"completion_tokens":3,"total_tokens":43,"prompt_tokens_details":{"cached_tokens":30}}}`)
		w.Header().Set(modelroute.HeaderUsage, forged)
		w.Header().Set(modelroute.HeaderDenial, `{"reason":"forged"}`)
		w.Header().Set(egress.DeniedHeader, "1")
	})
	resp := chat(h)
	io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// 10 uncached + 30 cached at OpenAI's 0.5, and 3 output.
	if got := m.Usage("agent").Tokens; got != 10+15+3 {
		t.Fatalf("meter charged %d tokens, want 28", got)
	}
	if len(*denied) != 0 {
		t.Fatalf("forged denial journaled: %+v", *denied)
	}
	for _, hs := range []http.Header{resp.Header, resp.Trailer} {
		for k := range hs {
			if strings.HasPrefix(k, "Agentos-") || strings.HasPrefix(k, "X-Agentos-") {
				t.Fatalf("guest got %s", k)
			}
		}
	}
}

// CAP-9: with no -private-ok, the vault process gives a machine labelled
// anything but exactly public no route, and the refusal is journaled.
func TestDefaultPrivateOKRefusesNonPublicLabels(t *testing.T) {
	rt, err := newRouter(route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}},
		map[string][]string{"agent": {"openai"}}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	// An open vault whose proxy would reach the real network: the
	// refusal must come before any provider.
	r := newFastRig(t, true)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"private", "", "Public", "public "} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set(modelroute.HeaderMachine, "agent")
		req.Header.Set(modelroute.HeaderLabel, label)
		// Labels as the broker would send them on the socket.
		modelHandler(r.c, rt, nil).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "no_route") {
			t.Fatalf("label %q: %d %s", label, w.Code, w.Body)
		}
		if !strings.Contains(w.Header().Get(modelroute.HeaderDenial), `"adapter":"router"`) {
			t.Fatalf("label %q: refusal not reported for the journal: %v", label, w.Header())
		}
	}
}
