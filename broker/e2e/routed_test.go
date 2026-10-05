package e2e

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: OP-8, ARC-6, CAP-9, CRED-5

// TestOP8RoutedCallsSettleFromProviderUsage composes the box's model
// path: guest socket, OP-8 meter, model router, egress proxy, provider. A
// guest that asks for no usage gets a stream without it, and the meter
// still settles from what the provider reported (Anthropic's cache reads
// at their weight); the provider is sent an output limit no larger than
// what the meter reserved.
func TestOP8RoutedCallsSettleFromProviderUsage(t *testing.T) {
	work := t.TempDir()
	key := make([]byte, vault.KeySize)
	rand.Read(key)
	v, err := vault.Create(filepath.Join(work, "vault"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	nonce := make([]byte, 8)
	rand.Read(nonce)
	if err := v.Put("provider-key", vault.KindAPIKey, []byte("sk-synthetic-"+hex.EncodeToString(nonce))); err != nil {
		t.Fatal(err)
	}

	stream, err := os.ReadFile("../route/testdata/anthropic_stream.sse")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var limits []int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MaxTokens int64 `json:"max_tokens"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		limits = append(limits, req.MaxTokens)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write(stream)
	}))
	defer srv.Close()
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	jstore, err := journal.OpenFile(filepath.Join(work, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()
	eng, err := journal.Open(jstore, denyAll{}, map[string]journal.Executor{}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	ms := &machines{private: map[string]bool{}}
	public := func(string) string { return route.LabelPublic }
	proxy, err := egress.New(egress.Config{
		Adapters:  []egress.Adapter{egress.OpenAI("provider-key"), egress.Anthropic("provider-key")},
		Grants:    map[string][]string{"m1": {"anthropic"}},
		Vault:     v,
		Audit:     &egress.JournalAuditor{Journal: eng},
		Transport: tr,
		Label:     public,
	})
	if err != nil {
		t.Fatal(err)
	}
	router, err := route.New(route.Config{
		Providers: []route.Provider{route.OpenAI(), route.Anthropic()},
		Rule:      route.Rule{"default": {{Provider: "anthropic", Model: "claude-fixture"}}},
		Granted:   func(m, p string) bool { return m == "m1" && p == "anthropic" },
		Label:     public,
		Upstream:  proxy.Handler,
		Audit:     func(route.Decision) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	mtr, err := meter.Open(meter.Config{
		Path:       filepath.Join(work, "meter.json"),
		MachineCap: meter.Limits{Calls: 40, Tokens: 1 << 24},
		OverallCap: meter.Limits{Calls: 1000, Tokens: 1 << 30},
		MaxReserve: int64(router.MaxOutputTokens()),
	})
	if err != nil {
		t.Fatal(err)
	}
	plane, err := guest.New(guest.Config{
		Dir: filepath.Join(work, "guests"), Machines: ms, Effects: eng,
		Model: guest.Routed(router), Meter: mtr,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	dir, err := plane.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, guest.Socket)
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}

	// Both mount paths a guest may be configured with.
	for i, path := range []string{"/model/v1/chat/completions", "/model/openai/v1/chat/completions"} {
		resp, err := c.Post("http://broker"+path, "application/json",
			strings.NewReader(`{"model":"default","stream":true,"max_tokens":1000000,"messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), "Hello") || !strings.Contains(string(b), "[DONE]") {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
		}
		if strings.Contains(string(b), `"usage"`) {
			t.Fatalf("%s: usage sent to a guest that did not ask: %s", path, b)
		}
		// Anthropic's report: 25 input, 1800 cache reads at 0.1, 32 output.
		if u := mtr.Usage("m1"); u.Calls != int64(i+1) || u.Tokens != int64(i+1)*(25+180+32) {
			t.Fatalf("%s: meter %+v, want %d calls of 237 tokens", path, u, i+1)
		}
	}
	// An escaped separator or a dot segment is denied, never decoded or
	// redirected into the served path, even by a guest that follows
	// redirects (ADP-10).
	mu.Lock()
	served := len(limits)
	mu.Unlock()
	for _, path := range []string{
		"/model/v1/chat%2Fcompletions", "/model/openai%2Fv1/chat/completions", "/model/%761/chat/completions",
		"/model/v1/../v1/chat/completions", "/model/./v1/chat/completions", "/model//v1/chat/completions",
		"/model/x/../v1/chat/completions", "/x/../model/v1/chat/completions",
	} {
		resp, err := c.Post("http://broker"+path, "application/json",
			strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("%s was served", path)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(limits) != served {
		t.Errorf("an unclean path reached the provider: %d calls, want %d", len(limits), served)
	}
	for _, l := range limits {
		if l <= 0 || l > int64(router.MaxOutputTokens()) {
			t.Fatalf("provider was sent max_tokens %d, ceiling %d", l, router.MaxOutputTokens())
		}
	}
}

// The meter's default output ceiling is the router's, so the limit the
// meter forwards and reserves is the one the router enforces.
var _ = [1]struct{}{}[meter.DefaultMaxReserve-route.DefaultMaxOutputTokens]
