package run

// REQ: PLN-5, CLK-7, LOG-7, RES-5

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
)

type oneAddr netip.Addr

func (a oneAddr) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(a)}, nil
}

func fakeJWT(acct string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": acct}}) + ".sig"
}

// planProvider is a fake Codex backend: the code exchange issues the
// synthetic login real-access-1, and a model call streams back its bearer
// with usage 30 in and 40 out and a pool reading.
func planProvider(t *testing.T, calls *atomic.Int32) (*plan.Login, *x509.CertPool) {
	return planProviderUsing(t, calls, func(int) string { return `"usage":{"input_tokens":30,"output_tokens":40}` })
}

// planProviderUsing is planProvider whose completed event carries usage of
// the body's length it was sent: a JSON member, or nothing.
func planProviderUsing(t *testing.T, calls *atomic.Int32, usage func(n int) string) (*plan.Login, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "real-access-1", "refresh_token": "real-refresh-1", "id_token": fakeJWT("acct-1")})
		case "/backend-api/codex/responses":
			calls.Add(1)
			sent, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Codex-Primary-Used-Percent", "25")
			w.Header().Set("X-Codex-Primary-Reset-At", "4000000000")
			io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\""+r.Header.Get("Authorization")+"\"}\n\n")
			io.WriteString(w, `data: {"type":"response.completed","response":{`+usage(len(sent))+`}}`+"\n\n")
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	d := plan.Codex(netguard.New(netguard.Config{Resolver: oneAddr(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}))
	host := "example.com:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	for i := range d.Endpoints {
		d.Endpoints[i].Host = host
	}
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.New(d, plan.NewStore(s, nil), roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BeginSignIn("signin"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"client_id": {"app_x"}, "code": {"ac"}, "code_verifier": {"v"}, "grant_type": {"authorization_code"},
		"redirect_uri": {"http://127.0.0.1:18432/deviceauth/callback"}}.Encode()
	r := httptest.NewRequest("POST", "http://127.0.0.1:18432/oauth/token", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, det := p.Do(context.Background(), "signin", r, nil)
	if det != "" {
		t.Fatalf("sign-in: %s", det)
	}
	resp.Body.Close()
	return p, roots
}

// A CLI guest reaches its provider's API only through its endpoint in the
// model clerk's process, holding a placeholder. Each model call is admitted
// against the plan's spend cap before it is sent and metered into the log
// from the usage its stream reported, with the pool's reading; the real
// login never reaches the guest, and a call past the cap is refused before
// anything is sent (PLN-5(a), CLK-7, LOG-7, RES-5).
func TestPlanGuestEndpointMetersEachCall(t *testing.T) {
	var calls atomic.Int32
	login, _ := planProvider(t, &calls)
	b, call := planGuest(t, login, 100, 1<<20)
	st, body := call(`{"model":"m","stream":true}`)
	if st != 200 || !strings.Contains(body, "response.completed") || strings.Contains(body, "real-access-1") {
		t.Fatalf("the guest got %d %q", st, body)
	}
	var used, pool kernel.Entry
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			switch e.Type {
			case kernel.TModelUsed:
				used = e
			case kernel.TPoolRead:
				pool = e
			}
		}
		return nil
	})
	if !strings.Contains(string(used.Body), `"amount":70`) || !strings.Contains(string(used.Body), `"source":"provider"`) {
		t.Fatalf("the metered use: %s", used.Body)
	}
	if !strings.Contains(string(pool.Body), `"used":250`) || !strings.Contains(string(pool.Body), `4000000000000`) {
		t.Fatalf("the pool reading: %s", pool.Body)
	}

	// 70 of 100 spent; the next call's worst case (27 in at a byte a token,
	// 50 out) does not fit, so it is refused with the cap's code and never
	// sent.
	st, body = call(`{"model":"m","stream":true}`)
	if st != http.StatusTooManyRequests || !strings.Contains(body, DPlanRefused+" "+key.RSpendTask) || calls.Load() != 1 {
		t.Fatalf("a call past the cap: %d %q, provider calls %d", st, body, calls.Load())
	}
}

// planGuest serves login's guest g on an endpoint charged to a live plan
// with a spend cap of task, at a declared context window of window tokens
// and 50 output tokens, and answers a client that posts a body as g.
func planGuest(t *testing.T, login *plan.Login, task, window int64) (*box, func(string) (int, string)) {
	t.Helper()
	b := newBoxFor(t, filepath.Join(shortDir(t), "web.sock"), "model", key.Read)
	root := key.Issue(ownerPriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, ownerPriv, holderPub, b.now, 1<<40, key.LimitSpendTask(task))
	if err != nil {
		t.Fatal(err)
	}
	cos := []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(root, ky)), key.Approve(sparePriv, kernel.BatchHash(root, ky))}
	pl := kernel.SignPlan(kernel.Plan{ID: "t", Key: ky, Steps: []kernel.PlanStep{{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}, holderPriv)
	if err := b.h.With(func(k *kernel.Kernel) error {
		if err := k.Issue(b.now-kernel.GrantHold, cos, root, ky); err != nil {
			return err
		}
		return k.Submit(b.now, pl)
	}); err != nil {
		t.Fatal(err)
	}

	g, err := login.Guest("g")
	if err != nil {
		t.Fatal(err)
	}
	c := &model.Clerk{Routes: map[string]model.Price{"codex": {InPerM: 1_000_000, OutPerM: 1_000_000, Pool: "codex"}},
		Ledger: proc.Meter{Conn: serveMeter(t, b)}}
	sock := filepath.Join(shortDir(t), "plan.sock")
	ln, err := ListenPlan(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServePlan(ln, PlanGuest{Login: login, Clerk: c, Guest: "g", Plan: "t", Route: "codex", Context: window, MaxOut: 50, Clock: func() int64 { return 0 }})
	cli := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	return b, func(in string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest("POST", "http://127.0.0.1:18432/backend-api/codex/responses", strings.NewReader(in))
		r.Header.Set("Authorization", "Bearer "+g.Tokens["access_token"])
		r.Header.Set("Content-Type", "application/json")
		resp, err := cli.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
}

// amounts are the log's spend reservations and metered uses, in order.
func amounts(t *testing.T, b *box) (reserved, used []int64) {
	t.Helper()
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			var v struct{ Amount int64 }
			if e.Type != kernel.TSpendReserved && e.Type != kernel.TModelUsed {
				continue
			}
			if err := json.Unmarshal(e.Body, &v); err != nil {
				t.Fatal(err)
			}
			if e.Type == kernel.TSpendReserved {
				reserved = append(reserved, v.Amount)
			} else {
				used = append(used, v.Amount)
			}
		}
		return nil
	})
	return reserved, used
}

// A call is admitted at the most its usage can be: its body's bytes as
// input, one byte a token (a token is at least one byte of the text), or
// the declared context window if smaller or if the body carries an image,
// whose tokens its bytes do not bound; and the declared output limit. So a
// call whose provider reports that most settles within its admission
// (MIG-4-plan-bound, LOG-7, RES-5).
func TestPlanGuestCallSettlesWithinItsAdmission(t *testing.T) {
	text := `{"model":"m","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"漢字漢字"}]}]}`
	image := `{"model":"m","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input\u005fimage","image_url":"data:image/png;base64,AA=="}]}]}`
	for _, c := range []struct {
		name, body string
		window     int64
		// in is the input tokens the provider reports, of the n bytes the
		// clerk sent: the most the bound allows.
		in func(n int64) int64
	}{
		{"text", text, 1 << 20, func(n int64) int64 { return n }},
		{"past the window", text, 40, func(int64) int64 { return 40 }},
		{"image", image, 3000, func(int64) int64 { return 3000 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			login, _ := planProviderUsing(t, &calls, func(n int) string {
				return fmt.Sprintf(`"usage":{"input_tokens":%d,"output_tokens":50}`, c.in(int64(n)))
			})
			b, call := planGuest(t, login, 1<<30, c.window)
			if st, body := call(c.body); st != 200 {
				t.Fatalf("the call: %d %q", st, body)
			}
			reserved, used := amounts(t, b)
			if len(reserved) != 1 || len(used) != 1 || used[0] != reserved[0] {
				t.Fatalf("admitted %v, settled %v: the most usage should settle at its admission", reserved, used)
			}
		})
	}
}

// A whole answer with no usage is the clerk's own count, never past the
// declared output limit, so it too settles within the admission.
func TestPlanGuestOwnCountSettlesWithinItsAdmission(t *testing.T) {
	var calls atomic.Int32
	login, _ := planProviderUsing(t, &calls, func(int) string { return `"pad":"` + strings.Repeat("x", 4096) + `"` })
	b, call := planGuest(t, login, 1<<30, 1<<20)
	if st, body := call(`{"model":"m","stream":true}`); st != 200 {
		t.Fatalf("the call: %d %q", st, body)
	}
	reserved, used := amounts(t, b)
	if len(reserved) != 1 || len(used) != 1 || used[0] != reserved[0] {
		t.Fatalf("admitted %v, settled %v", reserved, used)
	}
}

// A guest endpoint with no declared context window admits nothing.
func TestPlanGuestNeedsAContextWindow(t *testing.T) {
	var calls atomic.Int32
	login, _ := planProvider(t, &calls)
	_, call := planGuest(t, login, 1<<30, 0)
	if st, body := call(`{"model":"m","stream":true}`); st != http.StatusServiceUnavailable || !strings.Contains(body, DPlanMeter) || calls.Load() != 0 {
		t.Fatalf("no window: %d %q, provider calls %d", st, body, calls.Load())
	}
}

// Every detail maps to a status, and none carries a value (CLK-4).
func TestPlanStatusFromDetail(t *testing.T) {
	for d, want := range map[string]int{
		DPlanRefused + " spend-task":   http.StatusTooManyRequests,
		DPlanMeter:                     http.StatusServiceUnavailable,
		plan.DStopped + " unswappable": http.StatusServiceUnavailable,
		clerk.DBlocked:                 http.StatusBadGateway,
		clerk.DNoAnswer + " h":         http.StatusBadGateway,
		plan.DBody + " tool":           http.StatusForbidden,
		plan.DPlaceholder:              http.StatusForbidden,
		"plan-refusedX":                http.StatusForbidden,
	} {
		if got := planStatus(d); got != want {
			t.Errorf("%q: %d, want %d", d, got, want)
		}
	}
}
