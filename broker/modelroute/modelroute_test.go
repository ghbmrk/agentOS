package modelroute

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: ARC-1, CRED-1, REV-5, ADP-10, ARC-6

// fakeEgress stands in for the vault process on its model socket.
type fakeEgress struct {
	mu   sync.Mutex
	seen []*http.Request
	h    http.HandlerFunc
}

func (f *fakeEgress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r)
	f.mu.Unlock()
	f.h(w, r)
}

func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return path
}

type denials struct {
	mu  sync.Mutex
	got []string
	ds  []Denial
}

func (d *denials) add(machine string, x Denial) {
	d.mu.Lock()
	d.got = append(d.got, machine)
	d.ds = append(d.ds, x)
	d.mu.Unlock()
}

// The broker, not the guest, names the machine and its label to the vault
// process: guest-sent copies of those headers are replaced. A denial the
// vault process reports comes back to the broker's journal under the
// machine the broker forwarded for, and never reaches the guest.
func TestForwardNamesMachineAndLabelAndReturnsDenials(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openai/v1/chat/completions" {
			io.WriteString(w, `{"ok":true}`)
			return
		}
		b, _ := json.Marshal(Denial{Adapter: "openai", Method: r.Method, Status: 403, Reason: "no declared operation matches", Machine: "someone-else"})
		w.Header().Set(HeaderDenial, string(b))
		http.Error(w, "egress denied", 403)
	}}
	sock := serveUnix(t, fe)
	d := &denials{}
	labels := map[string]string{"m1": "private", "m2": "public"}
	fwd := Forward(Config{Socket: sock, Label: func(m string) string { return labels[m] }, Denied: d.add})

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set(HeaderMachine, "m2")
	req.Header.Set(HeaderLabel, "public")
	req.Header.Set("Agentos-Anything", "x")
	w := httptest.NewRecorder()
	fwd("m1").ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` {
		t.Fatalf("forwarded: %d %s", w.Code, w.Body)
	}
	got := fe.seen[0]
	if got.Header.Get(HeaderMachine) != "m1" || got.Header.Get(HeaderLabel) != "private" || got.Header.Get("Agentos-Anything") != "" {
		t.Fatalf("vault process saw machine %q label %q", got.Header.Get(HeaderMachine), got.Header.Get(HeaderLabel))
	}

	w = httptest.NewRecorder()
	fwd("m1").ServeHTTP(w, httptest.NewRequest("GET", "/openai/v1/models", nil))
	if w.Code != 403 || w.Header().Get(HeaderDenial) != "" {
		t.Fatalf("denial: %d, header leaked: %q", w.Code, w.Header().Get(HeaderDenial))
	}
	if len(d.got) != 1 || d.got[0] != "m1" || d.ds[0].Reason != "no declared operation matches" || d.ds[0].Status != 403 {
		t.Fatalf("journaled %v %+v", d.got, d.ds)
	}
}

// The path reaches the vault process byte for byte, escapes and dot
// segments included, so its shape checks see what the guest sent rather
// than a decoded or cleaned copy that matches a served path (ADP-10).
func TestForwardKeepsThePathAsSent(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.RequestURI) }}
	fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "public" }, Denied: (&denials{}).add})
	for _, p := range []string{"/v1/chat%2Fcompletions", "/openai%2Fv1/chat/completions", "/v1/../v1/chat/completions", "/v1/./chat/completions", "/%761/chat/completions"} {
		w := httptest.NewRecorder()
		fwd("m1").ServeHTTP(w, httptest.NewRequest("POST", p, strings.NewReader(`{}`)))
		if w.Body.String() != p {
			t.Errorf("sent %s, vault process saw %s", p, w.Body)
		}
	}
}

// A machine with no known label is sent as private, never as public.
func TestUnknownLabelIsSentAsPrivate(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "" }, Denied: func(string, Denial) {}})
	fwd("m1").ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/openai/v1/chat/completions", nil))
	if l := fe.seen[0].Header.Get(HeaderLabel); l != "private" {
		t.Fatalf("label %q", l)
	}
}

// With the vault process down, the guest gets 503, as when the vault is
// locked; nothing hangs.
func TestVaultProcessDownIs503(t *testing.T) {
	fwd := Forward(Config{Socket: filepath.Join(t.TempDir(), "absent.sock"), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	w := httptest.NewRecorder()
	fwd("m1").ServeHTTP(w, httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", w.Code)
	}
}

// A metered call the vault process never answers is charged its input
// estimate only: the 503 page the guest gets is the broker's, not model
// output (OP-8).
func TestUnansweredCallChargesNoOutput(t *testing.T) {
	fwd := Forward(Config{Socket: filepath.Join(t.TempDir(), "absent.sock"), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"model":"default","max_tokens":100}`
	w := httptest.NewRecorder()
	m.Wrap("m1", fwd("m1")).ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", w.Code)
	}
	if u, want := m.Usage("m1"), meter.Tokens(int64(len(body))); u.Tokens != want || u.Calls != 1 {
		t.Fatalf("charged %d tokens and %d calls, want %d and 1", u.Tokens, u.Calls, want)
	}
}

// Token streams keep flowing: each chunk the vault process flushes reaches
// the guest before the response ends.
func TestStreamsAreFlushed(t *testing.T) {
	next := make(chan struct{})
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-next
		io.WriteString(w, "data: two\n\n")
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	srv := httptest.NewServer(fwd("m1"))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/openai/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "one") {
		t.Fatalf("first chunk %q", buf[:n])
	}
	close(next)
	rest, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(rest), "two") {
		t.Fatalf("rest %q", rest)
	}
}

// gateBody hands over the guest's request body, then holds the
// transport's trailing EOF read until gate closes.
type gateBody struct {
	orig io.ReadCloser
	gate chan struct{}
	eof  bool
}

func (g *gateBody) Read(b []byte) (int, error) {
	if g.eof {
		<-g.gate
		return g.orig.Read(b)
	}
	n, err := g.orig.Read(b)
	if err == io.EOF {
		g.eof = true
		if n == 0 {
			<-g.gate
			return g.orig.Read(b)
		}
		return n, nil
	}
	return n, err
}

func (g *gateBody) Close() error { return g.orig.Close() }

// The guest's request body stays readable by the transport after the
// response has started. Its trailing EOF read is held until the guest has
// the first chunk; had the server drained and closed the body when the
// response began, that read would fail, the transport would drop the
// vault connection, and the rest of the stream would be lost.
func TestStreamSurvivesTrailingBodyRead(t *testing.T) {
	next := make(chan struct{})
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-next
		// A dropped connection shows here as a cancelled request; the
		// second chunk must not race it.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
		io.WriteString(w, "data: two\n\n")
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = &gateBody{orig: r.Body, gate: gate}
		fwd("m1").ServeHTTP(w, r)
	}))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/openai/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "one") {
		t.Fatalf("first chunk %q", buf[:n])
	}
	close(gate)
	close(next)
	rest, err := io.ReadAll(resp.Body)
	if !strings.Contains(string(rest), "two") {
		t.Fatalf("rest %q err %v", rest, err)
	}
}

// Our headers never reach the guest as trailers either.
func TestTrailersAreScrubbed(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", HeaderDenial+", X-Other")
		io.WriteString(w, "body")
		w.Header().Set(HeaderDenial, `{"reason":"x"}`)
		w.Header().Set("X-Other", "kept")
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	srv := httptest.NewServer(fwd("m1"))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/openai/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Trailer.Get(HeaderDenial) != "" || resp.Trailer.Get("X-Other") != "kept" {
		t.Fatalf("trailers %v", resp.Trailer)
	}
}

// A served call's usage trailer reaches the meter once, on the metered
// call, and never the guest.
func TestUsageTrailerReachesMeterNotGuest(t *testing.T) {
	trailer := `{"provider":"anthropic","input":12,"cache_read":100,"output":7,"reported":true,"complete":true,"output_chars":40}`
	for _, c := range []struct {
		name, value string
		want        int64 // tokens charged
	}{
		// 12 + 100*0.1 input, 7 output.
		{"reported", trailer, 29},
		// No usable report: the meter's own count (Tokens of the
		// request bytes and the 2 content characters it saw).
		{"absent", "", -1},
		{"malformed", `{"provider":`, -1},
		{"negative", strings.Replace(trailer, `"output":7`, `"output":-7`, 1), -1},
		{"oversized", `{"provider":"` + strings.Repeat("a", maxUsage) + `"}`, -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", HeaderUsage)
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, `data: {"choices":[{"delta":{"content":"hi"}}]}`+"\n\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, "data: [DONE]\n\n")
				if c.value != "" {
					w.Header().Set(HeaderUsage, c.value)
				}
			}}
			sock := serveUnix(t, fe)
			fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
			m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30}})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(m.Wrap("m1", fwd("m1")))
			defer srv.Close()
			const body = `{"model":"default","max_tokens":100}`
			resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.HasSuffix(string(got), "[DONE]\n\n") {
				t.Fatalf("body %q", got)
			}
			for k := range resp.Trailer {
				if strings.HasPrefix(k, headerPrefix) {
					t.Fatalf("guest got trailer %s", k)
				}
			}
			if strings.Contains(resp.Header.Get("Trailer"), HeaderUsage) {
				t.Fatalf("guest was told of the usage trailer: %q", resp.Header.Get("Trailer"))
			}
			want := c.want
			if want < 0 {
				want = meter.Tokens(int64(len(body))) + meter.Tokens(2)
			}
			if u := m.Usage("m1"); u.Tokens != want {
				t.Fatalf("charged %d tokens, want %d", u.Tokens, want)
			}
		})
	}
}

// The proxy's own denial mark never reaches the guest.
func TestEgressDeniedMarkIsScrubbed(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Agentos-Egress-Denied", "1")
		http.Error(w, "egress denied: test", http.StatusForbidden)
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	srv := httptest.NewServer(fwd("m1"))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("X-Agentos-Egress-Denied") != "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
}

// A body cut off before its end reports no usage, even with a trailer
// declared: the meter keeps its own count of what the guest got.
func TestTruncatedBodyReportsNoUsage(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		// Read the request first: closing a socket with unread data
		// resets it, and a reset can reach the broker before the
		// response does, which turns the call into a 503 with no
		// stream to cut.
		io.Copy(io.Discard, r.Body)
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		chunk := `data: {"choices":[{"delta":{"content":"hi"}}]}` + "\n\n"
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTrailer: Agentos-Usage\r\nTransfer-Encoding: chunked\r\n\r\n")
		buf.WriteString(strconv.FormatInt(int64(len(chunk)), 16) + "\r\n" + chunk + "\r\n")
		buf.Flush()
		conn.Close() // no last chunk, so no trailer
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"model":"default","max_tokens":100}`
	w := httptest.NewRecorder()
	m.Wrap("m1", fwd("m1")).ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	if want := meter.Tokens(int64(len(body))) + meter.Tokens(2); m.Usage("m1").Tokens != want {
		t.Fatalf("charged %d tokens, want the counted floor %d", m.Usage("m1").Tokens, want)
	}
}

// REQ: LOOP-5, CHG-1

// A replay machine's calls go to the vault process like a live machine's,
// always labelled private, carrying the routing rule of the tree under
// evaluation; the vault process applies it within the owner's grants. A
// guest cannot send a rule of its own, and a machine outside the replay
// prefix never gets the evaluation route.
func TestLOOP5EvaluationCallsCarryTheTreesRule(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}`) }}
	sock := serveUnix(t, fe)
	ev := Evaluation(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: (&denials{}).add, OverCeiling: func(string) {}})

	rule := []byte(`{"chat":[{"provider":"anthropic","model":"m"}]}`)
	for _, c := range []struct {
		rule []byte
		want string
	}{{rule, base64.StdEncoding.EncodeToString(rule)}, {nil, ""}} {
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`))
		req.Header.Set(HeaderRule, "eyJndWVzdCI6MX0=")
		w := httptest.NewRecorder()
		ev("eval-0a1b", c.rule).ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		fe.mu.Lock()
		got := fe.seen[len(fe.seen)-1]
		fe.mu.Unlock()
		if got.Header.Get(HeaderRule) != c.want || got.Header.Get(HeaderLabel) != "private" || got.Header.Get(HeaderMachine) != "eval-0a1b" {
			t.Errorf("rule %q label %q machine %q", got.Header.Get(HeaderRule), got.Header.Get(HeaderLabel), got.Header.Get(HeaderMachine))
		}
	}

	n := len(fe.seen)
	w := httptest.NewRecorder()
	ev("agent", rule).ServeHTTP(w, httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`)))
	if w.Code != http.StatusServiceUnavailable || len(fe.seen) != n {
		t.Fatalf("non-replay machine: status %d, forwarded %d", w.Code, len(fe.seen)-n)
	}

	// The live route never forwards a rule, whatever the guest sends.
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set(HeaderRule, base64.StdEncoding.EncodeToString(rule))
	Forward(Config{Socket: sock, Label: func(string) string { return "private" }, Denied: (&denials{}).add})("agent").ServeHTTP(httptest.NewRecorder(), req)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if r := fe.seen[len(fe.seen)-1]; r.Header.Get(HeaderRule) != "" {
		t.Fatalf("live route forwarded a rule: %q", r.Header.Get(HeaderRule))
	}
}

// Evaluation needs somewhere to report a ceiling refusal: without
// OverCeiling it forwards nothing. With it, a refusal the vault process
// gives with ReasonEvalCeiling names the replay machine to OverCeiling,
// and other denials do not.
func TestLOOP5CeilingRefusalsReachTheEvaluator(t *testing.T) {
	var reason atomic.Value
	reason.Store(ReasonEvalCeiling)
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(Denial{Adapter: "router", Method: r.Method, Status: 403, Reason: reason.Load().(string)})
		w.Header().Set(HeaderDenial, string(b))
		http.Error(w, "refused", 403)
	}}
	sock := serveUnix(t, fe)
	call := func(cfg Config) {
		w := httptest.NewRecorder()
		Evaluation(cfg)("eval-0a1b", nil).ServeHTTP(w, httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`)))
	}
	cfg := Config{Socket: sock, Label: func(string) string { return "private" }, Denied: (&denials{}).add}
	call(cfg)
	fe.mu.Lock()
	n := len(fe.seen)
	fe.mu.Unlock()
	if n != 0 {
		t.Fatal("forwarded without OverCeiling")
	}
	var over []string
	cfg.OverCeiling = func(m string) { over = append(over, m) }
	call(cfg)
	reason.Store("no declared operation matches")
	call(cfg)
	if len(over) != 1 || over[0] != "eval-0a1b" {
		t.Fatalf("OverCeiling got %q", over)
	}
}
