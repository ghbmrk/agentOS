package modelroute

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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

// reporter stands in for the OP-8 meter's ResponseWriter.
type reporter struct {
	http.ResponseWriter
	mu    sync.Mutex
	got   []string
	whole []bool
}

func (r *reporter) ReportUsage(u []byte, complete bool) {
	r.mu.Lock()
	r.got = append(r.got, string(u))
	r.whole = append(r.whole, complete)
	r.mu.Unlock()
}

func (r *reporter) Flush() { r.ResponseWriter.(http.Flusher).Flush() }

// A served call's usage trailer reaches the meter once and never the guest.
func TestUsageTrailerReachesMeterNotGuest(t *testing.T) {
	trailer := `{"usage":{"input_tokens":12,"cache_read_input_tokens":100,"output_tokens":7},"complete":true}`
	for _, c := range []struct {
		name, value string
		want        []string
	}{
		{"reported", trailer, []string{`{"input_tokens":12,"cache_read_input_tokens":100,"output_tokens":7}`}},
		{"absent", "", nil},
		{"malformed", `{"usage":`, nil},
		{"oversized", `{"usage":{"x":"` + strings.Repeat("a", maxUsage) + `"},"complete":true}`, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", HeaderUsage)
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: {}\n\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, "data: [DONE]\n\n")
				if c.value != "" {
					w.Header().Set(HeaderUsage, c.value)
				}
			}}
			sock := serveUnix(t, fe)
			fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
			rep := &reporter{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rep.ResponseWriter = w
				fwd("m1").ServeHTTP(rep, r)
			}))
			defer srv.Close()
			resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.HasSuffix(string(body), "[DONE]\n\n") {
				t.Fatalf("body %q", body)
			}
			for k := range resp.Trailer {
				if strings.HasPrefix(k, headerPrefix) {
					t.Fatalf("guest got trailer %s", k)
				}
			}
			if strings.Contains(resp.Header.Get("Trailer"), HeaderUsage) {
				t.Fatalf("guest was told of the usage trailer: %q", resp.Header.Get("Trailer"))
			}
			rep.mu.Lock()
			defer rep.mu.Unlock()
			if len(rep.got) != len(c.want) || (len(c.want) == 1 && (rep.got[0] != c.want[0] || !rep.whole[0])) {
				t.Fatalf("reported %q %v, want %q", rep.got, rep.whole, c.want)
			}
		})
	}
}

// A guest-side writer that charges nothing just gets the response.
func TestUsageTrailerWithoutReporter(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", HeaderUsage)
		io.WriteString(w, "ok")
		w.Header().Set(HeaderUsage, `{"usage":{"output_tokens":1},"complete":true}`)
	}}
	sock := serveUnix(t, fe)
	fwd := Forward(Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	srv := httptest.NewServer(fwd("m1"))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" || resp.Trailer.Get(HeaderUsage) != "" {
		t.Fatalf("%q %v", body, resp.Trailer)
	}
}
