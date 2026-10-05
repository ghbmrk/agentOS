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
