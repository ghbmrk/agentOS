package sockprobe

// REQ: LOOP-7

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// told collects the refusals a server's Refused hook is told of.
type told struct {
	mu    sync.Mutex
	codes []sockets.Code
}

func (t *told) hook(_ sockets.Peer, c sockets.Code) {
	t.mu.Lock()
	t.codes = append(t.codes, c)
	t.mu.Unlock()
}

func (t *told) list() []sockets.Code {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]sockets.Code(nil), t.codes...)
}

func tempDir(t *testing.T) string {
	t.Helper()
	// Short: a unix socket path is limited to about 100 bytes.
	d, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// guestEndpoint is the daemon's guest socket, as daemon.Open builds it.
func guestEndpoint(tl *told) sockets.Endpoint {
	return sockets.Endpoint{
		Name: "guest-m1.sock", Peer: sockets.Peer{Kind: "guest", ID: "m1"}, MaxConns: 4, IdleTimeout: 30 * time.Second,
		Refused: tl.hook,
		Ops: map[string]sockets.Handler{
			"whoami": func(_ context.Context, p sockets.Peer, _ json.RawMessage) (any, error) { return p, nil },
		},
	}
}

// serve starts eps in a fresh run directory and returns it.
func serve(t *testing.T, eps ...sockets.Endpoint) string {
	t.Helper()
	dir := filepath.Join(tempDir(t), "run")
	ctx, cancel := context.WithCancel(context.Background())
	s := &sockets.Server{Dir: dir}
	if err := s.Start(ctx, eps...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Wait() })
	return dir
}

// guestView is the agent machine's view of the run directory: only its
// own socket, as the VM's mount gives it.
func guestView(t *testing.T, run string, names ...string) string {
	t.Helper()
	v := tempDir(t)
	for _, n := range names {
		if err := os.Symlink(filepath.Join(run, n), filepath.Join(v, n)); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func guestConfig(dir string) Config {
	return Config{Dir: dir, Declared: []string{"guest-m1.sock"}, Ping: "whoami"}
}

// LOOP-7 bullet 2: against the guest socket, every probe frame is refused
// with its fixed code, the broker answers the ping after each one as the
// same peer, and the server is told of every refusal (the daemon
// journals them; daemon/refused_test.go).
func TestTheGuestSocketPassesTheProbe(t *testing.T) {
	tl := &told{}
	run := serve(t, guestEndpoint(tl))
	res := Run(context.Background(), guestConfig(guestView(t, run, "guest-m1.sock")))
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %q", res.Failures)
	}
	if len(res.Sent) != len(Frames) {
		t.Fatalf("sent %+v", res.Sent)
	}
	var want []sockets.Code
	for i, s := range res.Sent {
		if s.Got != s.Want || s.Want != Frames[i].Want || s.Socket != "guest-m1.sock" {
			t.Fatalf("frame %d: %+v", i, s)
		}
		want = append(want, s.Want)
	}
	if got := tl.list(); strings.Join(codes(got), ",") != strings.Join(codes(want), ",") {
		t.Fatalf("server told %q, want %q", got, want)
	}
}

func codes(cs []sockets.Code) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}

// Planted controls: each defect the probe exists for is reported.
func TestTheProbeReportsAnUndeclaredSocket(t *testing.T) {
	tl := &told{}
	owner := sockets.Endpoint{Name: "owner.sock", Ops: map[string]sockets.Handler{
		"ping": func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return "ok", nil }}}
	run := serve(t, guestEndpoint(tl), owner)
	res := Run(context.Background(), guestConfig(guestView(t, run, "guest-m1.sock", "owner.sock")))
	if !has(res.Failures, "undeclared socket owner.sock is reachable") {
		t.Fatalf("failures: %q", res.Failures)
	}
}

func TestTheProbeReportsAMissingDeclaredSocket(t *testing.T) {
	res := Run(context.Background(), guestConfig(tempDir(t)))
	if !has(res.Failures, "declared socket guest-m1.sock is not reachable") {
		t.Fatalf("failures: %q", res.Failures)
	}
}

func TestTheProbeReportsALenientServer(t *testing.T) {
	// A server that answers every line OK, whatever it is.
	dir := tempDir(t)
	lenient(t, filepath.Join(dir, "guest-m1.sock"), func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			if _, err := r.ReadBytes('\n'); err != nil {
				return
			}
			c.Write([]byte(`{"ok":true,"result":{"kind":"guest","id":"m1"}}` + "\n"))
		}
	})
	res := Run(context.Background(), guestConfig(dir))
	for _, f := range Frames {
		if !has(res.Failures, f.Name+" on guest-m1.sock") {
			t.Fatalf("frame %s not reported: %q", f.Name, res.Failures)
		}
	}
}

func TestTheProbeReportsAServerThatStopsAnswering(t *testing.T) {
	// Refuses the first frame properly, then stops serving anyone.
	dir := tempDir(t)
	var mu sync.Mutex
	n := 0
	lenient(t, filepath.Join(dir, "guest-m1.sock"), func(c net.Conn) {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k > 2 { // the declared-socket ping and the first frame
			return
		}
		r := bufio.NewReader(c)
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		if strings.Contains(string(line), `"whoami"`) {
			c.Write([]byte(`{"ok":true,"result":{"kind":"guest","id":"m1"}}` + "\n"))
			return
		}
		c.Write([]byte(`{"ok":false,"error":"malformed request"}` + "\n"))
	})
	res := Run(context.Background(), Config{Dir: dir, Declared: []string{"guest-m1.sock"}, Ping: "whoami", Timeout: 300 * time.Millisecond})
	if !has(res.Failures, "unresponsive after") {
		t.Fatalf("failures: %q", res.Failures)
	}
}

// The probe sees nothing but the directory it is given and the declared
// names: a config with no ping or no declared socket is refused.
func TestABadConfigIsAFailure(t *testing.T) {
	for _, cfg := range []Config{{Dir: tempDir(t), Ping: "whoami"}, {Dir: tempDir(t), Declared: []string{"a.sock"}}, {Declared: []string{"a.sock"}, Ping: "whoami"}, {Dir: tempDir(t), Declared: []string{"../a.sock"}, Ping: "whoami"}} {
		if res := Run(context.Background(), cfg); len(res.Failures) == 0 || len(res.Sent) != 0 {
			t.Fatalf("%+v: %+v", cfg, res)
		}
	}
}

func lenient(t *testing.T, path string, h func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); h(c) }()
		}
	}()
}

func has(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
