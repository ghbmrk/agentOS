package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: A14, CRED-5, A3

// sockServer serves handler on a unix socket in a fresh directory, standing in for the egress
// route socket mounted at /run/agentos.
func sockServer(t *testing.T, h http.Handler) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "route.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return p
}

func start(t *testing.T, socket string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go relay(ctx, ln, socket)
	return ln.Addr().String()
}

// TestA14ForwarderRelaysHTTPToTheRouteSocket: a request to the loopback port reaches the route
// socket byte for byte and the answer comes back; the forwarder adds no route of its own.
func TestA14ForwarderRelaysHTTPToTheRouteSocket(t *testing.T) {
	var got string
	sock := sockServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = r.Method + " " + r.URL.Path + " " + string(b)
		w.Header().Set("X-Route", "yes")
		w.Write([]byte("answer"))
	}))
	addr := start(t, sock)
	resp, err := http.Post("http://"+addr+"/backend-api/codex/responses", "application/json", strings.NewReader(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "answer" || resp.Header.Get("X-Route") != "yes" {
		t.Fatalf("reply %q %v", b, resp.Header)
	}
	if got != `POST /backend-api/codex/responses {"x":1}` {
		t.Fatalf("socket saw %q", got)
	}
}

// TestA14ForwarderHoldsNoOtherDestination: with the socket gone, a connection is closed rather
// than sent anywhere else (fail closed).
func TestA14ForwarderHoldsNoOtherDestination(t *testing.T) {
	addr := start(t, filepath.Join(t.TempDir(), "absent.sock"))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		t.Fatal("got data with no route socket")
	}
}

// TestA3ForwarderListensOnLoopbackOnly: only 127.0.0.1 addresses are accepted for -listen.
func TestA3ForwarderListensOnLoopbackOnly(t *testing.T) {
	for _, a := range []string{"0.0.0.0:18432", ":18432", "10.0.0.1:18432", "[::]:18432", "example.com:18432"} {
		if err := checkListen(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
	if err := checkListen("127.0.0.1:18432"); err != nil {
		t.Fatal(err)
	}
}

// TestCRED5ForwarderStartsTheCLIAfterListening: the command after -- runs once the port is bound,
// and its exit status is the forwarder's.
func TestCRED5ForwarderStartsTheCLIAfterListening(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	code := run([]string{"-listen", "127.0.0.1:0", "-socket", filepath.Join(dir, "s.sock"), "--",
		"/bin/sh", "-c", `echo "$AGENTOS_FORWARDER_ADDR" > ` + out + `; exit 7`})
	if code != 7 {
		t.Fatalf("exit %d, want the child's 7", code)
	}
	if b, _ := os.ReadFile(out); !strings.HasPrefix(string(b), "127.0.0.1:") {
		t.Fatalf("child saw address %q", b)
	}
}

// TestA14ForwarderCapsConnections: past maxConns open relays the forwarder accepts and closes the
// next connection at once, so a runaway CLI cannot exhaust the worker's fds or memory; when a relay
// ends the slot frees.
func TestA14ForwarderCapsConnections(t *testing.T) {
	old := maxConns
	maxConns = 1
	defer func() { maxConns = old }()
	hold := make(chan struct{})
	sock := sockServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hold
	}))
	addr := start(t, sock)
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(first, "GET /backend-api/codex/models HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := second.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("a connection past the cap was relayed (%d, %v)", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("a connection past the cap was held open, not closed")
	}
	close(hold)
	first.Close()
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get("http://" + addr + "/backend-api/codex/models")
	if err != nil {
		t.Fatalf("after the slot freed: %v", err)
	}
	resp.Body.Close()
}

// TestA14ForwarderClosesIdleRelays: a relay with no traffic either way for idleTimeout is closed.
func TestA14ForwarderClosesIdleRelays(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	defer func() { idleTimeout = old }()
	sock := sockServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := start(t, sock)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("an idle relay sent data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("an idle relay was never closed")
	}
	if time.Since(start) < idleTimeout {
		t.Fatal("the relay closed before it was idle")
	}
}
