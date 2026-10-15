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
