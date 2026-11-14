package main

// REQ: ARC-6 (DEL-1d)

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// closeCount wraps a transport and counts the response bodies it hands
// out and the ones closed, so a test can see a body left open (each one
// holds its connection).
type closeCount struct {
	next           http.RoundTripper
	mu             sync.Mutex
	opened, closed int
}

func (c *closeCount) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.opened++
	c.mu.Unlock()
	resp.Body = &countedBody{resp.Body, c}
	return resp, nil
}

func (c *closeCount) open() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opened - c.closed
}

type countedBody struct {
	io.ReadCloser
	c *closeCount
}

func (b *countedBody) Close() error {
	b.c.mu.Lock()
	b.c.closed++
	b.c.mu.Unlock()
	return b.ReadCloser.Close()
}

// logs sends the log package's output to a buffer for the test's run.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
	hit chan struct{}
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hit != nil {
		select {
		case l.hit <- struct{}{}:
		default:
		}
	}
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLogs(t *testing.T) *logs {
	l := &logs{hit: make(chan struct{}, 1)}
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return l
}

// A 204 from /owner/next is "nothing waiting": no model call, no error.
// Any other status but 200 is an error naming it, and its body, even a
// well-formed message, is never handed to the model.
func TestOwnerNextStatusIsChecked(t *testing.T) {
	for _, c := range []struct {
		code int
		want string
	}{{http.StatusNoContent, ""}, {http.StatusInternalServerError, "next: 500 Internal Server Error"}} {
		broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
			if c.code != http.StatusNoContent {
				w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"x"}`))
			}
		}))
		var asks int
		gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			asks++
			w.Write([]byte(`{"choices":[{"message":{"content":"y"}}]}`))
		}))
		sleep = func(time.Duration) { t.Fatalf("%d: retried", c.code) }
		u, _ := url.Parse(broker.URL)
		err := ownerOnce(context.Background(), &http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t")
		sleep = time.Sleep
		broker.Close()
		gateway.Close()
		if got := ""; err != nil {
			got = err.Error()
			if got != c.want {
				t.Fatalf("%d: error %q, want %q", c.code, got, c.want)
			}
		} else if c.want != "" {
			t.Fatalf("%d: no error, want %q", c.code, c.want)
		}
		if asks != 0 {
			t.Fatalf("%d: model asked %d times", c.code, asks)
		}
	}
}

// An unreachable broker is an error from ownerOnce, not a crash.
func TestOwnerNextUnreachable(t *testing.T) {
	broker := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no broker")
	})}
	if err := ownerOnce(context.Background(), broker, "http://127.0.0.1:0", "m", "t"); err == nil || !strings.Contains(err.Error(), "no broker") {
		t.Fatalf("error %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Every response body the bridge reads, from the broker and from the
// guest's inbound API, is closed; a reply retry names the status it got.
func TestOwnerClosesBodiesAndLogsReplyStatus(t *testing.T) {
	l := captureLogs(t)
	var replies int
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner/next" {
			w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"x"}`))
			return
		}
		replies++
		if replies == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("later"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer broker.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"y"}}]}`))
	}))
	defer gateway.Close()
	guest := &closeCount{next: http.DefaultTransport}
	http.DefaultTransport = guest
	defer func() { http.DefaultTransport = guest.next }()
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()

	u, _ := url.Parse(broker.URL)
	b := &closeCount{next: rewrite{u}}
	if err := ownerOnce(context.Background(), &http.Client{Transport: b}, gateway.URL, "m", "t"); err != nil {
		t.Fatal(err)
	}
	if b.opened != 3 || b.open() != 0 {
		t.Fatalf("broker bodies: %d opened, %d left open", b.opened, b.open())
	}
	// rewrite reaches the broker through the default transport too.
	if guest.opened != 4 || guest.open() != 0 {
		t.Fatalf("default-transport bodies: %d opened, %d left open", guest.opened, guest.open())
	}
	if !strings.Contains(l.String(), "owner reply 0a0b0c0d0e0f: 503 Service Unavailable; retrying") {
		t.Fatalf("log %q", l.String())
	}
}

// The owner loop logs a failed round and waits before the next, until
// its context ends.
func TestOwnerLogsAFailedRound(t *testing.T) {
	l := captureLogs(t)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go owner(ctx, done, &http.Client{Transport: rewrite{u}}, "http://127.0.0.1:0", "m", "t")
	select {
	case <-l.hit:
	case <-time.After(5 * time.Second):
		t.Error("no log line for a failed round")
	}
	cancel()
	<-done
	if !strings.Contains(l.String(), "owner message: next: 500 Internal Server Error") {
		t.Fatalf("log %q", l.String())
	}
}

// ask sends the gateway token and a JSON content type, and a gateway it
// cannot reach is an error, not a crash.
func TestAskSendsTokenAndType(t *testing.T) {
	var auth, ctype string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ctype = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		w.Write([]byte(`{"choices":[{"message":{"content":"y"}}]}`))
	}))
	if got, err := ask(gateway.URL, "m", "t0k", "x"); err != nil || got != "y" {
		t.Fatalf("ask: %q, %v", got, err)
	}
	gateway.Close()
	if auth != "Bearer t0k" || ctype != "application/json" {
		t.Fatalf("headers %q %q", auth, ctype)
	}
	if _, err := ask(gateway.URL, "m", "t0k", "x"); err == nil {
		t.Fatal("closed gateway: no error")
	}
}

// The broker sees Host broker.localhost whatever address the transport
// dials, as on the machine's socket.
func TestRoutesSendBrokerHost(t *testing.T) {
	var host string
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)
	bridge := httptest.NewServer(routes(&http.Client{Transport: rewrite{u}}, t.TempDir()))
	defer bridge.Close()
	resp, err := http.Get(bridge.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if host != "broker.localhost" {
		t.Fatalf("host %q", host)
	}
}
