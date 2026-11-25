package modelroute

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// REQ: A14, RES-5

type closeSpy struct {
	io.Reader
	closed *bool
}

func (s closeSpy) Close() error { *s.closed = true; return nil }

type spyTransport struct{ closed *bool }

func (s spyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: closeSpy{strings.NewReader("ok"), s.closed}}, nil
}

// The control client carries a 10s bound (a stalled vault must not hang the
// broker) and closes every reply body, even a failing one.
func TestA14RouteControlBoundsTheCallAndClosesTheReply(t *testing.T) {
	c := NewRouteControl("/nonexistent.sock")
	if c.c.Timeout != 10*time.Second {
		t.Fatalf("control client timeout = %v, want 10s", c.c.Timeout)
	}
	closed := false
	c.c.Transport = spyTransport{&closed}
	if _, err := c.call("open", "pw-a", 16); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("reply body left open")
	}
}
