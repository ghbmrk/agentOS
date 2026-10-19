package guest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: CRED-8, K18g-3

// A guest that stops reading a reply fails the plane's next write within
// WriteTimeout, so its request ends and frees its slot (CRED-8, egress K18).
func TestPlaneWriteDeadlineFreesStalledGuest(t *testing.T) {
	done := make(chan struct{}, 4)
	r := newRig(t, func(c *Config) {
		c.MaxConns = 1
		c.Meter = roomyMeter(t)
		c.WriteTimeout = 200 * time.Millisecond
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/big" {
					chunk := []byte(strings.Repeat("x", 64<<10))
					for i := 0; i < 128; i++ { // 8 MiB, past any socket buffer
						w.Write(chunk)
					}
					done <- struct{}{}
					return
				}
				io.WriteString(w, "ok")
			})
		}
	})
	r.client("m1")
	conn, err := net.Dial("unix", filepath.Join(r.p.cfg.Dir, "m1", Socket))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /model/big HTTP/1.1\r\nHost: broker\r\n\r\n") // and never read
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a guest that stopped reading held its request past the write deadline")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := r.do("m1", "GET", "/model/small", "")
		if code == 200 && body == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stalled guest's slot was not freed: %d %s", code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The deadline is per write, not for the whole reply: a streamed reply that
// lasts longer than WriteTimeout, read as it comes, and a reply whose first
// byte comes later than WriteTimeout, and one the server sends when the
// handler returns later than that, all arrive whole (K18g-3).
func TestPlaneWriteDeadlineKeepsLongReplies(t *testing.T) {
	const d = 200 * time.Millisecond
	r := newRig(t, func(c *Config) {
		c.WriteTimeout = d
		c.Meter = roomyMeter(t)
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/stream":
					w.Header().Set("Content-Type", "text/event-stream")
					for i := 0; i < 8; i++ {
						fmt.Fprintf(w, "data: %d\n\n", i)
						w.(http.Flusher).Flush()
						time.Sleep(d / 2)
					}
				case "/slow":
					time.Sleep(2 * d)
					io.WriteString(w, `{"ok":true}`)
				case "/late": // buffered, then sent when the handler returns
					io.WriteString(w, `{"ok":true}`)
					time.Sleep(2 * d)
				}
			})
		}
	})
	resp, err := r.client("m1").Get("http://broker/model/stream")
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	var got []string
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			got = append(got, l)
		}
	}
	resp.Body.Close()
	if len(got) != 8 || got[7] != "data: 7" {
		t.Fatalf("a streamed reply longer than the write deadline was cut: %q (%v)", got, sc.Err())
	}
	if code, body := r.do("m1", "GET", "/model/slow", ""); code != 200 || body != `{"ok":true}` {
		t.Fatalf("a reply that started after the write deadline was cut: %d %q", code, body)
	}
	if code, body := r.do("m1", "GET", "/model/late", ""); code != 200 || body != `{"ok":true}` {
		t.Fatalf("a reply flushed after the handler returned was cut: %d %q", code, body)
	}
}

// Without a configured WriteTimeout the plane still deadlines each write.
func TestPlaneWriteDeadlineDefault(t *testing.T) {
	r := newRig(t, nil)
	if r.p.cfg.WriteTimeout != DefaultWriteTimeout || DefaultWriteTimeout <= 0 {
		t.Fatalf("WriteTimeout defaulted to %v", r.p.cfg.WriteTimeout)
	}
}

// roomyMeter meters calls without limiting these tests, whose replies (8 MiB
// stalled, several calls) would spend the rig's caps.
func roomyMeter(t *testing.T) *meter.Meter {
	m, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 100, Tokens: 1 << 40},
		OverallCap: meter.Limits{Calls: 100, Tokens: 1 << 40},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
