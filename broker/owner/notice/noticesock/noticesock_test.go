package noticesock

// REQ: OP-9, CH-3

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
)

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "n.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h}
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
	return path
}

func TestGetAsksTheSocketForBootAndAfter(t *testing.T) {
	var got string
	path := serve(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path + "?" + r.URL.RawQuery
		json.NewEncoder(w).Encode(notice.Batch{Boot: "b1", Missed: 2})
	})
	b, err := New(path).Get(context.Background(), "b1", 7)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/notices?after=7&boot=b1" || b.Boot != "b1" || b.Missed != 2 {
		t.Errorf("asked %q, got %+v", got, b)
	}
}

func TestGetRefusesANon200AndAnOversizeReply(t *testing.T) {
	path := serve(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) })
	if _, err := New(path).Get(context.Background(), "", 0); err == nil {
		t.Error("a 403 read as a batch")
	}
	big := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"boot":"`))
		for i := 0; i < maxReply+10; i++ {
			w.Write([]byte("x"))
		}
		w.Write([]byte(`"}`))
	})
	if _, err := New(big).Get(context.Background(), "", 0); err == nil {
		t.Error("an oversize reply was decoded")
	}
}

func TestGetOnlyEverDialsItsOwnSocket(t *testing.T) {
	// Whatever host the URL names, the connection is to the one socket.
	path := serve(t, func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(notice.Batch{Boot: "ok"}) })
	c := New(path)
	b, err := c.Get(context.Background(), "", 0)
	if err != nil || b.Boot != "ok" {
		t.Fatalf("%v %+v", err, b)
	}
}

func TestGetTimesOut(t *testing.T) {
	path := serve(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	c := New(path)
	c.Timeout = 100 * time.Millisecond
	if _, err := c.Get(context.Background(), "", 0); err == nil {
		t.Error("a hung socket did not time out")
	}
}
