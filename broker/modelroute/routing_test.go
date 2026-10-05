package modelroute

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// REQ: ADP-4

// The routing client (W3, potency PW4 on #90) fails rather than report a
// rule it does not have: the vault process down, or answering no rule,
// is an error, so the change pipeline never records an empty rule as the
// router's.
func TestRoutingStateIsNeverEmpty(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "routing.sock")
	ctx := context.Background()
	if _, err := NewRouting(sock).State(ctx); err == nil {
		t.Fatal("state with the vault process down")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rule":{},"candidate":{}}`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	if _, err := NewRouting(sock).State(ctx); err == nil {
		t.Fatal("an empty rule was reported")
	}
}
