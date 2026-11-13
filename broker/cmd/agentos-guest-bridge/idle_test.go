package main

// REQ: ARC-6, ARC-7

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// GUEST-bridge-tree-dead: agentosd serves no managed_tree tool
// (MIG-4-untrusted-learn), so the bridge's idle work makes no broker tool
// call at all: the only request it sends unprompted is the owner poll.
// Failure path: the bridge polls a removed tool forever and logs the
// unknown-tool answer.
func TestBridgeMakesNoToolCallAtIdle(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]int{}
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)

	background(&http.Client{Transport: rewrite{u}}, "http://127.0.0.1:1", "m", "tok")
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		polled := paths["/owner/next"]
		mu.Unlock()
		if polled > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if paths["/owner/next"] == 0 {
		t.Fatal("the owner poll never ran")
	}
	for p, n := range paths {
		if p != "/owner/next" {
			t.Errorf("idle bridge sent %d request(s) to %s", n, p)
		}
	}
}
