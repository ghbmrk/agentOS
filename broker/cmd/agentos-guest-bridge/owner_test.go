package main

// REQ: ARC-6 (DEL-1d)

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}

// DEL-1d: the bridge keeps its answer until the broker has it. A 503
// (the broker could not store the reply), a 429 (the machine had too many
// requests in flight) or a 502 is retried after a backoff with the same
// body; the model is asked once.
func TestDEL1BridgeRetriesTheReplyNotTheModel(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	codes := []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusNoContent}
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/owner/next":
			w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"book the dentist"}`))
		case "/owner/reply":
			b, _ := io.ReadAll(r.Body)
			posts = append(posts, string(b))
			w.WriteHeader(codes[len(posts)-1])
		}
	}))
	defer broker.Close()
	var asks int
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asks++
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": "booked"}}}})
	}))
	defer gateway.Close()
	var waits []time.Duration
	sleep = func(d time.Duration) { waits = append(waits, d) }
	defer func() { sleep = time.Sleep }()

	u, _ := url.Parse(broker.URL)
	if err := ownerOnce(&http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t"); err != nil {
		t.Fatal(err)
	}
	if asks != 1 || len(posts) != 4 || posts[0] != posts[1] || posts[0] != posts[2] || posts[0] != posts[3] || posts[0] != `{"id":"0a0b0c0d0e0f","text":"booked"}` {
		t.Fatalf("asks %d, posts %q", asks, posts)
	}
	if len(waits) != 3 || waits[0] != time.Second || waits[1] != 2*time.Second || waits[2] != 4*time.Second {
		t.Fatalf("waits %v", waits)
	}
}

// DEL-1d: a 409, 404 or 400 is final: the broker has an answer, never had
// the message, or can never take this body, so the bridge stops without
// retrying.
func TestDEL1BridgeStopsOnFinalAnswers(t *testing.T) {
	for _, code := range []int{http.StatusConflict, http.StatusNotFound, http.StatusBadRequest} {
		var posts int
		broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/owner/next" {
				w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"x"}`))
				return
			}
			posts++
			w.WriteHeader(code)
		}))
		gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"choices":[{"message":{"content":"y"}}]}`))
		}))
		sleep = func(time.Duration) { t.Fatal("retried a final answer") }
		u, _ := url.Parse(broker.URL)
		ownerOnce(&http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t")
		sleep = time.Sleep
		broker.Close()
		gateway.Close()
		if posts != 1 {
			t.Fatalf("%d: %d posts", code, posts)
		}
	}
}
