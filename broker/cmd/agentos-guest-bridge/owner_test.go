package main

// REQ: ARC-6 (DEL-1d)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	if err := ownerOnce(context.Background(), &http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t"); err != nil {
		t.Fatal(err)
	}
	if asks != 1 || len(posts) != 4 || posts[0] != posts[1] || posts[0] != posts[2] || posts[0] != posts[3] || posts[0] != `{"id":"0a0b0c0d0e0f","text":"booked"}` {
		t.Fatalf("asks %d, posts %q", asks, posts)
	}
	if len(waits) != 3 || waits[0] != time.Second || waits[1] != 2*time.Second || waits[2] != 4*time.Second {
		t.Fatalf("waits %v", waits)
	}
}

// DEL-1d: a 409 or 404 is final: the broker has an answer or never had
// the message, so the bridge stops without retrying.
func TestDEL1BridgeStopsOnFinalAnswers(t *testing.T) {
	for _, code := range []int{http.StatusConflict, http.StatusNotFound} {
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
		ownerOnce(context.Background(), &http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t")
		sleep = time.Sleep
		broker.Close()
		gateway.Close()
		if posts != 1 {
			t.Fatalf("%d: %d posts", code, posts)
		}
	}
}

// CH-11 (#2297): a 400 is the broker refusing this answer (an agent
// reaction, or a body it can never take) while the owner message stays
// pending. The bridge asks the model once more, with its refused answer and
// the broker's refusal words in the conversation, and posts that answer
// without a backoff. A second refusal is final, so one message never
// stalls the ones after it.
func TestCH11BridgeAsksAgainAfterARefusal(t *testing.T) {
	const refusal = "agent reactions are refused; reply in text"
	for _, tc := range []struct {
		name  string
		codes []int
		ok    bool
	}{
		{"accepted on the second answer", []int{http.StatusBadRequest, http.StatusNoContent}, true},
		{"refused twice", []int{http.StatusBadRequest, http.StatusBadRequest}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var posts []string
			broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/owner/next" {
					w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"book the dentist"}`))
					return
				}
				b, _ := io.ReadAll(r.Body)
				posts = append(posts, string(b))
				if len(posts) > len(tc.codes) {
					t.Errorf("post %d after a final answer", len(posts))
					return
				}
				if code := tc.codes[len(posts)-1]; code == http.StatusBadRequest {
					http.Error(w, refusal, code)
				} else {
					w.WriteHeader(code)
				}
			}))
			defer broker.Close()
			type turn struct{ Role, Content string }
			var asks [][]turn
			answers := []string{"\U0001F44D", "Booked for Tuesday."}
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct{ Messages []turn }
				json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				asks = append(asks, req.Messages)
				a := answers[min(len(asks), len(answers))-1]
				mu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": a}}}})
			}))
			defer gateway.Close()
			sleep = func(time.Duration) { t.Error("waited before re-asking or after a final answer") }
			defer func() { sleep = time.Sleep }()

			u, _ := url.Parse(broker.URL)
			err := ownerOnce(context.Background(), &http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t")
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok %v", err, tc.ok)
			}
			if len(asks) != 2 || len(posts) != 2 {
				t.Fatalf("asks %d, posts %q", len(asks), posts)
			}
			if len(asks[0]) != 1 || asks[0][0] != (turn{"user", "book the dentist"}) {
				t.Fatalf("first ask %+v", asks[0])
			}
			second := asks[1]
			if len(second) != 3 || second[0] != asks[0][0] || second[1] != (turn{"assistant", answers[0]}) ||
				second[2].Role != "user" || !strings.Contains(second[2].Content, refusal) {
				t.Fatalf("second ask %+v", second)
			}
			if posts[0] != `{"id":"0a0b0c0d0e0f","text":"`+answers[0]+`"}` {
				t.Fatalf("first post %q", posts[0])
			}
			if posts[1] != `{"id":"0a0b0c0d0e0f","text":"Booked for Tuesday."}` {
				t.Fatalf("second post %q", posts[1])
			}
		})
	}
}
