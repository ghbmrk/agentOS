package holder

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-7

// C1 on #2449: each request takes its own copy of the secret and clears
// that copy when done, so a second request still carries the key.
func TestTwoRequestsInARowBothCarryTheKey(t *testing.T) {
	key := canary(t, "sk-canary-")
	var mu sync.Mutex
	var sent []string
	up := &upstream{reply: func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		sent = append(sent, r.Header.Get("Authorization"))
		mu.Unlock()
		return answer(200, http.Header{"Content-Type": {"application/json"}}, `{"echo":"`+key+`"}`)(r)
	}}
	h := newHolder(t, up, &swapper{})
	h.Hand([]byte(key))
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("POST", "/v1/messages", `{"m":1}`))
		if w.Code != 200 || strings.Contains(w.Body.String(), key) {
			t.Fatalf("request %d: status %d body %s", i, w.Code, w.Body)
		}
	}
	if len(sent) != 2 || sent[0] != "Bearer "+key || sent[1] != "Bearer "+key {
		t.Fatalf("sent %d logins, want the key twice", len(sent))
	}
	if !h.holds([]byte(key)) {
		t.Fatal("a request cleared the held secret")
	}
}

// C1 on #2449: a Hand that lands while a request is in flight neither
// races it nor changes it: the request finishes with the key it took, and
// its response stays redacted for that key. Run under -race.
func TestHandRacingARequestInFlight(t *testing.T) {
	old, rotated := canary(t, "sk-canary-"), canary(t, "sk-canary-rotated-")
	inside, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var sent []string
	up := &upstream{reply: func(r *http.Request) (*http.Response, error) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		sent = append(sent, auth)
		first := len(sent) == 1
		mu.Unlock()
		if first {
			close(inside)
			<-release
		}
		return answer(200, http.Header{"Content-Type": {"application/json"}}, `{"echo":"`+strings.TrimPrefix(auth, "Bearer ")+`"}`)(r)
	}}
	h := newHolder(t, up, &swapper{})
	h.Hand([]byte(old))
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("POST", "/v1/messages", `{"m":1}`))
		done <- w
	}()
	<-inside
	h.Hand([]byte(rotated))
	close(release)
	w := <-done
	if w.Code != 200 || strings.Contains(w.Body.String(), old) || !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("in-flight request: status %d body %s", w.Code, w.Body)
	}
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req("POST", "/v1/messages", `{"m":1}`))
	if w2.Code != 200 || strings.Contains(w2.Body.String(), rotated) || !strings.Contains(w2.Body.String(), vault.Placeholder) {
		t.Fatalf("after the hand: status %d body %s", w2.Code, w2.Body)
	}
	if len(sent) != 2 || sent[0] != "Bearer "+old || sent[1] != "Bearer "+rotated {
		t.Fatal("the in-flight request lost its key, or the next one missed the rotated key")
	}
}
