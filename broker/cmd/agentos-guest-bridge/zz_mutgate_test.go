package main

// REQ: ARC-6 (DEL-1d)

import (
	"bytes"
	"context"
	"encoding/json"
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

// bridgeRun runs one owner message through ownerOnce against fakes. The
// broker answers each post with the next of codes (a 400 carries body); the
// gateway fails its first modelFails asks. It returns the error, the
// conversations asked and the log text.
func bridgeRun(t *testing.T, codes []int, body string, modelFails int) (error, [][]turn, string) {
	t.Helper()
	var mu sync.Mutex
	posts := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/owner/next" {
			w.Write([]byte(`{"id":"0a0b0c0d0e0f","text":"hello"}`))
			return
		}
		posts++
		if code := codes[posts-1]; code == http.StatusBadRequest && body != "" {
			http.Error(w, body, code)
		} else {
			w.WriteHeader(code)
		}
	}))
	defer broker.Close()
	var asks [][]turn
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Messages []turn }
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		asks = append(asks, req.Messages)
		n := len(asks)
		mu.Unlock()
		if n <= modelFails {
			http.Error(w, "starting", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": "answer"}}}})
	}))
	defer gateway.Close()
	sleep = func(time.Duration) {}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() { sleep = time.Sleep; log.SetOutput(os.Stderr) }()

	u, _ := url.Parse(broker.URL)
	err := ownerOnce(context.Background(), &http.Client{Transport: rewrite{u}}, gateway.URL, "m", "t")
	return err, asks, buf.String()
}

func TestMutgateRefusalIsLogged(t *testing.T) {
	err, _, logs := bridgeRun(t, []int{400, 204}, "no reactions", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, "owner reply 0a0b0c0d0e0f: refused (no reactions); asking again") {
		t.Fatalf("log %q", logs)
	}
}

func TestMutgateModelRetryIsLogged(t *testing.T) {
	err, asks, logs := bridgeRun(t, []int{204}, "", 1)
	if err != nil || len(asks) != 2 {
		t.Fatalf("err %v, asks %d", err, len(asks))
	}
	if !strings.Contains(logs, "owner message 0a0b0c0d0e0f: inbound API: 500 Internal Server Error; retrying") {
		t.Fatalf("log %q", logs)
	}
}

func TestMutgateEmptyRefusalFallsBackToStatus(t *testing.T) {
	err, asks, _ := bridgeRun(t, []int{400, 400}, "", 0)
	if err == nil || !strings.Contains(err.Error(), "refused again: 400 Bad Request") {
		t.Fatalf("err %v", err)
	}
	if len(asks) != 2 || !strings.Contains(asks[1][2].Content, "The broker refused your reply: 400 Bad Request. Answer") {
		t.Fatalf("asks %+v", asks)
	}
}
