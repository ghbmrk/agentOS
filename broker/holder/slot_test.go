package holder

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: CRED-1, ARC-1

// slot is a Slot that keeps what it was handed.
type slot struct {
	mu sync.Mutex
	b  []byte
}

func (s *slot) Hand(b []byte) { s.mu.Lock(); s.b = append([]byte(nil), b...); s.mu.Unlock() }
func (s *slot) Drop()         { s.Hand(nil) }
func (s *slot) Held() bool    { s.mu.Lock(); defer s.mu.Unlock(); return len(s.b) > 0 }

// HandHandler serves any Slot the way a holder's hand socket serves its
// secret, so the keyless proxy (SIM-split-wire) is handed its redaction
// state by the same Keeper, with its own size cap.
func TestHandHandlerServesASlot(t *testing.T) {
	dir := socketDir(t)
	ln, err := Listen(filepath.Join(dir, HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	s := &slot{}
	srv := &http.Server{Handler: HandHandler(s, 1<<20)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	big := bytes.Repeat([]byte("x"), maxSecret*4)
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return append([]byte(nil), big...), nil }}
	ctx := context.Background()
	if handed, err := k.Check(ctx); err != nil || !handed {
		t.Fatalf("hand: %v %v", handed, err)
	}
	if !bytes.Equal(s.b, big) {
		t.Fatal("slot was not handed the bytes the keeper sent")
	}
	if err := k.Drop(ctx); err != nil || s.Held() {
		t.Fatalf("drop: %v held=%v", err, s.Held())
	}
	over := &Keeper{Socket: k.Socket, Secret: func() ([]byte, error) { return bytes.Repeat([]byte("x"), 1<<20+1), nil }}
	if _, err := over.Check(ctx); err == nil || s.Held() {
		t.Fatalf("a hand over the cap was taken: %v", err)
	}
}

// A holder's own hand socket keeps its own cap, maxSecret, now that it is
// served by HandHandler.
func TestHolderHandKeepsItsCap(t *testing.T) {
	h, err := New(Config{Adapters: []egress.Adapter{egress.OpenAI("openai-key")}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.hand().ServeHTTP(w, httptest.NewRequest("PUT", "/secret", bytes.NewReader(bytes.Repeat([]byte("x"), maxSecret+1))))
	if w.Code == http.StatusNoContent || h.Held() {
		t.Fatalf("a secret over maxSecret was taken: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.hand().ServeHTTP(w, httptest.NewRequest("PUT", "/secret", bytes.NewReader(bytes.Repeat([]byte("x"), 64))))
	if w.Code != http.StatusNoContent || !h.Held() {
		t.Fatalf("a small secret was refused: %d", w.Code)
	}
}
