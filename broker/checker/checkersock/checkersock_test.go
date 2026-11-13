package checkersock

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-4

// VerifyTOTP reads the checker's answers: 200 its match, 429 a paused
// bucket with its end, 503 no seed, a socket that cannot be dialled
// ErrDown, and any other answer an error that is never a match.
func TestVerifyTOTPReadsEachAnswer(t *testing.T) {
	dir, err := os.MkdirTemp("", "cks")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for i, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			var req VerifyRequest
			if r.URL.Path != "/verify" || json.NewDecoder(r.Body).Decode(&req) != nil || req != (VerifyRequest{Code: "123456", After: 7, Counted: true}) {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(VerifyResponse{Step: 9, OK: true})
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(PausedHeader, "1800000600")
			w.WriteHeader(http.StatusTooManyRequests)
		},
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) },
	} {
		path := filepath.Join(dir, fmt.Sprintf("v%d.sock", i))
		ln, err := sockets.ListenPeers(path, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: h}
		go srv.Serve(ln)
		step, ok, err := VerifyClient(path).VerifyTOTP("123456", 7, true)
		srv.Close()
		var p *PausedError
		switch i {
		case 0:
			if step != 9 || !ok || err != nil {
				t.Errorf("match: %d %v %v", step, ok, err)
			}
		case 1:
			if ok || !errors.As(err, &p) || p.Until.Unix() != 1800000600 {
				t.Errorf("paused: %v %v", ok, err)
			}
		case 2:
			if ok || !errors.Is(err, ErrNoSeed) {
				t.Errorf("no seed: %v %v", ok, err)
			}
		default:
			if ok || err == nil || errors.Is(err, ErrNoSeed) || errors.As(err, &p) {
				t.Errorf("answer %d: %v %v", i, ok, err)
			}
		}
	}
	if _, ok, err := VerifyClient(filepath.Join(dir, "absent.sock")).VerifyTOTP("123456", 0, true); ok || !errors.Is(err, ErrDown) {
		t.Errorf("down: %v %v", ok, err)
	}
}
