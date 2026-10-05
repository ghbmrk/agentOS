package modelroute

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// REQ: CH-2, CH-18

// A vault process that takes the code and never answers may have spent
// it: the client says so (VerifyLost) within its timeout, instead of
// holding the owner channel.
func TestVerifyWithNoAnswerIsLostWithinTheTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // read nothing, answer nothing
		}
	}()
	start := time.Now()
	_, _, err = NewVerifier(path).VerifyTOTP("123456", 0, true)
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Kind != VerifyLost {
		t.Fatalf("hung process: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}

// REQ: ADP-12

// The second line's state is a closed set: a vault process that answers
// anything else is refused, so agentosd never shows text the vault
// process supplied (L3 on #142).
func TestSecondLineRefusesAnUnknownState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verify.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	body.Store(`{"state":"other"}`)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body.Load().(string))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	v := NewVerifier(path)
	if st, err := v.SecondLine(context.Background()); err == nil || st != "" {
		t.Fatalf("unknown state: %q %v", st, err)
	}
	body.Store(`{"state":"confirm"}`)
	if st, err := v.SecondLine(context.Background()); err != nil || st != SecondLineConfirm {
		t.Fatalf("known state: %q %v", st, err)
	}
	// The texting account's state is closed the same way (UX-159-1).
	body.Store(`{"texts":"other"}`)
	if st, err := v.SecondLineTexts(context.Background()); err == nil || st != "" {
		t.Fatalf("unknown texts state: %q %v", st, err)
	}
	body.Store(`{"texts":"signin"}`)
	if st, err := v.SecondLineTexts(context.Background()); err != nil || st != TextsSignIn {
		t.Fatalf("known texts state: %q %v", st, err)
	}
}
