package modelroute

import (
	"errors"
	"net"
	"path/filepath"
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
