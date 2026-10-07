package recovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: BAK-1
func TestBAK1w1AcceptUploadMatchesReceipt(t *testing.T) {
	body := []byte("sealed-backup-bytes-canary")
	sum := sha256.Sum256(body)
	rc := Receipt{created: time.Now().UTC(), sum: sum[:]}
	if err := AcceptUpload(rc, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if err := AcceptUpload(rc, strings.NewReader("tampered")); !errors.Is(err, ErrUploadMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
	if err := AcceptUpload(Receipt{}, bytes.NewReader(body)); err == nil {
		t.Fatal("empty receipt accepted")
	}
}
