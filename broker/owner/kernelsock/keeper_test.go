package kernelsock

// REQ: REC-4, STO-2

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The keeper's socket client sends the one-shot's request (agentos-enroll
// rotateRequest: secret base64, next hex, approval base64), ends its
// write half, and reads the one word; a socket not held by the expected
// uid is not spoken to.
func TestKeeperSockSpeaksTheOneShot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			mu.Lock()
			got = b
			mu.Unlock()
			c.Write([]byte("factor\n"))
			c.Close()
		}
	}()
	secret := []byte("synthetic passphrase")
	next := bytes.Repeat([]byte{0x5a}, 32)
	word, err := Keeper{Socket: path, UID: os.Getuid()}.Rotate(context.Background(), "passphrase", secret, next, []byte("appr"))
	if err != nil || word != "factor" {
		t.Fatalf("word %q %v", word, err)
	}
	mu.Lock()
	var req struct {
		Factor   string `json:"factor"`
		Secret   []byte `json:"secret"`
		Next     string `json:"next"`
		Approval []byte `json:"approval"`
	}
	d := json.NewDecoder(bytes.NewReader(got))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		t.Fatalf("request %q: %v", got, err)
	}
	mu.Unlock()
	if req.Factor != "passphrase" || !bytes.Equal(req.Secret, secret) || req.Next != hex.EncodeToString(next) || string(req.Approval) != "appr" {
		t.Fatalf("request %+v", req)
	}
	if _, err := (Keeper{Socket: path, UID: os.Getuid() + 1}).Rotate(context.Background(), "passphrase", secret, next, nil); !errors.Is(err, ErrNotKeeper) {
		t.Fatalf("spoke to a socket another uid holds: %v", err)
	}
}
