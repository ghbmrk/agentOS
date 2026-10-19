package holder

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// REQ: CRED-1, ARC-1

// A key the owner replaces reaches the holder: the keeper hands again
// when the version it handed has moved, though the holder still holds
// the old one (SIM-split-wire).
func TestKeeperRehandsARotatedKey(t *testing.T) {
	dir := socketDir(t)
	h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
	serve(t, h, dir, os.Getuid())
	old, rotated := canary(t, "sk-canary-"), canary(t, "sk-canary-")
	key := old
	var ver atomic.Uint64
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte(key), nil }, Version: ver.Load}
	ctx := context.Background()
	if handed, err := k.Check(ctx); err != nil || !handed {
		t.Fatalf("first hand: %v %v", handed, err)
	}
	if handed, err := k.Check(ctx); err != nil || handed {
		t.Fatalf("handed again with nothing changed: %v %v", handed, err)
	}
	key = rotated
	ver.Add(1)
	if handed, err := k.Check(ctx); err != nil || !handed {
		t.Fatalf("rotated key not handed: %v %v", handed, err)
	}
	if !h.holds([]byte(rotated)) {
		t.Fatal("holder still holds the old key")
	}
}

// Locking the vault empties the holders: Drop takes the secret back, so a
// locked box holds no login anywhere (CRED-1).
func TestKeeperDropEmptiesTheHolder(t *testing.T) {
	dir := socketDir(t)
	h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
	serve(t, h, dir, os.Getuid())
	key := canary(t, "sk-canary-")
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte(key), nil }}
	ctx := context.Background()
	if _, err := k.Check(ctx); err != nil || !h.Held() {
		t.Fatalf("hand: %v", err)
	}
	if err := k.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Held() {
		t.Fatal("holder kept its secret after Drop")
	}
	// After a drop the keeper hands again on its next round.
	if handed, err := k.Check(ctx); err != nil || !handed {
		t.Fatalf("no hand after drop: %v %v", handed, err)
	}
}

// Only the hand socket's uid can drop the secret.
func TestDropAdmitsOnlyTheHandUID(t *testing.T) {
	dir := socketDir(t)
	h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
	h.Hand([]byte(canary(t, "sk-canary-")))
	serve(t, h, dir, os.Getuid()+1)
	k := &Keeper{Socket: filepath.Join(dir, HandSocket)}
	if err := k.Drop(context.Background()); err == nil {
		t.Fatal("drop from another uid accepted")
	}
	if !h.Held() {
		t.Fatal("another uid emptied the holder")
	}
}

// A drop forgets what the keeper handed: if the holder holds a secret on
// the keeper's next round (a hand that landed after the drop), the keeper
// hands its own again rather than trust it (SIM-split-wire).
func TestKeeperForgetsItsHandAtDrop(t *testing.T) {
	dir := socketDir(t)
	h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
	serve(t, h, dir, os.Getuid())
	key := canary(t, "sk-canary-")
	var ver atomic.Uint64
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte(key), nil }, Version: ver.Load}
	ctx := context.Background()
	if handed, err := k.Check(ctx); err != nil || !handed {
		t.Fatalf("hand: %v %v", handed, err)
	}
	if err := k.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	h.Hand([]byte(canary(t, "sk-canary-stale-")))
	if handed, err := k.Check(ctx); err != nil || !handed || !h.holds([]byte(key)) {
		t.Fatalf("after a drop the keeper trusted what the holder held: %v %v", handed, err)
	}
}
