package main

// REQ: CLK-1, CLK-14

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/netguard"
)

func testSealer(t *testing.T, k [32]byte) clerk.Sealer {
	t.Helper()
	ck := clerkkey.Key{Name: clerkName, Key: secret.Hide(k)}
	sk, err := ck.Sealer()
	must(t, err)
	s, err := clerk.NewAESSealer(sk)
	must(t, err)
	return s
}

// REV-CHK-save (#4192): a slot write that stops before its rename, as a
// crash would, fails the owner's step and leaves the store in memory and the
// slot on disk as they were: a refused planremove keeps the login signed in,
// a refused key set keeps no key, and the next start reads the same.
func TestStoppedSlotWriteKeepsTheOldSlot(t *testing.T) {
	k := [32]byte{7}
	d := declarations(netguard.New(netguard.Config{}))[0].d
	for step := 0; step < 4; step++ {
		dir := testConfig(t).dir
		sealedSlot(t, dir, k)
		before, err := os.ReadFile(filepath.Join(dir, planSlot("codex")))
		must(t, err)
		stop := func(i int) bool { return i == step }

		store, err := openStore(dir, planSlot("codex"), testSealer(t, k), stop)
		must(t, err)
		login, err := newLogin(d, store)
		must(t, err)
		if err := login.Remove(); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: planremove: got %v, want ErrStopped", step, err)
		}
		if mem, _ := store.MarshalBinary(); !bytes.Equal(mem, before) || !login.Signed() {
			t.Fatalf("step %d: the login in memory moved on a stopped write", step)
		}
		reopened, err := openStore(dir, planSlot("codex"), testSealer(t, k), nil)
		must(t, err)
		if again, err := newLogin(d, reopened); err != nil || !again.Signed() {
			t.Fatalf("step %d: the slot moved on a stopped write: %v", step, err)
		}

		keys, err := openKeys(dir, testSealer(t, k), stop)
		must(t, err)
		apis, err := model.NewAPIs(model.Shipped, keys, netguard.New(netguard.Config{}), nil)
		must(t, err)
		provider := model.Shipped[0].Provider
		if err := apis.SetKey(provider, "canary-not-a-key", false); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: key set: got %v, want ErrStopped", step, err)
		}
		if mem, _ := keys.MarshalBinary(); len(mem) != 0 {
			t.Fatalf("step %d: the keys in memory moved on a stopped write", step)
		}
		if _, err := os.Stat(filepath.Join(dir, keySlot)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: the keys' slot was written on a stopped write: %v", step, err)
		}
	}
}
