package main

// REQ: CAP-3, CRED-8

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The recall identity key (recall K5) lives in the vault: none is handed out
// while the vault is locked, it is created once and is the same on every
// request and after a restart, and it is stored as a broker key the local
// UI cannot overwrite.
func TestRecallKeyIsVaultHeld(t *testing.T) {
	r := newFastRig(t, true)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	if _, err := v.RecallKey(); !errors.Is(err, modelroute.ErrVaultLocked) {
		t.Fatalf("locked vault handed out a key: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	k1, err := v.RecallKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("key: %d bytes, %v", len(k1), err)
	}
	k2, _ := v.RecallKey()
	if !bytes.Equal(k1, k2) {
		t.Fatal("key changed between requests")
	}
	if err := r.c.put(RecallKeyName, []byte("replacement-key-value")); err == nil {
		t.Fatal("the local UI's credential write replaced the recall key")
	}
	r.c.lock()
	if _, err := v.RecallKey(); !errors.Is(err, modelroute.ErrVaultLocked) {
		t.Fatalf("key handed out after lock: %v", err)
	}
	vv, err := vault.Open(r.path, r.key)
	if err != nil {
		t.Fatal(err)
	}
	defer vv.Close()
	sec, ok := vv.Secret(RecallKeyName)
	if !ok || sec.Reveal() != string(k1) || !hasKind(vv, RecallKeyName, KindBrokerKey) {
		t.Fatal("recall key not kept in the vault as a broker key")
	}
}
