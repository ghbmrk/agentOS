package main

// REQ: CLK-1

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// The unlock step's config and the counter record it reads from the store
// print neither the passphrase nor the counter's auth, in sixteen verbs,
// bare and in holders with unexported pointer, value and interface fields
// (CLK-1, DECOY-b-8, #4833).
func TestUnlockStatePrintsNoKey(t *testing.T) {
	pass := []byte("unlock-passphrase-canary-0123")
	auth := []byte("counter-auth-canary-0123456789")
	c := config{store: "/x/store", uid: 1000, gid: 1000, passphrase: secret.Hide(bytes.Clone(pass))}
	var r counterRec
	if err := json.Unmarshal([]byte(`{"ref":{"handle":1},"auth":"`+b64(auth)+`"}`), &r); err != nil || r.Auth == nil || !bytes.Equal(**r.Auth, auth) {
		t.Fatalf("the counter record does not read its auth: %v", err)
	}
	secrettest.NoKey(t, [][]byte{pass, auth}, append(secrettest.Holders(c), secrettest.Holders(r)...)...)
}

func b64(b []byte) string {
	j, _ := json.Marshal(b)
	return string(j[1 : len(j)-1])
}
