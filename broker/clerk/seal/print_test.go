package seal_test

// REQ: CLK-1, DECOY-b-8

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// An open store prints neither its key nor an entry's value, in sixteen
// verbs, bare and in holders with unexported pointer, value and interface
// fields (CLK-1, DECOY-b-8, #4833): the entries hold the log key's and head
// key's sources, so a line that formats the store would put them in a log.
func TestStorePrintsNoKey(t *testing.T) {
	rec := recovery(t)
	path, s := create(t, rec)
	entry := []byte("store-entry-canary-0123456789")
	if err := s.Put("x/canary", entry); err != nil {
		t.Fatal(err)
	}
	again := unlock(t, path, rec)
	secrettest.NoKey(t, [][]byte{seal.StoreKey(s), entry}, append(secrettest.Holders(s), secrettest.Holders(again)...)...)
}

// No factor prints its passphrase, recovery key or boot PIN, bare, in a
// Swap or in holders, in sixteen verbs (DECOY-b-8, CLK-1, #4860): a line
// that formats a factor, or a ReplaceAndPut swap, would otherwise put the
// key that opens the store in a log.
func TestFactorsPrintNoKey(t *testing.T) {
	phrase := []byte("passphrase-canary-0123456789")
	key := []byte("recovery-key-canary-0123456789ab")
	pin := "boot-pin-canary-0123456789"
	factors := []seal.Factor{
		seal.Passphrase{Phrase: secret.Hide(phrase)},
		seal.Recovery{Key: secret.Hide(key)},
		seal.TPM{PIN: secret.Hide(pin), Host: "host"},
	}
	var vs []any
	for _, f := range factors {
		vs = append(vs, secrettest.Holders(f)...)
		vs = append(vs, secrettest.Holders(seal.Swap{ID: "slot", F: f})...)
	}
	swaps := []seal.Swap{{ID: "a", F: factors[0]}, {ID: "b", F: factors[1]}, {ID: "c", F: factors[2]}}
	vs = append(vs, secrettest.Holders(swaps)...)
	secrettest.NoKey(t, [][]byte{phrase, key, []byte(pin)}, vs...)
}
