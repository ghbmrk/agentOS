package seal_test

// REQ: CLK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
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
