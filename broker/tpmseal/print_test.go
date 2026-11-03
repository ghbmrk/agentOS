package tpmseal_test

// REQ: CLK-1

import (
	"bytes"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

// The log anchor's counter prints no auth value, in sixteen verbs, bare and
// in holders with unexported pointer, value and interface fields (CLK-1,
// DECOY-b-8, #4833): a line that formats the kernel's anchor shows no auth.
func TestCounterPrintsNoAuth(t *testing.T) {
	auth := []byte("counter-auth-canary-0123456789")
	c := tpmseal.Counter{SRK: []byte("srk-name"), Ref: tpmseal.CounterRef{Handle: 0x01500000, Name: []byte("nv-name")}, Auth: secret.Hide(bytes.Clone(auth))}
	secrettest.NoKey(t, [][]byte{auth}, secrettest.Holders(c)...)
}
