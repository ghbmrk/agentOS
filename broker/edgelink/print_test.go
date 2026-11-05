package edgelink

// REQ: CLK-1

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// Neither end's TLS configuration prints its link key: not the
// configuration, its certificate nor the guarded signer TLS holds, in
// sixteen verbs (%w and %p included), bare and in holders with unexported
// pointer, value and interface fields (CLK-1, DECOY-b-8, #4837). The guard
// keeps the signer behind a pointer to a pointer; the same key in a plain field
// shows, so the check can see one. Catches an error or debug line in the
// link's process that formats its tls.Config and puts the link key in a
// log.
func TestLinkConfigsPrintNoKey(t *testing.T) {
	core := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2e, 0x71}, ed25519.SeedSize/2))
	edge := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4b, 0x93}, ed25519.SeedSize/2))
	server, err := ServerConfig(core)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ClientConfig(edge, core.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	g := server.Certificates[0].PrivateKey
	vs := append(secrettest.Holders(server), secrettest.Holders(client)...)
	vs = append(vs, secrettest.Holders(server.Certificates[0])...)
	vs = append(vs, secrettest.Holders(client.Certificates[0])...)
	vs = append(vs, secrettest.Holders(g.(guard))...)
	secrettest.NoKey(t, [][]byte{core.Seed(), edge.Seed()}, vs...)
	// The guard still answers for the key it holds.
	if pub, ok := g.(guard).Public().(ed25519.PublicKey); !ok || !pub.Equal(core.Public()) {
		t.Error("the guard lost its signer")
	}
}
