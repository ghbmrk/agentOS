package edgelink

// REQ: CLK-1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Neither end's TLS configuration prints its link key: not the
// configuration, its certificate nor the guarded signer TLS holds, in
// sixteen verbs (%w and %p included), bare and in holders with unexported
// pointer, value and interface fields (CLK-1, DECOY-b-8, #4837). The guard
// keeps the signer in a handoff.Secret; the same key in a plain field
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
	type holder struct {
		c  *tls.Config
		cv tls.Certificate
		g  any
		v  any
	}
	h := holder{server, client.Certificates[0], g, client}
	secrets := [][]byte{core.Seed(), edge.Seed()}
	if keyShown(secrets, server, client, server.Certificates[0], client.Certificates[0], g, h, &h) {
		t.Error("a link configuration prints its key")
	}
	type plain struct{ k ed25519.PrivateKey }
	for _, k := range []ed25519.PrivateKey{core, edge} {
		if !keyShown([][]byte{k.Seed()}, &holder{v: &plain{k}}) {
			t.Error("no print showed the key in a plain field: the check cannot see it")
		}
	}
	// The guard still answers for the key it holds.
	if pub, ok := g.(guard).Public().(ed25519.PublicKey); !ok || !pub.Equal(core.Public()) {
		t.Error("the guard lost its signer")
	}
}

// keyShown formats each of vs in sixteen verbs and reports whether any
// output holds a secret: raw, as hex, as decimal bytes, JSON-escaped or in
// the verb's own form of the bytes (handoff's TestKernelKeysPrintNoKey).
func keyShown(secrets [][]byte, vs ...any) bool {
	shown := false
	for _, v := range vs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				j, _ := json.Marshal(string(s))
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(string(j), `"`), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					shown = shown || len(f) >= 10 && strings.Contains(out, strings.ToLower(f))
				}
			}
		}
	}
	return shown
}
