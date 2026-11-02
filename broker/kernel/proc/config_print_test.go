package proc

// REQ: CLK-1

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// A KernelConfig prints as its type alone, never the log key, the head key
// or the link key, in every verb its Format covers (fmt skips it under %w
// and %p, DECOY-b-8) (CLK-1, #4574). Catches a boot error or debug line
// that formats the config and puts the keys in an unsealed log.
func TestKernelConfigPrintsNoKey(t *testing.T) {
	var logKey [32]byte
	for i := range logKey {
		logKey[i] = byte(0xa0 + i)
	}
	head := ed25519.NewKeyFromSeed(logKey[:])
	link := ed25519.NewKeyFromSeed(append(logKey[1:], 7))
	c := KernelConfig{Key: logKey, Pub: head.Public().(ed25519.PublicKey), Sign: head, LinkKey: link}
	for _, v := range []any{c, &c} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range [][]byte{logKey[:], head.Seed(), link.Seed()} {
				for _, f := range []string{hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					if len(f) >= 10 && strings.Contains(out, strings.ToLower(f)) {
						t.Errorf("%s of %T shows a key", verb, v)
					}
				}
			}
		}
	}
}
