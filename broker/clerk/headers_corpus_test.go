package clerk

// REQ: CLK-1, CLK-2

import (
	"maps"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The exit's two declarable-header lists refuse the header corpus (#4910,
// #2623): a fixed header and the secret's header are each a name the list
// holds exactly, and any value declared for a fixed header or as the
// secret's prefix holds no line break or control character. Catches a list
// widened to a credential, request-reshaping or hop-by-hop name, a name in
// another case, or a value that adds a header line.
func TestDeclarableHeadersRefuseTheCorpus(t *testing.T) {
	sealer, err := NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	empty, one := NewSecrets(sealer, nil), NewSecrets(sealer, nil)
	if err := one.Put("web", KindStatic, []byte("synthetic-canary")); err != nil {
		t.Fatal(err)
	}
	declares := func(op Op, sec *Secrets) bool {
		op.Verb, op.Method, op.URL = key.Fetch, "GET", "https://h.example/v1/{url}"
		_, err := shape(op, string(op.Verb), key.ArgNames(op.Verb), sec)
		return err == nil
	}
	// The names each list may hold are written out (Exactly), not read
	// from the list, so a widened list fails here.
	t.Run("fixedHeaders", func(t *testing.T) {
		hostiletext.RunHeaders(t, func(h string) bool {
			return declares(Op{Headers: map[string]string{h: "v"}}, empty)
		}, hostiletext.Exactly(t, slices.Collect(maps.Keys(fixedHeaders)), "Accept", "Accept-Language", "User-Agent")...)
	})
	t.Run("secretHeaders", func(t *testing.T) {
		// An empty Header is the Authorization default, not a name the
		// list holds.
		hostiletext.RunHeaders(t, func(h string) bool {
			return h != "" && declares(Op{Slot: "web", Header: h}, one)
		}, hostiletext.Exactly(t, slices.Collect(maps.Keys(secretHeaders)), "Authorization", "X-Api-Key")...)
	})
	t.Run("fixed header value", func(t *testing.T) {
		hostiletext.RunHeaderValues(t, func(v string) bool {
			return declares(Op{Headers: map[string]string{"Accept": v}}, empty)
		})
	})
	t.Run("secret prefix", func(t *testing.T) {
		hostiletext.RunHeaderValues(t, func(v string) bool {
			return declares(Op{Slot: "web", Prefix: v}, one)
		})
	})
}
