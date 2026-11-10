package model

// REQ: CLK-3

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The key's header is a name keyHeaders holds exactly: the header corpus's
// credential, request-reshaping, hop-by-hop and broken names, in any case,
// are refused (#4910, #2623), and so is a widened list. Catches a key sent in a header a remote logs
// or a proxy acts on.
func TestKeyHeadersRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, func(h string) bool {
		d := Shipped[0]
		d.Header = h
		return d.validate() == nil
	}, hostiletext.Exactly(t, keyHeaders, "Authorization", "X-Api-Key")...)
}

// A declaration's own header is its provider's name and a word declHeaders
// holds exactly, and its value is visible ASCII, unpadded: the header
// corpus's credential, request-reshaping, hop-by-hop and broken names, in
// any case, and the value corpus are refused (#4914). Catches a provider
// declaring X-Http-Method-Override or X-Signature, another provider's
// header, or a value that adds a header line.
func TestDeclaredHeadersRefuseTheCorpus(t *testing.T) {
	declares := func(h, v string) bool {
		d := Shipped[0]
		d.Headers = map[string]string{h: v}
		return d.validate() == nil
	}
	hostiletext.RunHeaders(t, func(h string) bool { return declares(h, "2023-06-01") },
		"Anthropic-"+hostiletext.Exactly(t, declHeaders, "Version")[0])
	hostiletext.RunHeaderValues(t, func(v string) bool { return declares("Anthropic-Version", v) })
	for _, v := range []string{"", " v", "v ", "v\t"} {
		if declares("Anthropic-Version", v) {
			t.Errorf("the value %q was taken", v)
		}
	}
	for _, h := range []string{"Openai-Version", "Version", "Anthropic-Beta"} {
		if declares(h, "v") {
			t.Errorf("the anthropic declaration may set %q", h)
		}
	}
}
