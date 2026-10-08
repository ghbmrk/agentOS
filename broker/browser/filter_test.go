package browser

// REQ: CRED-10

import (
	"strings"
	"testing"
)

// Synthetic canaries only (CLAUDE.md).
const (
	canaryJWT    = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJlLWNhbmFyeQ"
	canaryGitHub = "ghp_CanaryGitHubToken0123456789abcd"
	canaryAPI    = "sk-ant-gatecanaryDisplayedKey0123456789abcdef"
	canaryAWS    = "AKIACANARY0123456789"
	canarySlack  = "xoxb-canary-0123456789"
	canaryRandom = "q7Xz2pL9mW4vR8tY3nB6kJ5h"
)

func TestDetectorRedactsKnownTokenFormats(t *testing.T) {
	for _, c := range []string{canaryJWT, canaryGitHub, canaryAPI, canaryAWS, canarySlack, canaryRandom} {
		out, n := Detect("before " + c + " after")
		if strings.Contains(out, c) || n == 0 {
			t.Errorf("%s survived: %q (n=%d)", c, out, n)
		}
		if !strings.Contains(out, "before ") || !strings.Contains(out, " after") {
			t.Errorf("surrounding text lost: %q", out)
		}
	}
}

func TestDetectorRedactsSecretNamedURLParameters(t *testing.T) {
	for _, in := range []string{
		"https://a.test/cb#access_token=abc123&state=x",
		"https://a.test/order?item=7&token=short1",
		"- link [ref=e4]:\n  - /url: /order?item=7&session=s1",
	} {
		out, n := Detect(in)
		if n == 0 || !strings.Contains(out, Redacted) {
			t.Errorf("%q: not redacted (%q)", in, out)
		}
		for _, v := range []string{"abc123", "short1", "=s1"} {
			if strings.Contains(out, v) {
				t.Errorf("%q: value %q survived in %q", in, v, out)
			}
		}
	}
}

func TestDetectorLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"Order 7 shipped to Nairobi on Tuesday",
		"https://a.test/products/kettle-stainless-steel-1-7-litre",
		"- button \"Add to basket\" [ref=e12]",
		"https://a.test/search?q=kettle&page=2",
		"internationalization-and-localization",
	} {
		if out, n := Detect(in); n != 0 || out != in {
			t.Errorf("%q changed to %q (n=%d)", in, out, n)
		}
	}
}

// The vault's exact values are scrubbed first, so a secret the detector's
// patterns would miss (a short or low-entropy one) still never leaves.
func TestFilterScrubsVaultValuesThenDetects(t *testing.T) {
	f := filter{scrub: fakeScrubber{"pw-canary-short"}}
	out, n := f.text("login pw-canary-short and " + canaryAPI)
	if strings.Contains(out, "pw-canary-short") || strings.Contains(out, canaryAPI) {
		t.Fatalf("canary survived: %q", out)
	}
	if n < 2 {
		t.Fatalf("want 2 hits, got %d", n)
	}
}

type fakeScrubber []string

func (f fakeScrubber) Redact(b []byte) []byte {
	s := string(b)
	for _, v := range f {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	return []byte(s)
}
