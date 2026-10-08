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

// CRED-10 (L3 #4): a value of 16 or more token characters next to a label
// such as "api key", "token", "secret" or "password" is redacted even when it
// is low-entropy hex or carries '/'. Synthetic canaries only.
func TestDetectorRedactsLabelledValues(t *testing.T) {
	const (
		hex32 = "9f86d081884c7d659a2feaa0c55ad015"
		hex64 = "9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015"
		aws   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	)
	for in, secret := range map[string]string{
		"api key: " + hex32:                      hex32,
		"API_KEY=" + hex32:                       hex32,
		"token " + hex64:                         hex64,
		"Bearer token: " + hex64:                 hex64,
		"secret: " + aws:                         aws,
		`"client_secret": "` + aws + `"`:         aws,
		"password = 4fj29dk3ls02kd93jf02":        "4fj29dk3ls02kd93jf02",
		"access_token: " + hex32:                 hex32,
		"- text: Key " + hex32:                   hex32,
		`- textbox "API key" [ref=e5]: ` + hex32: hex32,
	} {
		out, n := Detect(in)
		if strings.Contains(out, secret) || n == 0 {
			t.Errorf("%q survived: %q (n=%d)", in, out, n)
		}
	}
}

// The label rule keeps the label and stays off ordinary labelled prose.
func TestDetectorLabelRuleLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"Your token expires in 10 minutes",
		"Forgot password? Reset it here",
		"- link \"token-based-authentication-guide\" [ref=e7]",
		"secret: santa-gift-exchange-list",
		"key 2024-10-08",
	} {
		if out, n := Detect(in); n != 0 || out != in {
			t.Errorf("%q changed to %q (n=%d)", in, out, n)
		}
	}
	if out, _ := Detect("api key: 9f86d081884c7d659a2feaa0c55ad015"); out != "api key: "+Redacted {
		t.Errorf("label not kept: %q", out)
	}
}
