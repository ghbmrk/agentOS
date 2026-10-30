package owner

// REQ: CH-19

import (
	"regexp"
	"strings"
	"testing"
)

// TestCodeIsClassedApartFromTokens (CODEH-1): a code next to a code word
// is code-shaped and not token-shaped, a token format is token-shaped and
// not code-shaped, and SecretShaped is their union; amounts and dates are
// neither (CH-19, #906).
func TestCodeIsClassedApartFromTokens(t *testing.T) {
	cases := []struct {
		text        string
		token, code bool
	}{
		{"Your verification code is 482913", false, true},
		{"Your code is 482 913", false, true},
		{"Your code is ４８２９１３", false, true},
		{"Sign in with G-482913", false, true},
		{"Here is the key AKIACANARY0000000000", true, false},
		{"token ghp_CANARY000000000000000000000000000", true, false},
		{"code 482913 and AKIACANARY0000000000", true, true},
		{"Paid $1,250.00 on 2026-10-30 for order 88123", false, false},
	}
	for _, c := range cases {
		if TokenShaped(c.text) != c.token || CodeShaped(c.text) != c.code || SecretShaped(c.text) != (c.token || c.code) {
			t.Errorf("%q: token %v code %v secret %v, want token %v code %v", c.text, TokenShaped(c.text), CodeShaped(c.text), SecretShaped(c.text), c.token, c.code)
		}
	}
}

// TestCodePointerNamesKindAndSourceNotValue (CODEH-2): Converse, Notify
// and Post of a code text keep it as KeptOneTime and send one pointer that
// names the code's kind and its source and carries no part of the code
// and no display name; agent text that copies a pointer word for word
// still goes behind the agent prefix (CH-19, #906).
func TestCodePointerNamesKindAndSourceNotValue(t *testing.T) {
	const text = `"Acme Bank" <alerts@bank.example>: your verification code is 482913`
	sends := map[string]func(*Channel, string) error{
		"Converse": (*Channel).Converse,
		"Notify":   (*Channel).Notify,
		"Post":     func(c *Channel, s string) error { return c.Post(ClassUpdate, s) },
	}
	for name, send := range sends {
		r := pacedRig(t, quiet22to7(), 12, 0)
		k := &recKeeper{phone: r.phone}
		r.ch.SetKeeper(k)
		if err := send(r.ch, text); err != nil {
			t.Fatal(err)
		}
		source := fromAgent
		if name == "Post" {
			source = fromNotice
		}
		got := r.sentTexts()
		if len(got) != 1 || got[0] != CodePointer("a code of 6 digits", source) {
			t.Fatalf("%s sent %q", name, got)
		}
		if SecretShaped(got[0]) || regexp.MustCompile(`\d{2,}`).MatchString(got[0]) || strings.Contains(got[0], "Acme") || strings.Contains(got[0], "482") {
			t.Fatalf("%s pointer carries the value or a display name: %q", name, got[0])
		}
		if len(k.kinds) != 1 || k.kinds[0] != KeptOneTime || k.texts[0] != text {
			t.Fatalf("%s kept %q %q", name, k.kinds, k.texts)
		}
	}
	for _, c := range []struct{ text, kind string }{
		{"code: G-482913", "a code"},
		{"codes 482913 and 4829", "a code"},
		{"PIN 4 8 2 9", "a code of 4 digits"},
		{"Your OTP is 0123456789", "a code of 10 digits"},
	} {
		if got := CodeKind(c.text); got != c.kind {
			t.Errorf("CodeKind(%q) = %q, want %q", c.text, got, c.kind)
		}
	}
	for p := range codePointers {
		if got := agentText(p); got != p {
			t.Fatalf("agentText(%q) = %q", p, got)
		}
		r := pacedRig(t, quiet22to7(), 12, 0)
		if err := r.ch.Converse(p + " "); err != nil {
			t.Fatal(err)
		}
		if got := r.sentTexts(); len(got) != 1 || got[0] == p || got[0] == p+" " {
			t.Fatalf("agent text imitating a pointer went as %q", got)
		}
	}
}

// TestExpireCodesLeavesOtherTextReadable (CODEH-3): the code is replaced
// whether plain, spaced, fullwidth or next to "sign in", the rest of the
// text stays, and what is left is never code-shaped, falling back to
// every code-like word and then the whole text (CH-19, #906).
func TestExpireCodesLeavesOtherTextReadable(t *testing.T) {
	cases := []struct{ text, want string }{
		{"Hi Ana, your verification code is 482913. It expires soon.", "Hi Ana, your verification code is [expired]. It expires soon."},
		{"Your code is 482 913, thanks", "Your code is [expired], thanks"},
		{"Your code is ４８２９１３ now", "Your code is [expired] now"},
		{"Sign in with G-482913 today", "Sign in with [expired] today"},
		{"Order 88 shipped. PIN 4 8 2 9 for the locker.", "Order 88 shipped. PIN [expired] for the locker."},
	}
	for _, c := range cases {
		got := ExpireCodes(c.text)
		if got != c.want {
			t.Errorf("ExpireCodes(%q) = %q, want %q", c.text, got, c.want)
		}
		if AgentCode(got) {
			t.Errorf("ExpireCodes(%q) still carries a code: %q", c.text, got)
		}
	}
	for _, s := range []string{
		"с0de 482913", // Cyrillic look-alikes, found only on a fold
		"c​o​d​e 482913",
		"code\n482913",
	} {
		if got := ExpireCodes(s); AgentCode(got) || strings.Contains(got, "482913") {
			t.Errorf("ExpireCodes(%q) = %q", s, got)
		}
	}
	if AgentCode(ExpiredCode) || SecretShaped("code "+ExpiredCode) {
		t.Fatal("the expired marker adds a code shape")
	}
}
