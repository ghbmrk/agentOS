package browser

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// REQ: CLK-3
func TestSiteIsTheRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"https://shop.example.com/cart":      "example.com",
		"https://pay.shop.example.co.uk/x":   "example.co.uk",
		"https://Checkout.Example.COM./":     "example.com",
		"https://alice.github.io/page":       "alice.github.io",
		"https://bob.github.io/":             "bob.github.io",
		"https://github.io/":                 "github.io",
		"http://localhost:8080/":             "localhost",
		"https://192.0.2.7/pay":              "192.0.2.7",
		"https://[2001:db8::1]/pay":          "2001:db8::1",
		"https://shop.example.test/checkout": "example.test",
		"javascript:void(0)":                 "",
		"ftp://example.com/file":             "",
		"/relative":                          "",
		"":                                   "",
	} {
		if got := site(in); got != want {
			t.Errorf("site(%q) = %q, want %q", in, got, want)
		}
	}
}

// REQ: CLK-3, VRB-1
func TestSecretScreenWords(t *testing.T) {
	for _, s := range []string{"Change password", "/account/recovery", "Set up 2FA", "Two-factor authentication",
		"Show API key", "Add SSH key", "Change email", "/login/oauth/authorize", "Security settings", "Backup codes", "Generate new token", "Add device", "Export data", "one-time code", "/settings/apiKeys", "Recovery codes",
		// VRB-1's own examples, verbatim.
		"show an API key", "reset a password", "add a device", "export", "change account recovery",
		// Phrasings a pair list missed (#2711 round 2).
		"Add a device", "Link a device", "Trusted devices", "Manage devices", "Remove device", "Export", "Export your data", "/account/export",
		"Export vault", "Export contacts", "/settings/export", "Create token", "Generate token", "Regenerate token", "Tokens", "/settings/tokens",
		"/account/tokens", "/settings/security", "/account/security", "Sign-in & security", "Account security", "Security", "Set PIN",
		"Change your PIN", "Download backup", "Seed phrase", "/vault?token=abc&view=export",
		// Plurals (CLK-5 "Secret screens").
		"Access tokens", "API tokens", "Security questions", "Passphrases", "Passcodes", "Authenticators", "OTPs", "Secrets", "SSH keys",
		// A checkout's own phrase beside a secret verb still marks the screen.
		"Change PIN code", "Reset your PIN code", "Enter security code", "Enter the security code we sent to your phone",
		"Send security code", "Security code sent", "Gift card PIN reset", "New PIN code", "/cards/pin-code",
		"Recoveries", "Account recoveries", "Securities",
		"Set a new PIN code", "Reset PIN code", "Home security settings", "/vault?export=1", "/account?view=recovery",
		"/x?access_token=1", "/x?TOKEN=1", "Enter CVV / Security code", "PIN", "Change gift card PIN",
		// A checkout phrase's plural is not exempt: "Security codes" may be
		// backup codes (fail closed).
		"Security codes", "Gift card PINs", "Backup batteries"} {
		if secretText(s) == "" {
			t.Errorf("%q not read as a secret screen", s)
		}
	}
	for _, s := range []string{"Place order", "Continue", "/checkout/shipping", "Promo code", "Sign in", "Keyboard", "Security code", "Card security code", "Gift card PIN",
		"Remember this device", "/checkout?token=abc", "Smart home security", "Enamel pin", "Backup battery",
		"CVV / Security code", "Security code (CVV)", "SECURITY-CODE:"} {
		if w := secretText(s); w != "" {
			t.Errorf("%q read as a secret screen (%q)", s, w)
		}
	}
}

// The clerk's lists are SPEC CLK-5 "Secret screens" word for word: every
// alone entry and pair marks, and the checkout phrases are exactly the
// whole texts passed over (VRB-1). A word dropped from either side fails.
// REQ: VRB-1
func TestSecretListsAreTheSpecs(t *testing.T) {
	b, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(b)
	between := func(from, to string) []string {
		i := strings.Index(spec, from)
		if i < 0 {
			t.Fatalf("SPEC has no %q", from)
		}
		rest := spec[i+len(from):]
		j := strings.Index(rest, to)
		if j < 0 {
			t.Fatalf("SPEC has no %q after %q", to, from)
		}
		var out []string
		for _, e := range strings.Split(rest[:j], ",") {
			out = append(out, strings.Join(words(e), ""))
		}
		return out
	}
	marks := append(between("exact form listed): ", "."),
		between("**Alone** also: ", ".")...)
	marks = append(marks, between("**Only as a pair:** ", ".")...)
	want := map[string]bool{}
	for _, w := range marks {
		want[w] = true
	}
	if !maps.Equal(want, secretWords) {
		t.Errorf("secretWords %v, SPEC %v", slices.Sorted(maps.Keys(secretWords)), slices.Sorted(maps.Keys(want)))
	}
	exempt := map[string]bool{}
	for _, p := range between("one of the checkout phrases ", " (") {
		exempt[p] = true
	}
	if !maps.Equal(exempt, notSecret) {
		t.Errorf("notSecret %v, SPEC %v", slices.Sorted(maps.Keys(notSecret)), slices.Sorted(maps.Keys(exempt)))
	}
}
