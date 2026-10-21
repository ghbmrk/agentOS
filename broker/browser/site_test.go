package browser

import "testing"

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
		"Access tokens", "API tokens", "Security questions", "Passphrases", "Passcodes", "Authenticators", "OTPs", "Secrets", "SSH keys"} {
		if secretText(s) == "" {
			t.Errorf("%q not read as a secret screen", s)
		}
	}
	for _, s := range []string{"Place order", "Continue", "/checkout/shipping", "Promo code", "Sign in", "Keyboard", "Security code", "Card security code", "Gift card PIN",
		"PIN code", "Remember this device", "/products/backup-battery", "/checkout?token=abc", "Smart home security", "Enamel pin"} {
		if w := secretText(s); w != "" {
			t.Errorf("%q read as a secret screen (%q)", s, w)
		}
	}
}
