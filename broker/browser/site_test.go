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
		"Show API key", "Add SSH key", "Change email", "/login/oauth/authorize", "Security settings", "Backup codes", "Generate new token", "Add device", "Export data", "one-time code", "/settings/apiKeys", "Recovery codes"} {
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
