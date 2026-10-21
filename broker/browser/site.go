package browser

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// site is the site a task approval covers for a request reaching rawURL:
// its host's registrable domain on the public suffix list, the private
// section included, so x.github.io is its own site. A host with no
// registrable domain (an IP address, localhost, a public suffix itself) is
// its own exact host. "" means no http(s) host, which no approval covers
// (CLK-3).
func site(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "" || net.ParseIP(h) != nil {
		return h
	}
	s, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return h
	}
	return s
}

// secretWords mark a screen that may reveal or create a secret (VRB-1):
// show an API key, reset a password, add a device, export, change account
// recovery. Pairs are matched joined ("two factor" as "twofactor"). The
// list errs wide: a false match costs one more tap, a miss would let a
// task's tap cover a secret (#2689 item 3).
var secretWords = wordSet(`password passwords passcode passkey passkeys passphrase pin recovery
	mfa 2fa 2sv twofactor twostep onetime otp totp authenticator authentication
	secret secrets apikey apikeys token tokens credential credentials export backup
	device devices security`)

// secretText reports whether any of texts reads as a secret screen.
func secretText(texts ...string) bool {
	for _, t := range texts {
		w := words(t)
		for i := range w {
			if secretWords[w[i]] || i+1 < len(w) && secretWords[w[i]+w[i+1]] {
				return true
			}
		}
	}
	return false
}
