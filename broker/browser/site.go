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
// recovery. Pairs are matched joined ("two factor" as "twofactor"). Words
// a checkout also uses ("Security code", "Gift card PIN", "Remember this
// device", a "?token=" URL) count only in a pair that names the secret.
// The list errs wide: a false match costs one more tap, a miss would let a
// task's tap cover a secret (#2689 item 3).
var secretWords = wordSet(`password passwords passcode passkey passkeys passphrase recovery
	mfa 2fa 2sv twofactor twostep onetime otp totp authenticator authentication
	secret secrets apikey apikeys credential credentials key keys ssh gpg oauth
	securitysettings securityquestion securityquestions securitykey securitykeys
	accesstoken accesstokens apitoken apitokens newtoken changepin newpin resetpin
	adddevice newdevice yourdevices backupcode backupcodes exportdata exportaccount changeemail`)

// secretText is the first of texts' words, or joined word pairs, that
// reads as a secret screen, "" if none.
func secretText(texts ...string) string {
	for _, t := range texts {
		w := words(t)
		for i := range w {
			if secretWords[w[i]] {
				return w[i]
			}
			if i+1 < len(w) && secretWords[w[i]+w[i+1]] {
				return w[i] + " " + w[i+1]
			}
		}
	}
	return ""
}
