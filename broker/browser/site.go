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
// show an API key or token, reset a password or PIN, add a device, export,
// back up, change account recovery or security. Pairs are matched joined
// ("two factor" as "twofactor"), and each word also matches its plural
// ("Passphrases"). The list fails closed: a word counts on
// its own, and only the whole checkout texts in notSecret, which use the
// same words for something else, are passed over. A false match costs one more
// tap; a miss would let a task's tap cover a secret (#2689 item 3).
var secretWords = wordSet(`password passcode passkey passphrase recovery
	mfa 2fa 2sv twofactor twostep onetime otp totp authenticator authentication
	secret credential key ssh gpg oauth token export device backup security pin
	seedphrase changeemail`)

// isSecret reports whether w, or w less a plural "s", is a secret word.
func isSecret(w string) bool {
	return secretWords[w] || strings.HasSuffix(w, "s") && secretWords[w[:len(w)-1]]
}

// notSecret are the whole texts a checkout or a product page shows that
// use a secret word for something else: a card's security code, a gift
// card's PIN, a "remember this device" box, a home security product. Only
// a text that is exactly one of them is passed over, so "Enter security
// code" or "Change PIN code" beside it still marks the screen.
var notSecret = wordSet(`securitycode cardsecuritycode cvvsecuritycode securitycodecvv
	giftcardpin enamelpin rememberthisdevice homesecurity smarthomesecurity backupbattery`)

// secretText is the first of texts' words, or joined word pairs, that
// reads as a secret screen, "" if none. A URL's query parameter named
// token is a session token, not a token screen, so its key is not read.
func secretText(texts ...string) string {
	for _, t := range texts {
		w := words(dropTokenKey(t))
		if notSecret[strings.Join(w, "")] {
			continue
		}
		for i := range w {
			if isSecret(w[i]) {
				return w[i]
			}
			if i+1 < len(w) && isSecret(w[i]+w[i+1]) {
				return w[i] + " " + w[i+1]
			}
		}
	}
	return ""
}

// dropTokenKey is t with the key of a query parameter named exactly
// "token" removed (not "access_token" or "TOKEN"),
// its value kept ("?token=abc" reads "?=abc").
func dropTokenKey(t string) string {
	q := strings.IndexByte(t, '?')
	if q < 0 {
		return t
	}
	pairs := strings.Split(t[q+1:], "&")
	for i, p := range pairs {
		if k, v, ok := strings.Cut(p, "="); ok && k == "token" {
			pairs[i] = "=" + v
		}
	}
	return t[:q+1] + strings.Join(pairs, "&")
}
