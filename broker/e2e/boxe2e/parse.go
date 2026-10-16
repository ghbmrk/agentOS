package main

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// The driver reads the pages an owner's phone sees. Nothing it parses goes
// to the console: errors name what was missing, and page details are
// reduced to a sanitized heading.

var (
	passRe   = regexp.MustCompile(`(?s)<h2>Vault passphrase</h2>.*?<p class="mono big">(.*?)</p>`)
	recRe    = regexp.MustCompile(`(?s)<h1>Recovery key</h1>.*?<p class="mono big">(.*?)</p>`)
	promptRe = regexp.MustCompile(`Type word (\d+) of your vault passphrase and group (\d+) of your recovery key\.`)
	smsRe    = regexp.MustCompile(`href="sms:(\+[0-9]+)\?&body=PAIR%20([A-Za-z0-9]+)"`)
	otpRe    = regexp.MustCompile(`href="otpauth://totp/[^"?]*\?[^"]*?\bsecret=([A-Z2-7]+)`)
	stepRe   = regexp.MustCompile(`(?s)<h2>(\d\. .*?)</h2>`)
	headRe   = regexp.MustCompile(`(?s)<h[12]>(.*?)</h[12]>`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
	unsafeRe = regexp.MustCompile(`[^A-Za-z0-9 .,'()-]`)
)

// sheetSecrets reads the vault passphrase and recovery key from the saved
// Owner Card sheet, each under its own heading.
func sheetSecrets(sheet []byte) (pass, rec string, err error) {
	p, r := passRe.FindSubmatch(sheet), recRe.FindSubmatch(sheet)
	if p == nil || r == nil {
		return "", "", errors.New("the card sheet has no passphrase or recovery key")
	}
	return html.UnescapeString(string(p[1])), html.UnescapeString(string(r[1])), nil
}

// promptAsks reads the first-boot confirm prompt's 1-based word and group.
func promptAsks(page []byte) (word, group int, err error) {
	m := promptRe.FindSubmatch(page)
	if m == nil {
		return 0, 0, errors.New("the card page has no first-boot prompt")
	}
	word, _ = strconv.Atoi(string(m[1]))
	group, _ = strconv.Atoi(string(m[2]))
	return word, group, nil
}

// answers picks the asked word and group, as the owner reads them off the
// card.
func answers(pass, rec string, word, group int) (string, string, error) {
	words, groups := strings.Fields(pass), strings.Split(rec, "-")
	if word < 1 || word > len(words) || group < 1 || group > len(groups) {
		return "", "", fmt.Errorf("the prompt asks word %d and group %d of %d and %d", word, group, len(words), len(groups))
	}
	return words[word-1], groups[group-1], nil
}

// smsLink reads the box's number and pairing code from the text-your-box
// link.
func smsLink(page []byte) (num, code string, ok bool) {
	m := smsRe.FindStringSubmatch(html.UnescapeString(string(page)))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// lineState names which of the text-your-box step's three forms the page
// shows, from fixed wording only, so a failure can say why no link came
// without quoting the page.
func lineState(page []byte) string {
	s := string(page)
	switch {
	case strings.Contains(s, "I cannot send texts right now"):
		return "cannot-text"
	case strings.Contains(s, "I do not know my own number yet"):
		return "number-unknown"
	case strings.Contains(s, `href="sms:`):
		return "link"
	}
	return "other"
}

// otpSeed reads the code generator's secret from its enrollment link.
func otpSeed(page []byte) ([]byte, error) {
	m := otpRe.FindStringSubmatch(html.UnescapeString(string(page)))
	if m == nil {
		return nil, errors.New("the page has no code generator link")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
}

func base32Std(b []byte) string { return base32.StdEncoding.EncodeToString(b) }

// heading names a page for the console: the numbered setup step if there is
// one, else the first heading, with tags and anything unusual removed.
func heading(page []byte) string {
	m := stepRe.FindSubmatch(page)
	if m == nil {
		m = headRe.FindSubmatch(page)
	}
	if m == nil {
		return `"(no heading)"`
	}
	s := html.UnescapeString(tagRe.ReplaceAllString(string(m[1]), ""))
	s = strings.Join(strings.Fields(unsafeRe.ReplaceAllString(s, "")), " ")
	if len(s) > 60 {
		s = s[:60]
	}
	return strconv.Quote(s)
}

// aiOpen is the line the Connect AI step shows once it lists providers;
// before the box has updated it shows only a wait message.
const aiOpen = "One is enough. You can add more later."

// deviceOffer reports whether the Connect AI step offers a device-code
// sign-in for provider.
func deviceOffer(page []byte, provider string) bool {
	return bytes.Contains(page, []byte(`<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="`+
		html.EscapeString(provider)+`">`))
}

var deviceRe = regexp.MustCompile(`<p>Open <a href="([^"]*)">[^<]*</a> and enter <span class="mono">([^<]*)</span>\.</p>`)

// deviceLink reads the provider's sign-in link and the code to enter there
// from the Connect AI step, after the owner chose to sign in.
func deviceLink(page []byte) (link, code string, ok bool) {
	m := deviceRe.FindSubmatch(page)
	if m == nil {
		return "", "", false
	}
	return html.UnescapeString(string(m[1])), html.UnescapeString(string(m[2])), true
}
