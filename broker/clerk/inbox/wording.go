package inbox

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// alertPhrases are VRB-2's second alert net: security-alert wording that
// marks a mail an alert whoever sent it. They are broker/mail's AlertPhrases
// (ADP-2), which step 5 deletes with that package; the owner's languages add
// to them in a later row (ASSUMPTIONS.md MIG-4-mail-reader-3).
var alertPhrases = []string{
	"sign-in", "signin", "sign in", "signed in", "log-in attempt", "login attempt", "new login", "new sign",
	"new device", "password reset", "reset your password", "password was changed", "password changed",
	"security alert", "security notice", "security code", "suspicious", "unusual activity", "unusual sign",
	"is this you", "was this you", "unusual transaction", "verify your identity", "verification code",
	"two-step", "2-step", "two-factor", "recovery email", "recovery phone",
	"payment received", "payment failed", "payment declined", "payment notice", "payment due",
	"account change", "account was changed", "account details changed", "email address changed", "phone number changed",
}

// tokenFormats are known secret formats (CH-19's, from owner.SecretShaped):
// a mail that carries one is not hidden without asking.
var tokenFormats = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`\bAKIA[0-9A-Z]{16}\b`,
	`\bgh[pousr]_[A-Za-z0-9]{30,}`,
	`\bgithub_pat_[A-Za-z0-9_]{20,}`,
	`\bxox[abprs]-[A-Za-z0-9-]{10,}`,
	`\bsk-[A-Za-z0-9_-]{20,}`,
	`\b[rs]k_(live|test)_[A-Za-z0-9]{16,}`,
	`\bAIza[0-9A-Za-z_-]{35}`,
	`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`,
	`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
	`otpauth://`,
}, "|"))

// codeWords anchor short codes (CH-19's): a 4-10 character token with a
// digit counts only within codeReach words of one, so amounts, dates and
// order numbers pass.
var codeWords = map[string]bool{
	"code": true, "codes": true, "otp": true, "verification": true, "verify": true,
	"pin": true, "passcode": true, "2fa": true, "mfa": true, "one-time": true,
	"security": true, "login": true, "token": true, "password": true, "pass": true,
	"key": true, "sign-in": true, "signin": true,
}

const codeReach = 4

// wordingAlert reports whether text carries alert wording, a known secret
// format or a code next to a code word. It runs on the text folded to lower
// case with every run of space made one, fullwidth forms made ASCII, every
// Unicode decimal digit made its ASCII digit, and format characters dropped.
// The fold is no CH-12 skeleton: this net is how a real alert, written
// plainly, is kept, and a sender who disguises its wording only makes its own
// mail trashable, which the reader's class already allows
// (ASSUMPTIONS.md MIG-4-mail-reader-3).
func wordingAlert(text string) bool {
	f := foldText(text)
	if tokenFormats.MatchString(f) {
		return true
	}
	for _, p := range alertPhrases {
		if containsWord(f, p) {
			return true
		}
	}
	return codeAfterCodeIs.MatchString(f) || codeNearWord(strings.ReplaceAll(f, "sign in", "signin"))
}

// codeAfterCodeIs is a 4-digit number right after "code is" or "code:",
// which is a code even when it reads as a year (Mark, #2992).
var codeAfterCodeIs = regexp.MustCompile(`code(?: is:?|:) ?[0-9]{4}(?:[^0-9]|$)`)

// containsWord reports whether p occurs in s at the start of a word: the
// character before it is not an ASCII letter or digit, so "signin" is not
// read inside "designing" (#2888). The end is left open, so inflected and
// run-on forms ("login attempts", "sign-ins", "signed into") still match,
// and another script's letter beside it is a boundary.
func containsWord(s, p string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], p)
		if j < 0 {
			return false
		}
		j += i
		if j == 0 || !asciiWord(s[j-1]) {
			return true
		}
		i = j + 1
	}
}

func asciiWord(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

func foldText(s string) string {
	var b strings.Builder
	space := true
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		switch {
		case unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		case r >= 0x80 && unicode.IsDigit(r):
			r = '0' + rune(digitValue(r))
		case unicode.Is(unicode.Cf, r):
			continue
		}
		b.WriteRune(unicode.ToLower(r))
		space = false
	}
	return b.String()
}

// digitValue is a decimal digit's value: Unicode lays every decimal digit set
// out as ten consecutive code points from zero.
func digitValue(r rune) int {
	n := 0
	for unicode.IsDigit(r - rune(n) - 1) {
		n++
	}
	return n % 10
}

// codeNearWord reports whether a code-like token lies within codeReach words
// of a code word. Adjacent digit groups join, so "482 913" reads as one code.
func codeNearWord(s string) bool {
	var words []string
	for _, w := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-')
	}) {
		if n := len(words); n > 0 && allDigits(w) && allDigits(words[n-1]) && len(words[n-1])+len(w) <= 10 {
			words[n-1] += w
			continue
		}
		words = append(words, w)
	}
	for i, w := range words {
		if !codeWords[w] {
			continue
		}
		for j := max(0, i-codeReach); j <= i+codeReach && j < len(words); j++ {
			if j != i && codeLike(words[j]) {
				return true
			}
		}
	}
	return false
}

func allDigits(w string) bool {
	for _, r := range w {
		if r < '0' || r > '9' {
			return false
		}
	}
	return w != ""
}

// codeLike is a 4-10 character token of letters, digits and dashes with at
// least one digit (482913, G-482913, A1B2C3). A year from 1900 to 2099 is a
// date, which CH-19 lets pass (#2888), and a word with a few digits is a
// promo code (#2992).
func codeLike(w string) bool {
	return len(w) >= 4 && len(w) <= 10 && strings.ContainsAny(w, "0123456789") && !isYear(w) && !promoCode(w)
}

// promoCode is one run of three or more letters and one run of digits, in
// either order, with fewer digits than letters or a year: SAVE20, SPRING25,
// 20OFF, SAVE2026. Login codes are digits or mixed (G-482913, A1B2C3, K7XQ).
func promoCode(w string) bool {
	m := promoShape.FindStringSubmatch(strings.ReplaceAll(w, "-", ""))
	if m == nil {
		return false
	}
	letters, digits := m[1]+m[4], m[2]+m[3]
	return len(digits) < len(letters) || isYear(digits)
}

var promoShape = regexp.MustCompile(`^(?:([a-z]{3,})([0-9]+)|([0-9]+)([a-z]{3,}))$`)

func isYear(w string) bool {
	return len(w) == 4 && allDigits(w) && (w[:2] == "19" || w[:2] == "20")
}

// The bounds on what mailText reads of one mail.
const (
	maxTextParts = 64
	maxTextBytes = 64 << 10
)

// mailText is what the wording net reads: the decoded subject and every
// text/plain and text/html part, decoded from quoted-printable or base64 and
// with HTML's tags dropped and entities decoded, bounded. A charset other than
// UTF-8 is read as it comes, which keeps ASCII wording readable. A mail that
// does not parse is read whole, as it came.
func mailText(raw []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return string(raw[:min(len(raw), maxTextBytes)])
	}
	var b strings.Builder
	subject := m.Header.Get("Subject")
	if d, err := (&mime.WordDecoder{CharsetReader: rawCharset}).DecodeHeader(subject); err == nil {
		subject = d
	}
	b.WriteString(subject)
	parts := 0
	textParts(m.Header, m.Body, &b, &parts, 0)
	return b.String()
}

// rawCharset reads any charset's bytes as they come.
func rawCharset(_ string, r io.Reader) (io.Reader, error) { return r, nil }

type getter interface{ Get(string) string }

func textParts(h getter, body io.Reader, b *strings.Builder, parts *int, depth int) {
	if *parts++; *parts > maxTextParts || depth > 8 || b.Len() >= maxTextBytes {
		return
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = "text/plain" // read it rather than skip it
	}
	if strings.HasPrefix(mt, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			textParts(p.Header, p, b, parts, depth+1)
		}
	}
	if mt != "text/plain" && mt != "text/html" {
		return
	}
	r := io.LimitReader(body, 4*maxTextBytes)
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, lineDropper{r})
	}
	t, _ := io.ReadAll(io.LimitReader(r, int64(maxTextBytes-b.Len())))
	s := string(t)
	if mt == "text/html" {
		s = html.UnescapeString(htmlTag.ReplaceAllString(s, " "))
	}
	b.WriteString("\n")
	b.WriteString(s)
}

var htmlTag = regexp.MustCompile(`(?s)<(script|style)\b.*?</(script|style)\s*>|<[^>]*>`)

// lineDropper drops CR and LF so base64 decodes across lines.
type lineDropper struct{ r io.Reader }

func (l lineDropper) Read(p []byte) (int, error) {
	for {
		k, err := l.r.Read(p)
		j := 0
		for _, c := range p[:k] {
			if c != '\r' && c != '\n' {
				p[j] = c
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}
