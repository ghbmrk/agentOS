package owner

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/modem"
)

// MaxSegments caps every broker text (CH-12).
const MaxSegments = 3

// lookalikes folds characters that imitate Latin letters, so recipients
// render as plain text (CH-10). Anything else outside fieldChars is dropped.
var lookalikes = map[rune]string{
	// Cyrillic
	'а': "a", 'в': "b", 'е': "e", 'к': "k", 'м': "m", 'н': "h", 'о': "o", 'р': "p", 'с': "c", 'т': "t",
	'у': "y", 'х': "x", 'і': "i", 'ј': "j", 'ѕ': "s", 'ԁ': "d", 'ԛ': "q", 'ԝ': "w",
	'А': "A", 'В': "B", 'Е': "E", 'К': "K", 'М': "M", 'Н': "H", 'О': "O", 'Р': "P", 'С': "C", 'Т': "T",
	'У': "Y", 'Х': "X", 'І': "I", 'Ј': "J", 'Ѕ': "S",
	// Greek
	'α': "a", 'ο': "o", 'ν': "v", 'ρ': "p", 'τ': "t", 'υ': "u", 'ι': "i", 'κ': "k",
	'Α': "A", 'Β': "B", 'Ε': "E", 'Ζ': "Z", 'Η': "H", 'Ι': "I", 'Κ': "K", 'Μ': "M", 'Ν': "N", 'Ο': "O",
	'Ρ': "P", 'Τ': "T", 'Υ': "Y", 'Χ': "X",
	// Latin with marks
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ı': "i",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ñ': "n", 'ç': "c", 'ý': "y", 'ÿ': "y", 'ß': "ss",
	'À': "A", 'Á': "A", 'Â': "A", 'Ä': "A", 'Å': "A", 'É': "E", 'È': "E", 'Ö': "O", 'Ü': "U", 'Ñ': "N",
	// Apostrophes as phone keyboards type them.
	'\u2018': "'", '\u2019': "'", '\u02BC': "'",
	// Superscript and subscript digits (not decimal digits in Unicode).
	'⁰': "0", '¹': "1", '²': "2", '³': "3", '⁴': "4", '⁵': "5", '⁶': "6", '⁷': "7", '⁸': "8", '⁹': "9",
	'₀': "0", '₁': "1", '₂': "2", '₃': "3", '₄': "4", '₅': "5", '₆': "6", '₇': "7", '₈': "8", '₉': "9",
	'ℓ': "l", '℮': "e", 'ⅰ': "i", 'ⅼ': "l", '€': " EUR ", '£': " GBP ", '¥': " JPY ",
}

// fieldChars may appear in a rendered field. No line breaks, no GSM-7
// extension characters, nothing that renders ambiguously.
func fieldChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		strings.ContainsRune(" .,:;@+-_/$#%&'()*!?=", r)
}

// fold maps text to the plain form every fixed-pattern check runs on, a
// small stand-in for NFKC (golang.org/x/text is third-party, DEP-1):
// fullwidth forms become ASCII, every Unicode decimal digit becomes its
// ASCII digit, look-alike letters fold to Latin, and combining marks and
// format characters (zero-width joiners and the like) are dropped.
func fold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if r >= 0x1D400 && r <= 0x1D6A3 {
			// Mathematical alphanumeric letters: styled runs of A-Z a-z.
			off := (r - 0x1D400) % 52
			if off < 26 {
				r = 'A' + off
			} else {
				r = 'a' + off - 26
			}
		}
		switch {
		case r < 0x80:
			b.WriteRune(r)
		case unicode.IsDigit(r):
			b.WriteByte(byte('0' + digitValue(r)))
		case lookalikes[r] != "":
			b.WriteString(lookalikes[r])
		case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r):
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// digitValue is a decimal digit's value. Unicode lays every decimal digit
// set out as ten consecutive code points from zero, so the value is the
// number of digits just before r, modulo 10.
func digitValue(r rune) int {
	n := 0
	for unicode.IsDigit(r - rune(n) - 1) {
		n++
	}
	return n % 10
}

// longDigits finds runs of 6 or more digits.
var longDigits = regexp.MustCompile(`[0-9]{6,}`)

// field renders a verified value for a broker text: folded, everything
// outside a fixed alphabet dropped, whitespace collapsed, long digit runs
// cut to their last 4 so no field reads like a code, cut to max, and
// replaced if secret-shaped (CH-10, CH-12, CH-19).
func field(s string, max int) string {
	var b strings.Builder
	for _, r := range fold(s) {
		switch {
		case fieldChar(r):
			b.WriteRune(r)
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte(' ')
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if SecretShaped(out) {
		return "[hidden]"
	}
	out = longDigits.ReplaceAllStringFunc(out, func(d string) string { return "..." + d[len(d)-4:] })
	if len(out) > max {
		out = strings.TrimSpace(out[:max-2]) + ".."
	}
	return out
}

// Item is one action awaiting approval. Every field is broker-verified
// (CH-12); none is agent text.
type Item struct {
	// Ref is the caller's handle (e.g. the journal intent ID). It is not
	// rendered.
	Ref string
	// The verb shown is Facts.Verb, the one Classify judged.
	Object string
	// Recipient is a canonical identifier: address, number, or the last
	// 4 digits of an account, never a display name. Several are joined
	// with ", ". Recipients are never cut, hidden, or digit-collapsed: an
	// item whose recipients cannot be shown in full is not approvable by
	// text (SMSApprovable).
	Recipient string
	// Unverified marks an item whose fields the broker could not read
	// from the source; its line starts with a fixed warning outside every
	// field cap.
	Unverified bool
	// Amount is the verified amount as it should read, e.g. "$120.00".
	Amount string
	// UndoWindow is the effect's undo window; zero means it cannot be
	// undone.
	UndoWindow time.Duration
	Facts      Facts
}

func (it Item) line() string {
	s := field(it.Facts.Verb, 12) + " " + field(it.Object, 40)
	if it.Unverified {
		s = "UNVERIFIED, details on the Wi-Fi page: " + s
	}
	if it.Recipient != "" {
		if r, ok := recipientText(it.Recipient); ok {
			s += " to " + r
		} else {
			s += fmt.Sprintf(" to %d recipients, see the Wi-Fi page", len(strings.Split(it.Recipient, ",")))
		}
	}
	if it.Amount != "" {
		s += ", " + field(it.Amount, 16)
	}
	if it.UndoWindow > 0 {
		s += ", undo within " + dur(it.UndoWindow)
	} else {
		s += ", cannot be undone"
	}
	return s
}

// MaxRecipientChars bounds the recipients an approval text shows. Longer
// sets are approvable only on the local page.
const MaxRecipientChars = 100

// recipientText renders recipients in full, folded to plain text (CH-10),
// or reports that they cannot be: a character outside the fixed alphabet,
// a line break, secret-shaped content (CH-19), or more than
// MaxRecipientChars. Nothing is cut, hidden, or collapsed, because a
// shortened recipient can hide where an effect goes.
func recipientText(s string) (string, bool) {
	f := strings.TrimSpace(fold(s))
	if f == "" || len(f) > MaxRecipientChars || SecretShaped(f) {
		return "", false
	}
	for _, r := range f {
		if !fieldChar(r) {
			return "", false
		}
	}
	return f, true
}

// SMSApprovable reports whether an item can be approved by text: its
// recipients, if any, render in full. Request refuses any other item
// (ErrLocalOnly); it waits for the local page.
func SMSApprovable(it Item) bool {
	if it.Recipient == "" {
		return true
	}
	_, ok := recipientText(it.Recipient)
	return ok
}

func dur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d h", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d min", int((d+time.Minute-1)/time.Minute))
	}
}

// fits reports whether s is GSM-7 and within MaxSegments.
func fits(s string) bool {
	n, gsm := modem.Segments(s)
	return gsm && n <= MaxSegments
}
