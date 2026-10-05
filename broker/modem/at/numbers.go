package at

import (
	"strings"
	"unicode"
)

// keepsTrunk lists country codes whose numbers keep their leading 0 after
// the country code (Italy, San Marino, Vatican).
var keepsTrunk = map[string]bool{"39": true, "378": true, "379": true}

// E164 writes a numeric address the way the owner's number is configured:
// + and the country code. Networks deliver the same caller as
// international (type 1, "+15555123456"), national ("5555123456") or
// unknown with a trunk or exit prefix ("015…", "0044…"), and some put the
// exit prefix or the trunk 0 after a + ("+0044…", "+4407…"); without this
// the owner's own texts can fail to match their number and lock them out,
// and the second line could text the owner. cc is the home country code
// from setup (digits, e.g. "1" or "44"); with none, national numbers are
// returned unchanged. Addresses with letters are returned unchanged.
func E164(number string, ton byte, cc string) string {
	if strings.ContainsFunc(number, unicode.IsLetter) {
		return number
	}
	d := digits(number)
	if d == "" {
		return number
	}
	if strings.HasPrefix(strings.TrimSpace(number), "+") || ton == 1 {
		// A + followed by an exit prefix or a stray 0: no country code
		// starts with 0.
		if strings.HasPrefix(d, "011") {
			d = d[3:]
		} else {
			d = strings.TrimLeft(d, "0")
		}
		return "+" + trunk(d, cc)
	}
	if cc == "" {
		return number
	}
	switch {
	case strings.HasPrefix(d, "011") && cc == "1":
		d = d[3:]
	case strings.HasPrefix(d, "00"):
		d = strings.TrimLeft(d[2:], "0")
	case cc == "1" && len(d) == 10: // NANP national
		d = "1" + d
	case cc == "1" && len(d) == 11 && d[0] == '1':
	case cc != "1" && d[0] == '0': // national with trunk 0
		if keepsTrunk[cc] {
			d = cc + d
		} else {
			d = cc + d[1:]
		}
	case cc != "1" && strings.HasPrefix(d, cc) && len(d) > 10:
	default:
		return number
	}
	return "+" + trunk(d, cc)
}

// trunk drops a national trunk 0 written after the home country code.
func trunk(d, cc string) string {
	if cc != "" && !keepsTrunk[cc] && strings.HasPrefix(d, cc+"0") {
		return cc + d[len(cc)+1:]
	}
	return d
}

// SameNumber compares two numbers by their digits after E164. An
// alphanumeric sender is never the same as any number.
func SameNumber(a, b, cc string) bool {
	if strings.HasPrefix(a, "alpha:") || strings.HasPrefix(b, "alpha:") {
		return false
	}
	da, db := digits(E164(a, 0, cc)), digits(E164(b, 0, cc))
	return da != "" && da == db
}

func digits(n string) string {
	var sb strings.Builder
	for _, c := range n {
		if c >= '0' && c <= '9' {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}
