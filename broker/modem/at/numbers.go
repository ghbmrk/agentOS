package at

import "strings"

// E164 writes a numeric address the way the owner's number is configured:
// + and the country code. Networks deliver the same caller as
// international (type 1, "+15555123456"), national ("5555123456") or
// unknown with a trunk or exit prefix ("015…", "0044…"); without this the
// owner's own texts can fail to match their number and lock them out.
// cc is the home country code from setup (digits, e.g. "1" or "44"); with
// none, national numbers are returned unchanged.
func E164(number string, ton byte, cc string) string {
	d := strings.TrimPrefix(number, "+")
	if strings.HasPrefix(number, "+") || ton == 1 {
		return "+" + d
	}
	if cc == "" || d == "" {
		return number
	}
	if cc == "1" { // NANP: 10-digit national numbers, 011 to dial out
		switch {
		case strings.HasPrefix(d, "011"):
			return "+" + d[3:]
		case len(d) == 10:
			return "+1" + d
		case len(d) == 11 && d[0] == '1':
			return "+" + d
		}
		return number
	}
	switch {
	case strings.HasPrefix(d, "00"):
		return "+" + d[2:]
	case strings.HasPrefix(d, "0"):
		return "+" + cc + d[1:]
	case strings.HasPrefix(d, cc) && len(d) > 10:
		return "+" + d
	}
	return number
}

// SameNumber compares two numbers by their digits after E164.
func SameNumber(a, b, cc string) bool {
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
