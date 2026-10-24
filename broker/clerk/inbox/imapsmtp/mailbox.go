package imapsmtp

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf16"
)

// The filter binds a write to its folder by comparing the connection's
// command to the one go-imap writes for the request's own mailbox names,
// which this side encodes (it decodes nothing): modified UTF-7 (RFC 3501
// 5.1.3), then INBOX bare for SELECT and a Go-quoted string otherwise.

var mutf7 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

// utf7 is name in modified UTF-7, as go-imap's utf7 encoder writes it.
func utf7(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); {
		if c := name[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
			if c == '&' {
				b.WriteByte('-')
			}
			i++
			continue
		}
		start := i
		for i++; i < len(name) && (name[i] < 0x20 || name[i] > 0x7e); i++ {
		}
		var u []byte
		for _, r := range name[start:i] {
			if r1, r2 := utf16.EncodeRune(r); r1 != '�' {
				u = append(u, byte(r1>>8), byte(r1))
				r = r2
			}
			u = append(u, byte(r>>8), byte(r))
		}
		b.WriteString("&" + mutf7.EncodeToString(u) + "-")
	}
	return b.String()
}

// selectArg is folder as go-imap writes it after SELECT or EXAMINE.
func selectArg(folder string) string {
	e := utf7(folder)
	if strings.EqualFold(e, "INBOX") {
		return e
	}
	return strconv.Quote(e)
}

// mailboxArg is a mailbox as go-imap writes it in UID MOVE.
func mailboxArg(name string) string { return strconv.Quote(utf7(name)) }
