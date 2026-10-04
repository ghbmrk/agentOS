package owner

import (
	"strconv"
	"strings"
	"unicode"
)

// reply is an owner message that answers the owner channel: RESUME, YES,
// NO, UNDO, or MORE with their arguments (CH-11, CH-13). Like every control
// word it counts only as the whole message, ignoring case and punctuation.
type reply struct {
	word  string
	id    string // request ID, "" if omitted
	items []int  // batch item numbers, 1-based
	code  string // trailing code of 6 or more digits
	token string // challenge-mode token (UNLOCK, RESUME)
}

// fields upper-cases letters and digits and splits on everything else, as
// control.Parse does.
func fields(msg string) []string {
	return strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return ' '
	}, msg))
}

// parseReply reports whether msg is one of the owner channel's words.
//
//	YES [id] [item...] [code]   NO [id] [item...]
//	UNDO id   MORE id   RUN
//	RESUME [code]   RESUME token code   UNLOCK [token code]
//
// An id starts with a letter and has at most 3 characters; an item is a
// number up to 2 digits; a code is 6 to 8 digits.
func parseReply(msg string) (reply, bool) {
	f := fields(msg)
	if len(f) == 0 {
		return reply{}, false
	}
	r := reply{word: f[0]}
	args := f[1:]
	switch r.word {
	case "UNDO", "MORE":
		if len(args) == 1 && isID(args[0]) {
			r.id = args[0]
			return r, true
		}
		return reply{}, false
	case "RUN":
		if len(args) == 0 {
			return r, true
		}
		return reply{}, false
	case "RESUME", "UNLOCK":
		switch {
		case len(args) == 0:
			return r, true
		case len(args) == 1 && isCode(args[0]) && r.word == "RESUME":
			r.code = args[0]
			return r, true
		case len(args) == 2 && isToken(args[0]) && isCode(args[1]):
			r.token, r.code = args[0], args[1]
			return r, true
		}
		return reply{}, false
	case "YES", "NO":
	default:
		return reply{}, false
	}
	if len(args) > 0 && isID(args[0]) {
		r.id, args = args[0], args[1:]
	}
	if r.word == "YES" && len(args) > 0 && isCode(args[len(args)-1]) {
		r.code, args = args[len(args)-1], args[:len(args)-1]
	}
	for _, a := range args {
		n, err := strconv.Atoi(a)
		if err != nil || len(a) > 2 || n < 1 {
			return reply{}, false
		}
		r.items = append(r.items, n)
	}
	return r, true
}

func isID(s string) bool {
	if len(s) == 0 || len(s) > 3 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// isToken is a challenge-mode token: 4 letters or digits.
func isToken(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isCode(s string) bool { return len(s) >= 6 && len(s) <= 8 && allDigits(s) }

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// trailingCode splits a message whose last word is a code of exactly 6
// digits, separated by a space, from the rest (CH-14: a code may be
// appended to any message). "room 12" and "flight AB482913" do not count.
func trailingCode(msg string) (rest, code string, ok bool) {
	s := strings.TrimRightFunc(msg, func(r rune) bool { return !unicode.IsDigit(r) && !unicode.IsLetter(r) })
	i := strings.LastIndexFunc(s, unicode.IsSpace)
	if i < 0 {
		return msg, "", false
	}
	code = s[i+1:]
	if len(code) != codeDigits || !allDigits(code) {
		return msg, "", false
	}
	return strings.TrimSpace(s[:i]), code, true
}
