// Package hostiletext is one corpus of text that a name or label check must
// refuse, and Run, which feeds it through a check (REV-CHK-names, #3901).
// Reviews kept finding checks that accepted a blank, invisible or invalid
// name, each with its own hand-picked bad inputs (#3284, #3438, #3871); a
// check that runs this corpus refuses every shape below, and an entry added
// here reaches every such check at once.
//
// It is for tests only: no non-test file imports it (TestOnlyTestsImport).
package hostiletext

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Entry is one hostile text, with a name for the failure message.
type Entry struct{ Name, Text string }

// Plain is the positive control: every check accepts it, so a check that
// refuses everything does not pass Run.
const Plain = "name"

// Blank is text with nothing to see in it. Run feeds each entry alone.
var Blank = []Entry{
	{"empty", ""},
	{"space", " "},
	{"spaces and tab", " \t  "},
	{"NBSP only", "\u00a0"},
	{"ideographic space only", "\u3000"},
	{"hangul filler only", "\u3164"},
}

// Hidden is text that changes what a line means or shows without being
// seen, or is not text at all. Run feeds each entry alone and embedded at
// the start, middle and end of Plain.
var Hidden = []Entry{
	{"NBSP", "\u00a0"},
	{"zero-width space U+200B", "\u200b"},
	{"zero-width non-joiner U+200C", "\u200c"},
	{"zero-width joiner U+200D", "\u200d"},
	{"word joiner U+2060", "\u2060"},
	{"byte order mark U+FEFF", "\ufeff"},
	{"soft hyphen U+00AD", "\u00ad"},
	{"combining grapheme joiner U+034F", "\u034f"},
	{"Mongolian vowel separator U+180E", "\u180e"},
	{"variation selector 16", "\ufe0f"},
	{"variation selector 17", "\U000e0100"},
	{"hangul filler U+3164", "\u3164"},
	{"hangul choseong filler U+115F", "\u115f"},
	{"halfwidth hangul filler U+FFA0", "\uffa0"},
	{"Khmer vowel inherent U+17B4", "\u17b4"},
	{"LRE U+202A", "\u202a"},
	{"RLE U+202B", "\u202b"},
	{"PDF U+202C", "\u202c"},
	{"LRO U+202D", "\u202d"},
	{"RLO U+202E", "\u202e"},
	{"LRI U+2066", "\u2066"},
	{"RLI U+2067", "\u2067"},
	{"FSI U+2068", "\u2068"},
	{"PDI U+2069", "\u2069"},
	{"LRM U+200E", "\u200e"},
	{"RLM U+200F", "\u200f"},
	{"ALM U+061C", "\u061c"},
	{"tag space U+E0020", "\U000e0020"},
	{"tag a U+E0061", "\U000e0061"},
	{"cancel tag U+E007F", "\U000e007f"},
	{"lone CR", "\r"},
	{"LF", "\n"},
	{"CRLF", "\r\n"},
	{"NEL U+0085", "\u0085"},
	{"line separator U+2028", "\u2028"},
	{"paragraph separator U+2029", "\u2029"},
	{"NUL", "\x00"},
	{"SOH", "\x01"},
	{"backspace", "\b"},
	{"tab", "\t"},
	{"vertical tab", "\v"},
	{"form feed", "\f"},
	{"escape", "\x1b"},
	{"DEL", "\x7f"},
	{"C1 U+0080", "\u0080"},
	{"CSI U+009B", "\u009b"},
	{"C1 U+009F", "\u009f"},
	{"invalid byte FF", "\xff"},
	{"overlong slash C0 AF", "\xc0\xaf"},
	{"surrogate D800 as UTF-8", "\xed\xa0\x80"},
	{"truncated sequence", "\xe2\x82"},
}

// Except names Hidden entries a check may accept, each with its reason: a
// text a check's domain needs, such as the joiners that build Persian and
// Indic words (#2740). An entry Except names that is not in Hidden fails Run,
// so a renamed entry does not quietly widen it. Review checks each reason.
type Except map[string]string

// Accepted lists what accept wrongly decides: each shape it accepts that no
// exception covers, Plain if it refuses that, and each exception that names
// no entry.
func Accepted(accept func(string) bool, except ...Except) []string {
	var bad []string
	allowed := map[string]bool{}
	for _, ex := range except {
		for name, why := range ex {
			if !slices.ContainsFunc(Hidden, func(e Entry) bool { return e.Name == name }) {
				bad = append(bad, "excepts "+strconv.Quote(name)+", which is no Hidden entry")
			}
			if strings.TrimSpace(why) == "" {
				bad = append(bad, "excepts "+strconv.Quote(name)+" with no reason")
			}
			allowed[name] = true
		}
	}
	if !accept(Plain) {
		bad = append(bad, "refuses the plain "+strconv.Quote(Plain)+" (positive control)")
	}
	for _, e := range Blank {
		if accept(e.Text) {
			bad = append(bad, "accepts blank "+e.Name+" "+strconv.QuoteToASCII(e.Text))
		}
	}
	mid := len(Plain) / 2
	for _, e := range Hidden {
		if allowed[e.Name] {
			continue
		}
		for _, w := range []struct{ where, text string }{
			{"alone", e.Text},
			{"leading", e.Text + Plain},
			{"inside", Plain[:mid] + e.Text + Plain[mid:]},
			{"trailing", Plain + e.Text},
		} {
			if accept(w.text) {
				bad = append(bad, "accepts "+e.Name+" "+w.where+" "+strconv.QuoteToASCII(w.text))
			}
		}
	}
	return bad
}

// Run fails t for every shape accept accepts and no exception covers, and if
// it refuses Plain. accept is the check as its caller uses it: it may wrap
// the text, as in a path ("/mnt/" + s), so long as the hostile text is what
// decides.
func Run(t testing.TB, accept func(string) bool, except ...Except) {
	t.Helper()
	for _, b := range Accepted(accept, except...) {
		t.Errorf("hostiletext: %s", b)
	}
}
