package browser

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const omittedMark = "[password omitted]"

// minScrub is the shortest value scrubbed from the rest of the page: a
// shorter one ("1", "yes") would wipe ordinary text. It is still omitted
// from its own field (G10).
const minScrub = 4

// entryRoles are the roles an <input> or <textarea> that can hold a
// password is given (G10).
var entryRoles = map[string]bool{"textbox": true, "searchbox": true}

var (
	refToken = regexp.MustCompile(`\[ref=((?:f[0-9]+)?e[0-9]+)\]`)
	roleRE   = regexp.MustCompile(`^[ \t]*- '?[A-Za-z][A-Za-z-]*`)
	attrsRE  = regexp.MustCompile(`^(?: \[[^\]]*\])*`)
	childRE  = regexp.MustCompile(`^([ \t]*- [A-Za-z/][A-Za-z-]*):(.*)$`)
)

// nameEnd returns the index just past the quoted accessible name of a
// snapshot line, or the end of the role when there is no name. The name
// is page-controlled, so a [ref=...] token inside it is not the
// element's ref and the search starts after it (CRED-4). ok is false
// unless the line has the canonical shape `- role "name"` or
// `- role` followed by nothing, ":", " [" or a closing "'": an
// unquoted or unterminated name, extra spaces, or a YAML double-quoted
// key cannot be parsed.
func nameEnd(line string) (end int, ok bool) {
	m := roleRE.FindStringIndex(line)
	if m == nil {
		return 0, false
	}
	i := m[1]
	rest := line[i:]
	switch {
	case rest == "", strings.HasPrefix(rest, ":"), strings.HasPrefix(rest, " ["), strings.HasPrefix(rest, "'"):
		return i, true
	case !strings.HasPrefix(rest, ` "`):
		return 0, false
	}
	for i += 2; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

func indent(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// unquoteKey drops the opening quote of a YAML single-quoted key.
func unquoteKey(s string) string {
	in := indent(s)
	if strings.HasPrefix(s[len(in):], "- '") {
		return in + "- " + s[len(in)+3:]
	}
	return s
}

// yamlValue decodes a snapshot value that may be YAML-quoted.
func yamlValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		if u, err := strconv.Unquote(v); err == nil {
			return u
		}
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	return v
}

// omitUnparsed handles a line that cannot be parsed, so the element's
// own ref cannot be told from a decoy. If any ref on the line is a
// password field, everything after the role is replaced (fail closed)
// and the text after that ref is returned as the value.
func omitUnparsed(line string, refs map[string]bool) (string, string, bool) {
	for _, m := range refToken.FindAllStringSubmatchIndex(line, -1) {
		if !refs[line[m[2]:m[3]]] {
			continue
		}
		head := indent(line) + "- "
		if r := roleRE.FindString(line); r != "" {
			head = unquoteKey(r) + " "
		}
		v := strings.TrimLeft(line[m[1]:], " :'")
		return head + line[m[0]:m[1]] + ": " + omittedMark, v, true
	}
	return line, "", false
}

// omitLine omits the value of a password field's own line and returns
// the value it removed.
func omitLine(line string, refs map[string]bool) (string, string, bool) {
	start, ok := nameEnd(line)
	if !ok {
		return omitUnparsed(line, refs)
	}
	m := refToken.FindStringSubmatchIndex(line[start:])
	var end int
	switch {
	case m != nil && refs[line[start+m[2]:start+m[3]]]:
		end = start + m[1]
	case m == nil && refs[noRef] && isEntry(line):
		end = start
	default:
		return line, "", false
	}
	rest := line[end:]
	attr := attrsRE.FindString(rest)
	head := unquoteKey(line[:end] + attr)
	tail := strings.TrimLeft(rest[len(attr):], "'")
	switch {
	case strings.HasPrefix(tail, ":") && strings.TrimSpace(tail[1:]) != "":
		return head + ": " + omittedMark, tail[1:], true
	case strings.HasPrefix(tail, ":"):
		return head + ":", "", true
	default:
		return head, "", true
	}
}

// omitChild omits the value of a line nested under a password field: a
// field with a placeholder renders its value as a `- text:` child. Only
// the placeholder is kept; any other child loses everything after its
// key.
func omitChild(line string) (string, string) {
	m := childRE.FindStringSubmatch(line)
	switch {
	case m != nil && strings.HasSuffix(m[1], "- /placeholder"):
		return line, ""
	case m != nil && strings.TrimSpace(m[2]) == "":
		return line, ""
	case m != nil:
		return m[1] + ": " + omittedMark, m[2]
	}
	in := indent(line)
	return in + "- " + omittedMark, strings.TrimPrefix(line[len(in):], "- ")
}

// noRef stands in refs for every entry field the snapshot gives no ref,
// such as one the page made non-interactive: its value is omitted all
// the same (G10).
const noRef = ""

// isEntry reports whether line is a node with one of entryRoles.
func isEntry(line string) bool {
	r := roleRE.FindString(line)
	return r != "" && entryRoles[strings.TrimLeft(strings.TrimSpace(r)[2:], "'")]
}

// entryRefs derives the password refs the gate passes to OmitValues
// from the snapshot alone, without the driver's word for which fields are
// passwords (K14, CRED-4): every entry field that shows a value, on its
// own line or in a child other than its placeholder, unless the value is
// the text typed[ref] the agent itself typed into that field. A line
// with an entry role that cannot be parsed gives every ref on it (fail
// closed); a field with no ref gives noRef.
func entryRefs(snapshot string, typed map[string]string) map[string]bool {
	refs := map[string]bool{}
	lines := strings.Split(snapshot, "\n")
	for i, line := range lines {
		if !isEntry(line) {
			continue
		}
		start, ok := nameEnd(line)
		if !ok {
			for _, m := range refToken.FindAllStringSubmatch(line, -1) {
				refs[m[1]] = true
			}
			continue
		}
		ref, at := noRef, start
		if m := refToken.FindStringSubmatchIndex(line[start:]); m != nil {
			ref, at = line[start+m[2]:start+m[3]], start+m[1]
		}
		rest := line[at:]
		rest = strings.TrimLeft(rest[len(attrsRE.FindString(rest)):], "'")
		var values []string
		if strings.HasPrefix(rest, ":") {
			values = append(values, rest[1:])
		}
		depth := len(indent(line))
		for _, c := range lines[i+1:] {
			if strings.TrimSpace(c) == "" || len(indent(c)) <= depth {
				break
			}
			if cm := childRE.FindStringSubmatch(c); cm == nil {
				values = append(values, c)
			} else if !strings.HasSuffix(cm[1], "- /placeholder") {
				values = append(values, cm[2])
			}
		}
		t, isTyped := typed[ref]
		for _, v := range values {
			if v = yamlValue(v); v != "" && (!isTyped || v != t) {
				refs[ref] = true
			}
		}
	}
	return refs
}

// scrubForms replaces every form in line outside its [ref=...] tokens, so
// a value never rewrites a ref the agent clicks by.
func scrubForms(line string, forms []string) string {
	var b strings.Builder
	at := 0
	for _, m := range refToken.FindAllStringIndex(line, -1) {
		b.WriteString(scrubText(line[at:m[0]], forms))
		b.WriteString(line[m[0]:m[1]])
		at = m[1]
	}
	b.WriteString(scrubText(line[at:], forms))
	return b.String()
}

func scrubText(s string, forms []string) string {
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, "\x00")
	}
	return strings.ReplaceAll(s, "\x00", omittedMark)
}

// valueForms are the ways a value can appear in another element's
// accessible name: as is, with whitespace collapsed, JSON-escaped inside
// a quoted name, and each of those with ' doubled, because a key that
// needs YAML quoting (a name holding ": ", for one) is single-quoted.
func valueForms(values []string) []string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	seen := map[string]bool{}
	var forms []string
	for _, v := range values {
		for _, d := range []string{v, yamlValue(v)} {
			c := strings.Join(strings.Fields(d), " ")
			for _, e := range []string{d, c, esc.Replace(d), esc.Replace(c)} {
				for _, f := range []string{e, strings.ReplaceAll(e, "'", "''")} {
					f = strings.TrimSpace(f)
					if len(f) >= minScrub && !strings.Contains(f, "\x00") && !seen[f] {
						seen[f] = true
						forms = append(forms, f)
					}
				}
			}
		}
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return forms
}

// OmitValues removes the value text of snapshot lines whose ref is in
// refs, and of the lines nested under them. The line stays, so a login
// form is still visible. Every other copy of a removed value is also
// replaced, because the accessible name of a row, cell, link or button
// holding the field, or labelled by it, includes the value, except
// inside [ref=...] tokens. A value shorter than minScrub is omitted only
// from its own field; a longer one can over-redact, which fails closed.
// refs are password fields (CRED-4).
func OmitValues(snapshot string, refs map[string]bool) string {
	return omitValues(snapshot, refs, nil)
}

// omitValues is OmitValues, except that the value of a field whose ref is
// in keep, on its line and in its children, is never scrubbed: it is the
// text the agent typed there, and blanking it when it matches a password
// would answer a guess (G10).
func omitValues(snapshot string, refs, keep map[string]bool) string {
	lines := strings.Split(snapshot, "\n")
	own := keptValues(lines, keep)
	var values []string
	for i := 0; i < len(lines); i++ {
		line, v, ok := omitLine(lines[i], refs)
		if !ok {
			continue
		}
		lines[i] = line
		values = append(values, v)
		depth := len(indent(line))
		for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" && len(indent(lines[i+1])) > depth {
			i++
			lines[i], v = omitChild(lines[i])
			values = append(values, v)
		}
	}
	forms := valueForms(values)
	if len(forms) == 0 {
		return strings.Join(lines, "\n")
	}
	for i, line := range lines {
		kept := strings.TrimSuffix(line, ": "+omittedMark)
		if at, ok := own[i]; ok {
			kept = line[:at]
		}
		lines[i] = scrubForms(kept, forms) + line[len(kept):]
	}
	return strings.Join(lines, "\n")
}

// keptValues maps the index of each line that holds the value of a field
// in keep to where that value starts: after the ref and attributes on the
// field's own line, and the whole of a child other than /placeholder.
func keptValues(lines []string, keep map[string]bool) map[int]int {
	own := map[int]int{}
	if len(keep) == 0 {
		return own
	}
	for i, line := range lines {
		start, ok := nameEnd(line)
		if !ok {
			continue
		}
		m := refToken.FindStringSubmatchIndex(line[start:])
		if m == nil || !keep[line[start+m[2]:start+m[3]]] {
			continue
		}
		at := start + m[1]
		own[i] = at + len(attrsRE.FindString(line[at:]))
		depth := len(indent(line))
		for j := i + 1; j < len(lines) && strings.TrimSpace(lines[j]) != "" && len(indent(lines[j])) > depth; j++ {
			if cm := childRE.FindStringSubmatch(lines[j]); cm == nil || !strings.HasSuffix(cm[1], "- /placeholder") {
				own[j] = 0
			}
		}
	}
	return own
}
