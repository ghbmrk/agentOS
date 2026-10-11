package browser

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const omittedMark = "[password omitted]"

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
	if m == nil || !refs[line[start+m[2]:start+m[3]]] {
		return line, "", false
	}
	end := start + m[1]
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
					if f != "" && !strings.Contains(f, "\x00") && !seen[f] {
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
// holding the field, or labelled by it, includes the value. A short
// value can over-redact, which fails closed. refs are password fields
// (CRED-4).
func OmitValues(snapshot string, refs map[string]bool) string {
	lines := strings.Split(snapshot, "\n")
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
		for _, f := range forms {
			kept = strings.ReplaceAll(kept, f, "\x00")
		}
		kept = strings.ReplaceAll(kept, "\x00", omittedMark)
		lines[i] = kept + line[len(strings.TrimSuffix(line, ": "+omittedMark)):]
	}
	return strings.Join(lines, "\n")
}
