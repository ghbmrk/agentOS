package browser

import (
	"regexp"
	"strings"
)

var (
	refToken = regexp.MustCompile(`\[ref=((?:f[0-9]+)?e[0-9]+)\]`)
	roleRE   = regexp.MustCompile(`^[ \t]*- '?[A-Za-z][A-Za-z-]*`)
	attrsRE  = regexp.MustCompile(`^(?: \[[^\]]*\])*`)
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

// omitUnparsed handles a line that cannot be parsed, so the element's
// own ref cannot be told from a decoy. If any ref on the line is a
// password field, everything after the role is replaced (fail closed).
func omitUnparsed(line string, refs map[string]bool) string {
	for _, m := range refToken.FindAllStringSubmatch(line, -1) {
		if !refs[m[1]] {
			continue
		}
		head := line[:len(line)-len(strings.TrimLeft(line, " \t"))] + "- "
		if r := roleRE.FindString(line); r != "" {
			head = strings.Replace(r, "- '", "- ", 1) + " "
		}
		return head + m[0] + ": [password omitted]"
	}
	return line
}

// OmitValues removes the value text of snapshot lines whose ref is in
// refs. The line stays, so a login form is still visible. refs are
// password fields (CRED-4).
func OmitValues(snapshot string, refs map[string]bool) string {
	lines := strings.Split(snapshot, "\n")
	for i, line := range lines {
		start, ok := nameEnd(line)
		if !ok {
			lines[i] = omitUnparsed(line, refs)
			continue
		}
		m := refToken.FindStringSubmatchIndex(line[start:])
		if m == nil {
			continue
		}
		for j := range m {
			m[j] += start
		}
		if !refs[line[m[2]:m[3]]] {
			continue
		}
		rest := line[m[1]:]
		attr := attrsRE.FindString(rest)
		head := strings.Replace(line[:m[1]]+attr, "- '", "- ", 1)
		tail := strings.TrimLeft(rest[len(attr):], "'")
		switch {
		case strings.HasPrefix(tail, ":") && strings.TrimSpace(tail[1:]) != "":
			lines[i] = head + ": [password omitted]"
		case strings.HasPrefix(tail, ":"):
			lines[i] = head + ":"
		default:
			lines[i] = head
		}
	}
	return strings.Join(lines, "\n")
}
