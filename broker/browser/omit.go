package browser

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const omittedMark = "[password omitted]"

// withheldMark replaces a snapshot in which an omitted value also shows
// outside its field and the field's ancestors: scrubbing that copy would
// tell the agent which text on the page equals a password (G10, #2245).
const withheldMark = "[snapshot withheld: a password field's value also shows elsewhere on the page (CRED-4)]"

// minScrub is the shortest value that withholds a snapshot when it shows
// outside its field: a shorter one ("1", "yes") would match ordinary text.
// It is still omitted from its own field and scrubbed from the field's
// ancestors (G10).
const minScrub = 4

// entryRoles are the roles an <input> or <textarea> that can hold a
// password is given, including the spinbutton a page can assign to one
// (G10, #2245). combobox stays out: omitting a select's options breaks
// select (K14).
var entryRoles = map[string]bool{"textbox": true, "searchbox": true, "spinbutton": true}

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

// ownRef returns the element's own ref on a line whose name ends at start:
// a [ref=...] in the attribute run right after the name, never one inside
// the value, which is page-controlled (#2245). at is just past that ref, or
// start when the element has none.
func ownRef(line string, start int) (ref string, at int) {
	attrs := attrsRE.FindString(line[start:])
	m := refToken.FindStringSubmatchIndex(attrs)
	if m == nil {
		return noRef, start
	}
	return attrs[m[2]:m[3]], start + m[1]
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
	ref, end := ownRef(line, start)
	switch {
	case ref != noRef && refs[ref]:
	case ref == noRef && refs[noRef] && isEntry(line):
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

// role returns the role of a node line, or "" for a line that is not one.
func role(line string) string {
	r := roleRE.FindString(line)
	if r == "" {
		return ""
	}
	return strings.TrimLeft(strings.TrimSpace(r)[2:], "'")
}

// isEntry reports whether line is a node with one of entryRoles.
func isEntry(line string) bool {
	return entryRoles[role(line)]
}

// childValue returns the text a line nested under an entry field shows as
// the field's value: a `- text:` child, a property other than
// /placeholder, or a line that is not a node at all (fail closed). A node
// with another role, such as a rich-text editor's paragraph, is the
// field's structure, not its value (#2245).
func childValue(c string) (string, bool) {
	if m := childRE.FindStringSubmatch(c); m != nil {
		switch key := strings.TrimSpace(m[1])[2:]; {
		case key == "/placeholder":
			return "", false
		case key == "text", strings.HasPrefix(key, "/"):
			return m[2], true
		}
		return "", false
	}
	if r := role(c); r != "" && r != "text" {
		return "", false
	}
	return c, true
}

// entryRefs derives the password refs the gate passes to OmitValues
// from the snapshot alone, without the driver's word for which fields are
// passwords (K14, CRED-4): every entry field that shows a value, on its
// own line or in a childValue, unless the value is the text typed[ref]
// the agent itself typed into that field. A line with an entry role that
// cannot be parsed gives every ref on it (fail closed); a field with no
// ref gives noRef. stale holds each typed ref whose field now shows
// anything but the typed text, an empty field included, so the gate
// forgets it before the page can fill that field again (#2245).
func entryRefs(snapshot string, typed map[string]string) (refs, stale map[string]bool) {
	refs, stale = map[string]bool{}, map[string]bool{}
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
		ref, at := ownRef(line, start)
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
			if v, ok := childValue(c); ok {
				values = append(values, v)
			}
		}
		t, isTyped := typed[ref]
		shown := false
		for _, v := range values {
			if v = yamlValue(v); v != "" {
				shown = true
				if !isTyped || v != t {
					refs[ref] = true
				}
			}
		}
		if isTyped && ref != noRef && (refs[ref] || (!shown && t != "")) {
			stale[ref] = true
		}
	}
	return refs, stale
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
// needs YAML quoting (a name holding ": ", for one) is single-quoted. The
// text between [ref=...] tokens in a value counts on its own, because a
// ref is never scrubbed (#2245). Forms shorter than min are left out.
func valueForms(values []string, min int) []string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	seen := map[string]bool{}
	var forms []string
	for _, v := range values {
		var ds []string
		for _, d := range []string{v, yamlValue(v)} {
			ds = append(append(ds, d), refToken.Split(d, -1)...)
		}
		for _, d := range ds {
			c := strings.Join(strings.Fields(d), " ")
			for _, e := range []string{d, c, esc.Replace(d), esc.Replace(c)} {
				for _, f := range []string{e, strings.ReplaceAll(e, "'", "''")} {
					f = strings.TrimSpace(f)
					if f != "" && len(f) >= min && !strings.Contains(f, "\x00") && !seen[f] {
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

// containsForm reports whether s shows one of forms outside its
// [ref=...] tokens and omission marks.
func containsForm(s string, forms []string) bool {
	for _, part := range refToken.Split(s, -1) {
		part = strings.ReplaceAll(part, omittedMark, "\x00")
		for _, f := range forms {
			if strings.Contains(part, f) {
				return true
			}
		}
	}
	return false
}

// ancestors returns the indexes of the lines that hold line i: each line
// above it indented less than the one below it on the path.
func ancestors(lines []string, i int) []int {
	var up []int
	d := len(indent(lines[i]))
	for k := i - 1; k >= 0 && d > 0; k-- {
		if n := len(indent(lines[k])); strings.TrimSpace(lines[k]) != "" && n < d {
			up = append(up, k)
			d = n
		}
	}
	return up
}

// OmitValues removes the value text of snapshot lines whose ref is in
// refs, and of the lines nested under them. The line stays, so a login
// form is still visible. A row, cell, link or button holding the field
// carries the value in its accessible name, so each copy in the field's
// own lines and its ancestors is replaced, except inside [ref=...]
// tokens. A copy of minScrub or more characters anywhere else (an element
// labelled by the field, a heading that echoes it) withholds the whole
// snapshot: replacing it would tell the agent which text equals the
// value. refs are password fields (CRED-4, #2245).
func OmitValues(snapshot string, refs map[string]bool) string {
	return omitValues(snapshot, refs, nil, nil)
}

// omitValues is OmitValues, except that the value of a field whose ref is
// in keep, on its line and in its children, is never scrubbed nor counted
// as a copy: it is the text the agent typed there, and treating it
// differently when it matches a password would answer a guess (G10). said
// is the text the agent put on pages (typed, or in a URL it navigated to).
// Once any field is omitted, the page's echo of it is handled whether or
// not it matches a value, for the same reason: on an omitted field's own
// lines and ancestors it is scrubbed like the field's value, and a copy of
// minScrub or more characters on any other line, a kept field's value
// aside, withholds the snapshot (#2245, PR #2273 reviews).
func omitValues(snapshot string, refs, keep map[string]bool, said []string) string {
	lines := strings.Split(snapshot, "\n")
	own := keptValues(lines, keep)
	type field struct {
		lines  []int // the field's own lines and its ancestors
		values []string
	}
	var fields []field
	for i := 0; i < len(lines); i++ {
		line, v, ok := omitLine(lines[i], refs)
		if !ok {
			continue
		}
		lines[i] = line
		f := field{lines: append(ancestors(lines, i), i), values: []string{v}}
		depth := len(indent(line))
		for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" && len(indent(lines[i+1])) > depth {
			i++
			lines[i], v = omitChild(lines[i])
			f.lines = append(f.lines, i)
			f.values = append(f.values, v)
		}
		fields = append(fields, f)
	}
	// end is where the part of line j that can show a copy ends: before a
	// kept value or the mark that replaced an omitted one.
	end := func(j int) int {
		e := len(strings.TrimSuffix(lines[j], ": "+omittedMark))
		if at, ok := own[j]; ok && at < e {
			e = at
		}
		return e
	}
	if len(fields) == 0 {
		return strings.Join(lines, "\n")
	}
	near := map[int]bool{}
	for _, f := range fields {
		for _, j := range f.lines {
			near[j] = true
		}
	}
	if far := valueForms(said, minScrub); len(far) > 0 {
		for j := range lines {
			if !near[j] && containsForm(lines[j][:end(j)], far) {
				return withheldMark
			}
		}
	}
	scrub := map[int][]string{}
	for _, f := range fields {
		near := map[int]bool{}
		forms := valueForms(append(f.values, said...), 1)
		for _, j := range f.lines {
			near[j] = true
			scrub[j] = append(scrub[j], forms...)
		}
		far := valueForms(f.values, minScrub)
		for j := range lines {
			if !near[j] && len(far) > 0 && containsForm(lines[j][:end(j)], far) {
				return withheldMark
			}
		}
	}
	for j, forms := range scrub {
		sort.Slice(forms, func(a, b int) bool { return len(forms[a]) > len(forms[b]) })
		e := end(j)
		from := min(len(roleRE.FindString(lines[j])), e)
		lines[j] = lines[j][:from] + scrubForms(lines[j][from:e], forms) + lines[j][e:]
	}
	return strings.Join(lines, "\n")
}

// keptValues maps the index of each line that holds the value of an
// entry field in keep to where that value starts: after the ref and
// attributes on the field's own line, and the whole of a child other
// than /placeholder. A typed node with another role keeps nothing.
func keptValues(lines []string, keep map[string]bool) map[int]int {
	own := map[int]int{}
	if len(keep) == 0 {
		return own
	}
	for i, line := range lines {
		start, ok := nameEnd(line)
		if !ok || !isEntry(line) {
			continue
		}
		ref, at := ownRef(line, start)
		if ref == noRef || !keep[ref] {
			continue
		}
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
