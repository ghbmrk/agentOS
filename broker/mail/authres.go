package mail

import "strings"

// authResult is one result of an Authentication-Results header (RFC 8601
// §2.2): a method, its result, and its properties ("header.from").
type authResult struct {
	Method, Result string
	Props          map[string]string
}

// parseAuthResults reads an Authentication-Results value per RFC 8601:
// comments are removed first and quoted strings kept whole, so neither a
// "dmarc=pass" inside a comment nor a ";" inside a quoted string is read
// as a result. It returns the authserv-id and the results.
func parseAuthResults(v string) (string, []authResult) {
	parts := splitOutsideQuotes(stripComments(v), ';')
	if len(parts) == 0 {
		return "", nil
	}
	head := fields(parts[0])
	if len(head) == 0 {
		return "", nil
	}
	id := unquote(head[0])
	var out []authResult
	for _, p := range parts[1:] {
		f := fields(p)
		if len(f) == 0 {
			continue
		}
		method, result, ok := strings.Cut(f[0], "=")
		if !ok || method == "" || result == "" {
			continue
		}
		if i := strings.IndexByte(method, '/'); i >= 0 {
			method = method[:i]
		}
		r := authResult{Method: strings.ToLower(method), Result: strings.ToLower(unquote(result)), Props: map[string]string{}}
		for _, kv := range f[1:] {
			k, val, ok := strings.Cut(kv, "=")
			if !ok || !strings.Contains(k, ".") {
				continue // reason= and anything malformed
			}
			k = strings.ToLower(k)
			if _, dup := r.Props[k]; !dup {
				r.Props[k] = unquote(val)
			}
		}
		out = append(out, r)
	}
	return id, out
}

// stripComments replaces every comment (nested parentheses, with
// backslash escapes) outside a quoted string by a space.
func stripComments(s string) string {
	var b strings.Builder
	depth, quoted, esc := 0, false, false
	for _, c := range s {
		switch {
		case esc:
			esc = false
			if depth == 0 {
				b.WriteRune(c)
			}
			continue
		case c == '\\' && (quoted || depth > 0):
			esc = true
			if depth == 0 {
				b.WriteRune(c)
			}
			continue
		case quoted:
			if c == '"' {
				quoted = false
			}
		case c == '(':
			depth++
			continue
		case c == ')' && depth > 0:
			depth--
			if depth == 0 {
				b.WriteByte(' ')
			}
			continue
		case depth > 0:
			continue
		case c == '"':
			quoted = true
		}
		b.WriteRune(c)
	}
	return b.String()
}

// splitOutsideQuotes splits s at sep where sep is not in a quoted string.
func splitOutsideQuotes(s string, sep rune) []string {
	var out []string
	var b strings.Builder
	quoted, esc := false, false
	for _, c := range s {
		switch {
		case esc:
			esc = false
		case c == '\\' && quoted:
			esc = true
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(c)
	}
	return append(out, b.String())
}

// fields splits a comment-free resinfo into tokens at whitespace outside
// quoted strings, joining "a = b" into "a=b" (RFC 8601 allows CFWS around
// the "=").
func fields(s string) []string {
	var toks []string
	var b strings.Builder
	quoted, esc := false, false
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for _, c := range s {
		switch {
		case esc:
			esc = false
		case c == '\\' && quoted:
			esc = true
		case c == '"':
			quoted = !quoted
		case !quoted && (c == ' ' || c == '\t' || c == '\r' || c == '\n'):
			flush()
			continue
		}
		b.WriteRune(c)
	}
	flush()
	var out []string
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t == "=" && len(out) > 0 && i+1 < len(toks):
			out[len(out)-1] += "=" + toks[i+1]
			i++
		case strings.HasSuffix(t, "=") && !strings.HasPrefix(t, `"`) && i+1 < len(toks):
			out = append(out, t+toks[i+1])
			i++
		case strings.HasPrefix(t, "=") && len(out) > 0:
			out[len(out)-1] += t
		default:
			out = append(out, t)
		}
	}
	return out
}

// unquote removes a quoted string's quotes and escapes.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	var b strings.Builder
	esc := false
	for _, c := range s[1 : len(s)-1] {
		if !esc && c == '\\' {
			esc = true
			continue
		}
		esc = false
		b.WriteRune(c)
	}
	return b.String()
}
