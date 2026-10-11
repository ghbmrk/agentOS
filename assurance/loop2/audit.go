package main

// The fix-input audit: the fixer is reached only through adapter, which
// records every byte it hands over. A run fails if the record holds a
// held-back clause (as JSON in any layout), or a field of one, that the
// visible test does not.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
)

// adapter stands between Loop 2 and the scripted fixer. It gets only the
// Finding, as the Fixer interface gives it. leak, set only by the
// leaking-adapter control, is appended to the finding it passes on.
type adapter struct {
	inner loops.Fixer
	leak  []byte
	rec   bytes.Buffer
	calls int
}

func (a *adapter) Fix(ctx context.Context, f loops.Finding) (change.Candidate, error) {
	if a.leak != nil {
		f.Detail += " " + string(a.leak)
	}
	a.calls++
	record(&a.rec, reflect.ValueOf(f))
	return a.inner.Fix(ctx, f)
}

// record appends every string and byte field of v, NUL-separated.
func record(w *bytes.Buffer, v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		w.WriteString(v.String())
		w.WriteByte(0)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			w.Write(v.Bytes())
			w.WriteByte(0)
			return
		}
		for i := 0; i < v.Len(); i++ {
			record(w, v.Index(i))
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			record(w, v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			record(w, v.Field(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			record(w, k)
			record(w, v.MapIndex(k))
		}
	default:
		fmt.Fprint(w, v.Interface())
		w.WriteByte(0)
	}
}

type script struct {
	cands []change.Candidate
	n     int
}

func (s *script) Fix(context.Context, loops.Finding) (change.Candidate, error) {
	if s.n >= len(s.cands) {
		return change.Candidate{}, fmt.Errorf("the script has no candidate left")
	}
	s.n++
	return s.cands[s.n-1], nil
}

type auditReport struct {
	Clean bool     `json:"clean"`
	Bytes int      `json:"bytes"`
	Calls int      `json:"calls"`
	Hits  []string `json:"hits"`
}

// canon is v as canonical JSON: decoded and re-encoded, keys sorted, no
// HTML escaping.
func canon(v []byte) string {
	var x any
	d := json.NewDecoder(bytes.NewReader(v))
	d.UseNumber()
	if d.Decode(&x) != nil {
		return string(v)
	}
	return marshal(x)
}

func marshal(x any) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(x)
	return string(bytes.TrimRight(b.Bytes(), "\n"))
}

// forms are the ways a value can appear in the record: canonical JSON,
// and for a string also its bare text.
func forms(canonical string) []string {
	out := []string{canonical}
	var s string
	if json.Unmarshal([]byte(canonical), &s) == nil && s != "" {
		out = append(out, s)
	}
	return out
}

// containsToken finds needle in hay. A needle that is not a JSON string,
// array or object must stand alone: no letter, digit, '.', '-' or '+'
// next to it, so 20 does not match inside 1a20f or 2.205.
func containsToken(hay []byte, needle string) bool {
	if needle == "" {
		return false
	}
	n := []byte(needle)
	if c := n[0]; c == '"' || c == '[' || c == '{' {
		return bytes.Contains(hay, n)
	}
	inWord := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '+'
	}
	for i := 0; ; {
		j := bytes.Index(hay[i:], n)
		if j < 0 {
			return false
		}
		at := i + j
		end := at + len(n)
		if (at == 0 || !inWord(hay[at-1]) || !inWord(n[0])) && (end == len(hay) || !inWord(hay[end]) || !inWord(n[len(n)-1])) {
			return true
		}
		i = at + 1
	}
}

func clauseForms(c change.Clause) []string {
	m := map[string]any{"path": c.Path, "op": c.Op}
	if c.Pointer != "" {
		m["pointer"] = c.Pointer
	}
	if len(c.Value) > 0 {
		m["value"] = json.RawMessage(canon(c.Value))
	}
	sorted := marshal(m)
	c.Value = json.RawMessage(canon(c.Value))
	if len(c.Value) == 0 {
		c.Value = nil
	}
	return []string{marshal(c), sorted}
}

// clauseFields are c's path, pointer and value, as canonical JSON.
func clauseFields(c change.Clause) []string {
	out := []string{marshal(c.Path)}
	if c.Pointer != "" {
		out = append(out, marshal(c.Pointer))
	}
	if len(c.Value) > 0 {
		out = append(out, canon(c.Value))
	}
	return out
}

// shares is what the visible test gives away anyway: its whole clauses,
// in each form clauseForms gives, and each of their fields.
func shares(visible change.TreeRule) (clauses, fields map[string]bool) {
	clauses, fields = map[string]bool{}, map[string]bool{}
	for _, c := range visible.Clauses {
		for _, f := range clauseForms(c) {
			clauses[f] = true
		}
		for _, f := range clauseFields(c) {
			fields[f] = true
		}
	}
	return clauses, fields
}

// fieldless lists the clauses of held that the visible test does not share
// whole but whose every field it has. The field audit could not tell such
// a clause from the visible test, so validate refuses it.
func fieldless(visible, held change.TreeRule) []string {
	clauses, fields := shares(visible)
	var out []string
	for _, c := range held.Clauses {
		cf := clauseForms(c)
		if clauses[cf[0]] || clauses[cf[1]] {
			continue
		}
		if !slices.ContainsFunc(clauseFields(c), func(f string) bool { return !fields[f] }) {
			out = append(out, cf[1])
		}
	}
	return out
}

// clausesIn is the sorted form (clauseForms) of every JSON object in rec
// that decodes as a clause, whatever its whitespace and key order, so a
// raw held file is matched as well as a canonical one.
func clausesIn(rec []byte) map[string]bool {
	out := map[string]bool{}
	for i, b := range rec {
		if b != '{' {
			continue
		}
		var raw json.RawMessage
		if json.NewDecoder(bytes.NewReader(rec[i:])).Decode(&raw) != nil {
			continue
		}
		var c change.Clause
		if json.Unmarshal(raw, &c) != nil || c.Path == "" || c.Op == "" {
			continue
		}
		out[clauseForms(c)[1]] = true
	}
	return out
}

// audit checks the record against every held-back clause the visible test
// does not share.
func audit(rec []byte, calls, want int, visible change.TreeRule, held map[string][]byte) auditReport {
	r := auditReport{Bytes: len(rec), Calls: calls, Hits: []string{}}
	if calls != want {
		r.Hits = append(r.Hits, fmt.Sprintf("the fixer was called %d times, not %d", calls, want))
	}
	shared, fields := shares(visible)
	inRec := clausesIn(rec)
	for _, name := range sortedKeys(held) {
		h, err := parseRule(held[name])
		if err != nil {
			r.Hits = append(r.Hits, fmt.Sprintf("held/%s.json: %v", name, err))
			continue
		}
		for _, c := range h.Clauses {
			cf := clauseForms(c)
			if shared[cf[0]] || shared[cf[1]] {
				continue
			}
			if inRec[cf[1]] {
				r.Hits = append(r.Hits, fmt.Sprintf("held/%s: whole clause %s", name, cf[1]))
			}
			for _, f := range clauseFields(c) {
				if fields[f] {
					continue
				}
				for _, form := range forms(f) {
					if containsToken(rec, form) {
						r.Hits = append(r.Hits, fmt.Sprintf("held/%s: field %s", name, form))
						break
					}
				}
			}
		}
	}
	r.Clean = len(r.Hits) == 0
	return r
}
