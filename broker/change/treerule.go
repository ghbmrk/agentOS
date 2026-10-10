package change

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// A tree rule is a security test in a closed, deterministic form (P3-4b):
// clauses over tree files, each a JSON Pointer target checked by one of a
// fixed set of ops. It passes iff every clause holds; the empty set
// passes. It reads only the tree, with no model and no inference (ARC-2),
// so the evaluator answers it without a machine (AnswerTreeRule).

// TreeRule is a tree-rule test. Its encoding is {"tree_rule": [clauses]}.
type TreeRule struct {
	Clauses []Clause `json:"tree_rule"`
}

// Clause is one condition on a tree file. Pointer is an RFC 6901 JSON
// Pointer into the file's JSON; empty is the whole document.
type Clause struct {
	Path    string          `json:"path"`
	Pointer string          `json:"pointer,omitempty"`
	Op      string          `json:"op"`
	Value   json.RawMessage `json:"value,omitempty"`
}

// The ops, a closed set: no other op exists.
const (
	OpEq     = "eq"     // the target equals Value as canonical JSON
	OpAbsent = "absent" // the target is missing
	OpSubset = "subset" // both arrays, every target element in Value
	OpLe     = "le"     // both numbers, the target at most Value
)

// TreeRuleOK is the evaluator's output for a tree rule that holds, and the
// Expect of every tree-rule case; TreeRuleFail is its output otherwise.
const (
	TreeRuleOK   = "ok"
	TreeRuleFail = "fail"
)

// ErrInvalidTreeRule: a tree rule with an unknown op, a bad path, pointer
// or value. It is rejected when added, never counted as passing.
var ErrInvalidTreeRule = errors.New("change: invalid tree rule")

// ParseTreeRule reads b as a tree rule. ok is false when b is not one (no
// "tree_rule" key at the top); err is set when it is one but invalid.
func ParseTreeRule(b []byte) (r TreeRule, ok bool, err error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil {
		return TreeRule{}, false, nil
	}
	raw, ok := top["tree_rule"]
	if !ok {
		return TreeRule{}, false, nil
	}
	if len(top) != 1 {
		return TreeRule{}, true, fmt.Errorf("%w: keys besides tree_rule", ErrInvalidTreeRule)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r.Clauses); err != nil {
		return TreeRule{}, true, fmt.Errorf("%w: %v", ErrInvalidTreeRule, err)
	}
	return r, true, r.Valid()
}

// Encode is r's canonical bytes, the input of its case.
func (r TreeRule) Encode() []byte {
	if r.Clauses == nil {
		r.Clauses = []Clause{}
	}
	b, _ := json.Marshal(r)
	return b
}

// Valid checks every clause's form.
func (r TreeRule) Valid() error {
	for i, c := range r.Clauses {
		if err := c.valid(); err != nil {
			return fmt.Errorf("%w: clause %d: %v", ErrInvalidTreeRule, i, err)
		}
	}
	return nil
}

func (c Clause) valid() error {
	if err := cleanPath(c.Path); err != nil {
		return err
	}
	if c.Pointer != "" && !strings.HasPrefix(c.Pointer, "/") {
		return errors.New("pointer must be empty or start with /")
	}
	switch c.Op {
	case OpAbsent:
		if len(c.Value) != 0 {
			return errors.New("absent takes no value")
		}
	case OpEq, OpSubset, OpLe:
		if len(c.Value) == 0 || !json.Valid(c.Value) {
			return fmt.Errorf("%s needs a JSON value", c.Op)
		}
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	return nil
}

// Holds reports whether every clause holds on t. An invalid clause never
// holds.
func (r TreeRule) Holds(t Tree) bool {
	for _, c := range r.Clauses {
		if !c.holds(t) {
			return false
		}
	}
	return true
}

func (c Clause) holds(t Tree) bool {
	if c.valid() != nil {
		return false
	}
	b, ok := t[c.Path]
	if !ok {
		return c.Op == OpAbsent
	}
	doc, err := decodeJSON(b)
	if err != nil {
		// Not JSON: every clause on it fails, except absent on the whole
		// document, which fails because the file is there.
		return false
	}
	v, found := resolve(doc, c.Pointer)
	if !found || c.Op == OpAbsent {
		return !found && c.Op == OpAbsent
	}
	want, err := decodeJSON(c.Value)
	if err != nil {
		return false
	}
	switch c.Op {
	case OpEq:
		return bytes.Equal(canonicalJSON(v), canonicalJSON(want))
	case OpSubset:
		got, ok1 := v.([]any)
		set, ok2 := want.([]any)
		if !ok1 || !ok2 {
			return false
		}
		in := map[string]bool{}
		for _, e := range set {
			in[string(canonicalJSON(e))] = true
		}
		for _, e := range got {
			if !in[string(canonicalJSON(e))] {
				return false
			}
		}
		return true
	case OpLe:
		a, ok1 := v.(json.Number)
		b, ok2 := want.(json.Number)
		if !ok1 || !ok2 {
			return false
		}
		x, ok1 := new(big.Rat).SetString(string(a))
		y, ok2 := new(big.Rat).SetString(string(b))
		return ok1 && ok2 && x.Cmp(y) <= 0
	}
	return false
}

// decodeJSON reads one JSON value, numbers kept exact.
func decodeJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// resolve follows an RFC 6901 pointer.
func resolve(doc any, ptr string) (any, bool) {
	if ptr == "" {
		return doc, true
	}
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch n := doc.(type) {
		case map[string]any:
			v, ok := n[tok]
			if !ok {
				return nil, false
			}
			doc = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(n) || strconv.Itoa(i) != tok {
				return nil, false
			}
			doc = n[i]
		default:
			return nil, false
		}
	}
	return doc, true
}

// Minimize reduces a rule that fails on t to a 1-minimal clause set, by
// removing one clause at a time: the result still fails on t, and
// dropping any clause left makes it pass. A rule that holds on t is
// returned as it is.
func (r TreeRule) Minimize(t Tree) TreeRule {
	if r.Holds(t) {
		return r
	}
	cs := append([]Clause{}, r.Clauses...)
	for i := 0; i < len(cs); {
		less := TreeRule{Clauses: append(append([]Clause{}, cs[:i]...), cs[i+1:]...)}
		if !less.Holds(t) {
			cs = less.Clauses
			continue
		}
		i++
	}
	return TreeRule{Clauses: cs}
}

// Namespaces are the namespaces r's clauses read.
func (r TreeRule) Namespaces() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range r.Clauses {
		if ns := namespace(c.Path); !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	return out
}

// AnswerTreeRule is the evaluator's hook for tree-rule probes: it answers
// one from t alone, TreeRuleOK when it holds. ok is false when input is
// not a tree rule; an invalid one is answered TreeRuleFail.
func AnswerTreeRule(t Tree, input []byte) (out []byte, ok bool) {
	r, ok, err := ParseTreeRule(input)
	if !ok {
		return nil, false
	}
	if err != nil || !r.Holds(t) {
		return []byte(TreeRuleFail), true
	}
	return []byte(TreeRuleOK), true
}
