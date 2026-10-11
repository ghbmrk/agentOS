package change

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/routerule"
)

// classification is decided from paths and content alone (ARC-2: no
// inference), never from the candidate's claim about itself (CHG-6).
type classification struct {
	classes   []Class
	neutral   bool   // eligible for the CHG-6 standing grant
	forbidden string // non-empty: fails qualification
}

// classify decides what a set of edits is. Called with p.mu held.
func (p *Pipeline) classify(edits []Edit, base Tree, src Source) classification {
	cl := classification{neutral: src == Local}
	seen := map[Class]bool{}
	for _, e := range edits {
		c := classOf(e.Path)
		if why := loopKeyChange(e); why != "" {
			c = ClassAuthority
			cl.forbid(why)
		}
		if !seen[c] {
			seen[c] = true
			cl.classes = append(cl.classes, c)
		}
		switch c {
		case ClassAuthority:
			cl.forbid(fmt.Sprintf("changes %s, which no candidate may change (LOOP-10)", namespace(e.Path)))
		case ClassGovernance:
			if e.After == nil {
				cl.forbid(fmt.Sprintf("deletes from %s, which only an owner-approved intent changes (CHG-2)", namespace(e.Path)))
			}
			cl.forbid(fmt.Sprintf("changes %s, which only an owner-approved intent changes (CHG-2)", namespace(e.Path)))
		case ClassUnknown:
			cl.forbid(fmt.Sprintf("changes %s, which is not a known namespace", namespace(e.Path)))
		case ClassProcedure, ClassSkill:
			if id := newIdentifier(e.After, base); id != "" {
				// An address the box has never used is a new destination
				// in effect, so the owner sees it (Security, #34).
				cl.neutral = false
			}
		case ClassRouting:
			p.checkRouting(&cl, e)
		case ClassContext:
			p.checkContext(&cl, e)
			// Every text file a Loop 1 builder may write gets the same
			// check (C-3c-4 on W3 step 3c).
			if id := newIdentifier(e.After, base); id != "" {
				cl.neutral = false
			}
		default:
			cl.neutral = false // config and images are behavior changes (CHG-3)
		}
		image := c == ClassGuestImage || c == ClassHostImage
		switch {
		case src == Shared && c != ClassProcedure && c != ClassSkill:
			cl.forbid("a shared package carries only procedures and skills (CHG-5)")
		case src == Upstream && !image:
			cl.forbid("an upstream release changes only images (CHG-3)")
		case src != Upstream && image:
			cl.forbid("only a signed upstream release changes an image (UPD-8)")
		}
	}
	sort.Slice(cl.classes, func(i, j int) bool { return cl.classes[i] < cl.classes[j] })
	return cl
}

// loopKeyChange names the loop-governing key e changes (loopKeys), or ""
// when it changes none. A listed file deleted, or not a JSON object after
// the edit, changes every key it held.
func loopKeyChange(e Edit) string {
	keys, ok := loopKeys[e.Path]
	if !ok {
		return ""
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(e.Before, &before)
	if e.After == nil || json.Unmarshal(e.After, &after) != nil || after == nil {
		if e.Before == nil {
			return ""
		}
		return fmt.Sprintf("changes %s, which governs the loops; no candidate may (LOOP-10)", e.Path)
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		b, inB := before[k]
		a, inA := after[k]
		if inA != inB || (inA && !bytes.Equal(canonicalRaw(a), canonicalRaw(b))) {
			return fmt.Sprintf("sets %q in %s, which %s; no candidate may (LOOP-10)", k, e.Path, keys[k])
		}
	}
	return ""
}

func canonicalRaw(b json.RawMessage) []byte {
	v, err := decodeJSON(b)
	if err != nil {
		return b
	}
	return canonicalJSON(v)
}

// imagesOnly reports that every edit is to an image namespace.
func (cl *classification) imagesOnly() bool {
	for _, c := range cl.classes {
		if c != ClassGuestImage && c != ClassHostImage {
			return false
		}
	}
	return len(cl.classes) > 0
}

// identifier patterns: URLs, email addresses, and phone numbers in
// international or (NNN) NNN-NNNN form, so dates and times do not match.
var identifiers = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|\+\d[\d ().-]{7,}\d|\(\d{3}\) ?\d{3}-\d{4}`)

// newIdentifier returns the first external identifier in b that appears
// nowhere in the active tree, or "".
func newIdentifier(b []byte, base Tree) string {
	for _, m := range identifiers.FindAll(b, -1) {
		found := false
		for _, f := range base {
			if bytes.Contains(f, m) {
				found = true
				break
			}
		}
		if !found {
			return string(m)
		}
	}
	return ""
}

func (cl *classification) forbid(why string) {
	cl.neutral = false
	if cl.forbidden == "" {
		cl.forbidden = why
	}
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// checkRouting admits a routing rule as authority-neutral only if it keeps
// the same task classes and, within each, chooses among routes the active
// rule already has (ADP-4: routing never adds a route or a provider). A
// provider the owner has not granted fails outright (CAP-9).
func (p *Pipeline) checkRouting(cl *classification, e Edit) {
	if e.Path != RoutingPath {
		cl.forbid("routing has one file, " + RoutingPath)
		return
	}
	if e.After == nil {
		cl.forbid("the routing rule cannot be deleted")
		return
	}
	var next routerule.Rule
	if err := decodeStrict(e.After, &next); err != nil {
		cl.forbid("routing rule does not parse: " + err.Error())
		return
	}
	if len(next) == 0 {
		cl.forbid("a routing rule needs at least one task class")
		return
	}
	for class, routes := range next {
		if len(routes) == 0 {
			cl.forbid("routing class " + class + " has no routes")
			return
		}
		for _, rt := range routes {
			if p.cfg.RouteGranted == nil || !p.cfg.RouteGranted(rt.Provider) {
				cl.forbid("routing names provider " + rt.Provider + ", which the owner has not granted")
				return
			}
		}
	}
	var cur routerule.Rule
	if e.Before == nil || json.Unmarshal(e.Before, &cur) != nil || len(cur) != len(next) {
		cl.neutral = false
		return
	}
	for class, routes := range next {
		have := map[routerule.Route]bool{}
		for _, rt := range cur[class] {
			have[rt] = true
		}
		if len(have) == 0 {
			cl.neutral = false // a new task class is owner configuration
			return
		}
		for _, rt := range routes {
			if !have[rt] {
				cl.neutral = false // a new route is a behavior change
				return
			}
		}
	}
}

// checkContext admits a context rule as authority-neutral only if it
// selects among sources the machine already receives (CHG-6: a context
// rule never changes what data reaches which machine).
func (p *Pipeline) checkContext(cl *classification, e Edit) {
	name := strings.TrimPrefix(e.Path, "context/")
	machine, ok := strings.CutSuffix(name, ".json")
	if !ok || machine == "" || strings.Contains(machine, "/") {
		cl.forbid("a context rule is context/<machine>.json")
		return
	}
	if e.After == nil {
		cl.neutral = false
		return
	}
	var r ContextRule
	if err := decodeStrict(e.After, &r); err != nil {
		cl.forbid("context rule does not parse: " + err.Error())
		return
	}
	have := map[string]bool{}
	if p.cfg.Receives != nil {
		for _, s := range p.cfg.Receives(machine) {
			have[s] = true
		}
	}
	for _, s := range r.Select {
		if !have[s] {
			// That would change what data reaches the machine, which is
			// data flow (REV-5), not a context rule.
			cl.forbid("context rule for " + machine + " selects " + s + ", which that machine does not receive")
			return
		}
	}
}
