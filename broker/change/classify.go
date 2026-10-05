package change

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/route"
)

// classification is decided from paths and content alone (ARC-2: no
// inference), never from the candidate's claim about itself (CHG-6).
type classification struct {
	classes   []Class
	neutral   bool   // eligible for the CHG-6 standing grant
	forbidden string // non-empty: fails qualification
}

// classify decides what a set of edits is. Called with p.mu held.
func (p *Pipeline) classify(edits []Edit, src Source) classification {
	cl := classification{neutral: src == Local}
	seen := map[Class]bool{}
	for _, e := range edits {
		c := classOf(e.Path)
		if !seen[c] {
			seen[c] = true
			cl.classes = append(cl.classes, c)
		}
		switch c {
		case ClassAuthority:
			cl.forbid(fmt.Sprintf("changes %s, which no candidate may change (LOOP-10)", namespace(e.Path)))
		case ClassGovernance:
			cl.forbid(fmt.Sprintf("changes %s, which only an owner-approved intent changes (CHG-2)", namespace(e.Path)))
		case ClassUnknown:
			cl.forbid(fmt.Sprintf("changes %s, which is not a known namespace", namespace(e.Path)))
		case ClassProcedure, ClassSkill:
		case ClassRouting:
			p.checkRouting(&cl, e)
		case ClassContext:
			p.checkContext(&cl, e)
		default:
			cl.neutral = false // config and images are behavior changes (CHG-3)
		}
		if src == Shared && c != ClassProcedure && c != ClassSkill {
			cl.forbid("a shared package carries only procedures and skills (CHG-5)")
		}
	}
	sort.Slice(cl.classes, func(i, j int) bool { return cl.classes[i] < cl.classes[j] })
	return cl
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
	if d.More() {
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
	var next route.Rule
	if err := decodeStrict(e.After, &next); err != nil {
		cl.forbid("routing rule does not parse: " + err.Error())
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
	var cur route.Rule
	if e.Before == nil || json.Unmarshal(e.Before, &cur) != nil || len(cur) != len(next) {
		cl.neutral = false
		return
	}
	for class, routes := range next {
		have := map[route.Route]bool{}
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
