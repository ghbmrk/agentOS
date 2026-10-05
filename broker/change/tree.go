package change

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Tree is the managed state: file path to content. Every adoptable change
// is a change to this tree, so one diff rule classifies all of them.
type Tree map[string][]byte

// Hash is a stable digest of the whole tree.
func (t Tree) Hash() string {
	h := sha256.New()
	for _, p := range t.paths() {
		fmt.Fprintf(h, "%d:%s%d:", len(p), p, len(t[p]))
		h.Write(t[p])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (t Tree) paths() []string {
	ps := make([]string, 0, len(t))
	for p := range t {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func (t Tree) clone() Tree {
	out := Tree{}
	for p, b := range t {
		out[p] = append([]byte(nil), b...)
	}
	return out
}

// under returns the files in namespace ns.
func (t Tree) under(ns string) Tree {
	out := Tree{}
	for p, b := range t {
		if namespace(p) == ns {
			out[p] = append([]byte(nil), b...)
		}
	}
	return out
}

// Edit is one changed path: its content before and after. A nil side means
// the file is absent.
type Edit struct {
	Path   string `json:"path"`
	Before []byte `json:"before,omitempty"`
	After  []byte `json:"after,omitempty"`
}

// diff computes the edits that turn base into next, sorted by path. Files
// with identical content are not edits.
func diff(base, next Tree) []Edit {
	seen := map[string]bool{}
	var out []Edit
	for _, p := range append(base.paths(), next.paths()...) {
		if seen[p] {
			continue
		}
		seen[p] = true
		b, inB := base[p]
		n, inN := next[p]
		if inB == inN && bytes.Equal(b, n) {
			continue
		}
		e := Edit{Path: p}
		if inB {
			e.Before = append([]byte{}, b...)
		}
		if inN {
			e.After = append([]byte{}, n...)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// cleanPath accepts only relative, normalized paths with a namespace and a
// name, so no path can alias another.
func cleanPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || !strings.Contains(p, "/") ||
		strings.HasPrefix(p, "../") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("change: bad path %q", p)
	}
	return nil
}

func namespace(p string) string {
	ns, _, _ := strings.Cut(p, "/")
	return ns
}

// Class is what a changed path is, decided from its namespace alone.
type Class string

const (
	// Authority-neutral classes (CHG-6), subject to the content checks in
	// classify for routing and context.
	ClassProcedure Class = "procedure"
	ClassSkill     Class = "skill"
	ClassRouting   Class = "routing"
	ClassContext   Class = "context"
	// Behavior changes that need the owner or a standing grant (CHG-3).
	ClassConfig     Class = "config"
	ClassGuestImage Class = "guest-image"
	ClassHostImage  Class = "host-image"
	// Changes no candidate may carry (LOOP-10, CHG-2): authority and the
	// pipeline's own evaluation and policy.
	ClassAuthority  Class = "authority"
	ClassGovernance Class = "governance"
	ClassUnknown    Class = "unknown"
	// ClassTask is a case class, never a path's: an owner outcome on a
	// whole task (Loop 1's harvest). It is evidence for every change to
	// how tasks are done, so it is relevant to each class in taskClasses.
	ClassTask Class = "task"
)

// taskClasses are the change classes a ClassTask case is relevant to.
var taskClasses = map[Class]bool{
	ClassProcedure: true, ClassSkill: true, ClassRouting: true, ClassContext: true, ClassConfig: true,
}

// namespaces maps a path's first segment to its class. A namespace not
// listed is ClassUnknown, which fails qualification.
var namespaces = map[string]Class{
	"procedures":  ClassProcedure,
	"skills":      ClassSkill,
	"routing":     ClassRouting,
	"context":     ClassContext,
	"config":      ClassConfig,
	"guest-image": ClassGuestImage,
	"host-image":  ClassHostImage,
	// What an agent may do, with what, and where data goes.
	"grants":   ClassAuthority,
	"verbs":    ClassAuthority,
	"custody":  ClassAuthority,
	"checks":   ClassAuthority,
	"egress":   ClassAuthority,
	"dataflow": ClassAuthority,
	"labels":   ClassAuthority,
	// The pipeline's own suites, graders, policy, and budgets.
	"suites":   ClassGovernance,
	"graders":  ClassGovernance,
	"policy":   ClassGovernance,
	"security": ClassGovernance,
	"budget":   ClassGovernance,
}

func classOf(p string) Class {
	if c, ok := namespaces[namespace(p)]; ok {
		return c
	}
	return ClassUnknown
}

// RoutingPath is the one file that holds the model router's rule (ADP-4).
const RoutingPath = "routing/rule.json"

// ContextRule selects and orders data a machine already receives. Its file
// is context/<machine>.json.
type ContextRule struct {
	Select []string `json:"select"`
}

func canonicalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
