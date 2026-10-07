// Package deadcap formats OP-9 "no silent loss of capability" lines.
package deadcap

import "fmt"

// Kind is a closed set of why a capability is off.
type Kind string

const (
	Host     Kind = "host"     // memory, hardware
	Config   Kind = "config"   // missing image or grant
	Held     Kind = "held"     // security fix not installed, provider refuse
	OwnerOpt Kind = "owner"    // LOOPS OFF, PINNED — named once, then digest only
)

// Cap is one dead or held capability.
type Cap struct {
	Name   string // owner words, e.g. "Learning"
	Kind   Kind
	Fix    string // what would fix it
	Sticky bool   // true: every digest while it lasts (not owner-opt)
}

// StatusLine is one STATUS line (OP-9).
func StatusLine(c Cap) string {
	if c.Name == "" {
		return ""
	}
	if c.Fix == "" {
		return fmt.Sprintf("%s is off.", c.Name)
	}
	return fmt.Sprintf("%s is off: %s.", c.Name, c.Fix)
}

// DigestLines returns digest lines for sticky caps (and owner opts once).
func DigestLines(caps []Cap, alreadySaid map[string]bool) []string {
	var out []string
	for _, c := range caps {
		line := StatusLine(c)
		if line == "" {
			continue
		}
		if c.Kind == OwnerOpt {
			if alreadySaid[c.Name] {
				continue
			}
		} else if !c.Sticky && c.Kind != Held && c.Kind != Host && c.Kind != Config {
			continue
		}
		out = append(out, line)
	}
	return out
}
