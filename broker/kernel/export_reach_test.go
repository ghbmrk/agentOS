package kernel

import (
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// GraphReach is the classes clerk's keys reach through the declarations.
func GraphReach(s *State, clerk string) []key.Asset { return s.graphReach(clerk) }

// Reached is the sorted nodes node reaches, itself included; nil when no
// declaration names it.
func Reached(s *State, node string) []string {
	var out []string
	for id := range s.reached(node) {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
