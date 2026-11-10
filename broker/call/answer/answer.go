// Package answer is the voice call's answerer (VOICE-ro-c, briefs/VOICE-ro.md
// rule 4; SPEC CH-5, CH-17, PLN-3). What a call may hear is set by the data
// labels of what was read and the call's rung, never by the answerer's prompt:
// below P2 the writer is given only the box's own status, so a call from a
// spoofed caller ID cannot hear mail or the calendar read aloud, whatever it
// says (#4948).
package answer

import (
	"context"

	"github.com/ghbmrk/agentos/broker/call"
)

// Status is the label of a fact about the box itself (STATUS, what is due on
// the box), read from no account. It is the only label a call below P2 may
// hear.
const Status = "status"

// Fact is one value a read returned, with its data labels (PLN-3). The read
// side sets the labels from the kernel's; the transcript and the writer never
// do. A fact with no labels is private.
type Fact struct {
	Text   string
	Labels []string
}

// Reads are the planner's reads of mail, calendar, due items and STATUS
// under the call's read keys. They see the ask and its rung, so they may skip
// a read the rung cannot hear, but Answer does not rely on that.
type Reads interface {
	Read(ctx context.Context, a call.Ask) ([]Fact, error)
}

// Writer is the model that words the answer. It sees only the ask and the
// facts Answer admits; the channel closes at the end of the answer.
type Writer interface {
	Write(ctx context.Context, a call.Ask, facts []Fact) (<-chan string, error)
}

// Answerer is a call.Answerer that admits facts by their labels.
type Answerer struct {
	Reads  Reads
	Writer Writer
}

// Answer reads, admits what the ask's rung may hear, and has the writer word
// the answer from that alone. A failed read fails the turn. The rung is
// a.Rung(), read once: only package call can make an Ask above P0, and
// admit is called only here, with it (TestTheRungIsTheAsks).
func (an Answerer) Answer(ctx context.Context, a call.Ask) (<-chan string, error) {
	facts, err := an.Reads.Read(ctx, a)
	if err != nil {
		return nil, err
	}
	return an.Writer.Write(ctx, a, admit(a.Rung(), facts))
}

// admit returns the facts rung r may hear. P2 hears every fact. Any other
// rung, P1 and a rung this package does not know included, hears only facts
// whose every label is Status, so an unlabelled fact, or one that mixes the
// status with anything else, is held back.
func admit(r call.Rung, facts []Fact) []Fact {
	var out []Fact
	for _, f := range facts {
		if r == call.P2 || statusOnly(f.Labels) {
			out = append(out, f)
		}
	}
	return out
}

func statusOnly(labels []string) bool {
	for _, l := range labels {
		if l != Status {
			return false
		}
	}
	return len(labels) > 0
}
