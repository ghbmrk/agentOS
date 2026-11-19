package graph

// REQ: KEY-9, CLK-14

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// failing is a Declarer whose read or write fails; sent counts writes.
type failing struct {
	read, write error
	sent        *int
}

func (f failing) DeclReach() (kernel.DeclReach, error) { return kernel.DeclReach{}, f.read }
func (f failing) DeclareReach(kernel.DeclReach) error {
	*f.sent++
	return f.write
}

// The writer stops on each failure and passes it on: a graph it can't map,
// a log it can't read (it then sends nothing) and a write the kernel refused.
func TestWriteReachPassesFailuresOn(t *testing.T) {
	boom := errors.New("socket closed")
	sent := 0
	if err := WriteReach(failing{sent: &sent}, mailbank(t, true), map[string]string{"mail": "a.gone"}); err == nil || sent != 0 {
		t.Fatalf("a clerk rooted on a node the graph lacks: %v after %d writes, want an error and none", err, sent)
	}
	if err := WriteReach(failing{read: boom, sent: &sent}, mailbank(t, true), map[string]string{"mail": "a.mail"}); !errors.Is(err, boom) || sent != 0 {
		t.Fatalf("an unreadable log: %v after %d writes, want %v and none", err, sent, boom)
	}
	if err := WriteReach(failing{write: boom, sent: &sent}, mailbank(t, true), map[string]string{"mail": "a.mail"}); !errors.Is(err, boom) || sent != 1 {
		t.Fatalf("a refused write: %v after %d writes, want %v after one", err, sent, boom)
	}
}

// A node an earlier edge named only as a source is held back like one it
// named as a target: the kernel priced it as every class, so declaring it
// could lower that price and the kernel would refuse the entry whole.
func TestAdditionsHoldANodeAnEdgeNamedAsSource(t *testing.T) {
	have := kernel.DeclReach{Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"x"}, To: "y"}}}
	add, held := Additions(have, kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "x"}}})
	if len(add.Nodes)+len(add.Edges) != 0 || len(held) != 1 || held[0] != `node "x" stays undeclared: an earlier edge named it` {
		t.Fatalf("additions %+v, held %q, want nothing sent and x held", add, held)
	}
}
