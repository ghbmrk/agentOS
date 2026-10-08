package grants

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-5, ADP-2
func TestAttachmentUnboundHasOneConcurrentWinner(t *testing.T) {
	g := New(Config{Declared: map[string]map[string]string{"synthetic": {"message.list": "read"}}})
	if !g.HasExecutorDeclaration("synthetic") || g.HasExecutorDeclaration("unknown") {
		t.Fatal("declaration lookup substituted config")
	}
	var nilGate *Gate
	if nilGate.HasExecutorDeclaration("synthetic") || nilGate.AttachUnbound(nil, nil) || g.AttachUnbound(nil, nil) {
		t.Fatal("nil binding accepted")
	}
	const attempts = 8
	engines := make([]*journal.Engine, attempts)
	for i := range engines {
		eng, e := journal.Open(&journal.MemStore{}, g, map[string]journal.Executor{ExecutorName: g}, func(s string) string { return s })
		if e != nil {
			t.Fatal(e)
		}
		engines[i] = eng
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for _, eng := range engines {
		wg.Add(1)
		go func(eng *journal.Engine) {
			defer wg.Done()
			if g.AttachUnbound(eng, nil) {
				winners.Add(1)
			}
		}(eng)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("multiple binding winners", winners.Load())
	}
	chosen := g.eng
	for _, eng := range engines {
		if g.AttachUnbound(eng, nil) {
			t.Fatal("attached Gate rebound")
		}
	}
	if g.eng != chosen {
		t.Fatal("loser replaced existing engine")
	}
}
