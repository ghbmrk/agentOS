package egress

import (
	"net/http"
	"strings"
	"testing"
)

// REQ: RES-5, OP-8

// No fixed count bounds one machine's requests in flight (RES-5, OP-8: a
// plan route has no fixed per-machine call cap): a machine is admitted
// while its share of the in-flight memory budget has room, and only that
// measured bound refuses.
func TestProxyNoPerMachineConcurrencyCap(t *testing.T) {
	const n = 9 // more than the former fixed per-machine count of 4
	ir := newInFlightRig(t, 2*n*chatCost(t), 1, Cap{})
	done := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() { done <- ir.do("m0").Code }()
		select {
		case <-ir.entered:
		case c := <-done:
			close(ir.block)
			t.Fatalf("request %d of one machine refused: %d", i+1, c)
		}
	}
	if _, per := ir.slots(); per["m0"] != n {
		t.Fatalf("m0 in flight %d, want %d", per["m0"], n)
	}
	w := ir.do("m0")
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many requests in flight") {
		t.Fatalf("past the machine's share: %d %q", w.Code, w.Body)
	}
	close(ir.block)
	for i := 0; i < n; i++ {
		if c := <-done; c != 200 {
			t.Fatalf("held request: %d", c)
		}
	}
	if g, per := ir.slots(); g != 0 || len(per) != 0 {
		t.Fatalf("slots left: %d %v", g, per)
	}
}
