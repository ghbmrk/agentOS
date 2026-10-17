package cleanroom

// REQ: RES-5, OP-8

import (
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// RES-5 as #2291 amended it: a clean room's model calls have no fixed
// in-flight cap. Eight calls are held open at once and every one is
// served; none is refused as too many in flight.
func TestCleanRoomHasNoFixedInFlightCap(t *testing.T) {
	const n = 8
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 100, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 100, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	var arrived sync.WaitGroup
	arrived.Add(n)
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	r := newRig(t, func(c *Config) {
		c.Meter = mtr
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				arrived.Done()
				select {
				case <-all:
				case <-time.After(3 * time.Second):
					http.Error(w, "calls were not all in flight at once", http.StatusGatewayTimeout)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
			})
		}
	})
	codes := make([]int, n)
	r.f.guest = func(_, dir string) {
		c := client(dir)
		var wg sync.WaitGroup
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i], _ = call(c, "POST", "/model/v1/chat/completions", []byte(`{"model":"m","messages":[]}`))
			}()
		}
		wg.Wait()
		call(c, "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("call %d: %d (all %v)", i, code, codes)
		}
	}
}
