package cleanroom

// REQ: RES-5, OP-8, OSS-2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/inflight"
	"github.com/ghbmrk/agentos/broker/meter"
)

func heap() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// holdUploads opens n uploads to path over the socket in dir, each
// declaring size bytes of {"x":"aaa..."} and sending the first hold
// bytes, then holding. It returns once the uploads are held, with a func
// that finishes them and returns their status codes.
func holdUploads(t *testing.T, dir, path string, n, size, hold int) func() []int {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, Socket))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	head, tail := `{"x":"`, `"}`
	pad := strings.Repeat("a", size-len(head)-len(tail))
	body := []byte(head + pad + tail) // shared, so the guest side holds one copy
	release := make(chan struct{})
	sent := make(chan struct{}, n)
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		pr, pw := io.Pipe()
		req, _ := http.NewRequest("POST", "http://broker"+path, pr)
		req.ContentLength = int64(size)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := tr.RoundTrip(req)
			if err != nil {
				codes[i] = -1
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
		go func() {
			pw.Write(body[:hold])
			sent <- struct{}{}
			<-release
			pw.Write(body[hold:])
			pw.Close()
		}()
	}
	// At least one upload is admitted and read to its hold; the rest wait.
	select {
	case <-sent:
	case <-time.After(30 * time.Second):
		t.Fatal("no upload was admitted")
	}
	time.Sleep(300 * time.Millisecond)
	return func() []int {
		close(release)
		wg.Wait()
		return codes
	}
}

func bigMeter(t *testing.T) *meter.Meter {
	t.Helper()
	big := meter.Limits{Calls: 1 << 20, Tokens: 1 << 50}
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: big, OverallCap: big})
	if err != nil {
		t.Fatal(err)
	}
	return mtr
}

// RES-5 (#2314's combined finding): many large uploads held open at once
// hold the broker's memory to its budget, not one buffer each, and each
// waits for room rather than being refused.
func TestHeldUploadsKeepHeapBoundedAndWait(t *testing.T) {
	// Each budget admits one upload at a time (a 1 MiB model call reserves
	// ~108 MiB, a 1 MiB result ~32 MiB), so the heap holds one body while
	// unbounded buffering would hold n. Small bodies keep it fast under -race.
	for _, tc := range []struct {
		name, path string
		budget     int64
	}{
		{"model", "/model/v1/chat/completions", 256 << 20},
		{"result", "/cleanroom/result", 128 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *Config) {
				c.Meter, c.Model = bigMeter(t), func(string) http.Handler { return http.NotFoundHandler() }
				c.InFlightBytes = tc.budget
				c.Timeout = 2 * time.Minute
			})
			const n, size, hold, bound = 32, 1 << 20, 1<<20 - 4<<10, 8 << 20
			var grew int64
			var codes []int
			guested := make(chan struct{})
			r.f.guest = func(id, dir string) {
				defer close(guested)
				base := heap()
				finish := holdUploads(t, dir, tc.path, n, size, hold)
				grew = heap() - base
				codes = finish()
				call(client(dir), "POST", "/cleanroom/result", goodResult())
			}
			r.b.Send(nextDay(), [][]byte{skillHint(t)})
			r.run()
			// The uploads run one at a time, which takes longer than
			// waitFor's 5 s under -race; wait for the guest first.
			select {
			case <-guested:
			case <-time.After(time.Minute):
				t.Fatal("the guest's uploads did not finish")
			}
			waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
			r.f.wg.Wait()
			if grew > bound {
				t.Errorf("heap grew %d KiB with %d uploads of %d KiB held", grew>>10, n, size>>10)
			}
			for i, c := range codes {
				switch c {
				case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests, http.StatusServiceUnavailable, -1:
					t.Errorf("upload %d refused with %d; it should wait for room", i, c)
				}
			}
			if len(codes) != n {
				t.Fatalf("%d uploads finished", len(codes))
			}
		})
	}
}

// RES-5: there is no fixed count of requests; many small ones run at once.
func TestManySmallRequestsRunTogether(t *testing.T) {
	const n = 16
	var mu sync.Mutex
	in, peak := 0, 0
	gate := make(chan struct{})
	r := newRig(t, func(c *Config) {
		c.Meter = bigMeter(t)
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				in++
				peak = max(peak, in)
				if in == n {
					close(gate)
				}
				mu.Unlock()
				select {
				case <-gate:
				case <-time.After(3 * time.Second):
				}
				mu.Lock()
				in--
				mu.Unlock()
				io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			})
		}
	})
	var codes [n]int
	r.f.guest = func(id, dir string) {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i], _ = call(client(dir), "POST", "/model/v1/chat/completions", []byte(`{"model":"m","messages":[]}`))
			}()
		}
		wg.Wait()
		call(client(dir), "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if peak != n {
		t.Errorf("%d of %d requests ran at once", peak, n)
	}
	for i, c := range codes {
		if c != 200 {
			t.Errorf("request %d: %d", i, c)
		}
	}
}

// RES-5: a request that could never fit in a clean room's share of the
// budget gets 413 before its body is read.
func TestRequestOverShareIsRefusedUnread(t *testing.T) {
	var code int
	r := newRig(t, func(c *Config) {
		c.Meter, c.Model = bigMeter(t), func(string) http.Handler { return http.NotFoundHandler() }
		c.InFlightBytes = 64 << 20 // a 32 MiB share; an 8 MiB model call needs more
	})
	r.f.guest = func(id, dir string) {
		code, _ = call(client(dir), "POST", "/model/v1/chat/completions", bytes.Repeat([]byte(" "), 8<<20))
		call(client(dir), "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-share request: %d, want 413", code)
	}
}

func allocated(f func()) int64 {
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return int64(b.TotalAlloc - a.TotalAlloc)
}

// keys is a JSON object of n bytes of short entries under wrap, the
// costliest shape measured for a map decode.
func keys(n int, wrap string) []byte {
	var b bytes.Buffer
	b.WriteString("{" + wrap)
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"%x":""`, i)
	}
	b.WriteString(strings.Repeat("}", strings.Count(wrap, "{")) + "}")
	return b.Bytes()
}

// RES-5: what each route reserves covers all it allocates for the
// costliest body shapes measured (ASSUMPTIONS I2), at every size. The
// model route's meter is WrapBound's, which also scans the body.
func TestRouteCostsCoverWhatHandlersAllocate(t *testing.T) {
	mtr := bigMeter(t)
	model := mtr.WrapBound("m", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	s := &session{}
	for _, n := range []int{4 << 10, 64 << 10, 1 << 20, 7 << 20} {
		for _, tc := range []struct {
			name string
			h    http.Handler
			path string
			body []byte
			cost inflight.Cost
		}{
			{"model keys", model, "/v1/chat/completions", keys(n, ""), inflight.Model},
			{"result files", http.HandlerFunc(s.result), "/cleanroom/result", keys(n, `"files":{`), inflight.Decode},
		} {
			got := allocated(func() {
				tc.h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", tc.path, bytes.NewReader(tc.body)))
			})
			if want := tc.cost.Of(int64(len(tc.body))); got > want {
				t.Errorf("%s at %d bytes allocates %d, more than the %d reserved", tc.name, len(tc.body), got, want)
			}
		}
	}
}

// RES-5 (security on #2327): model calls in flight together cannot pass
// the meter's per-machine cap, even when the provider counts a token per
// byte, four times the meter's estimate.
func TestParallelCallsKeepMachineCap(t *testing.T) {
	const tokens, n, rounds, pad = 10000, 16, 3, 2000
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 1 << 20, Tokens: tokens}, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	in := 0
	all := make(chan struct{})
	var once sync.Once
	var machine string
	r := newRig(t, func(c *Config) {
		c.Meter = mtr
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				if in++; in == n {
					once.Do(func() { close(all) })
				}
				mu.Unlock()
				select {
				case <-all:
				case <-time.After(300 * time.Millisecond):
				}
				mu.Lock()
				in--
				mu.Unlock()
				fmt.Fprintf(w, `{"choices":[],"usage":{"prompt_tokens":%d,"completion_tokens":10}}`, len(body))
			})
		}
	})
	body := []byte(`{"model":"m","max_tokens":10,"messages":[],"pad":"` + strings.Repeat("a", pad) + `"}`)
	r.f.guest = func(id, dir string) {
		machine = id
		for range rounds {
			var wg sync.WaitGroup
			for range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					call(client(dir), "POST", "/model/v1/chat/completions", body)
				}()
			}
			wg.Wait()
		}
		call(client(dir), "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	// A call with none of the machine's others in flight is charged at
	// the estimate, so the cap is soft by that one call (inflight I8).
	if got, most := mtr.Usage(machine).Tokens, int64(tokens+len(body)+10); got > most {
		t.Errorf("machine used %d tokens; its cap is %d, soft by one call (%d)", got, tokens, most)
	}
}
