package loopbuild

// REQ: RES-5, OP-8

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

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/inflight"
	"github.com/ghbmrk/agentos/broker/meter"
)

func heap() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
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

// holdUploads opens n uploads to path over the socket in dir, each
// declaring size bytes of {"x":"aaa..."} and sending its first hold
// bytes, then holding. It returns once one upload is admitted, with a
// func that finishes them all and returns their status codes.
func holdUploads(t *testing.T, dir, path string, n, size, hold int) func() []int {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, Socket))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	head, tail := `{"x":"`, `"}`
	body := []byte(head + strings.Repeat("a", size-len(head)-len(tail)) + tail) // shared: the guest side holds one copy
	release := make(chan struct{})
	sent := make(chan struct{}, n)
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		pr, pw := io.Pipe()
		req, _ := http.NewRequest("POST", "http://builder"+path, pr)
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

// RES-5 (#2314's combined finding): many large uploads held open at once
// hold the broker's memory to the builder's share of its budget, not one
// buffer each, and each waits for room rather than being refused.
func TestHeldUploadsKeepHeapBoundedAndWait(t *testing.T) {
	for _, tc := range []struct {
		name, path        string
		n, size, hold     int
		budget, heapBound int64
	}{
		// One 1 MiB model call (~108 MiB reserved) fits a 128 MiB share at
		// a time; 32 held unbounded would be about 32 MiB. Small bodies
		// keep it fast under -race.
		{"model", "/model/v1/chat/completions", 32, 1 << 20, 1<<20 - 4<<10, 256 << 20, 8 << 20},
		// Three 1 MiB candidates fit a 128 MiB share at a time; 128 held
		// unbounded would be 64 MiB.
		{"candidate", "/candidate", 128, 2 * MaxCandidateBytes, MaxCandidateBytes, 256 << 20, 16 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := tc.n
			var grew int64
			var codes []int
			f := &machines{}
			f.guest = func(id, dir string) {
				base := heap()
				finish := holdUploads(t, dir, tc.path, n, tc.size, tc.hold)
				grew = heap() - base
				codes = finish()
				call(guestClient(dir), "POST", "/done", nil)
			}
			b := newBuilder(t, f, func(c *Config) {
				c.Meter, c.Model = bigMeter(t), func(string) http.Handler { return http.NotFoundHandler() }
				c.InFlightBytes, c.Timeout, c.JobTokens = tc.budget, 2*time.Minute, 1<<50
			})
			b.Build(context.Background(), brief(change.ClassProcedure))
			if grew > tc.heapBound {
				t.Errorf("heap grew %d MiB with %d uploads of %d KiB held", grew>>20, n, tc.size>>10)
			}
			if len(codes) != n {
				t.Fatalf("%d uploads finished", len(codes))
			}
			for i, c := range codes {
				switch c {
				case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests, http.StatusServiceUnavailable, -1:
					t.Errorf("upload %d refused with %d; it should wait for room", i, c)
				}
			}
		})
	}
}

// RES-5: there is no fixed count of model calls; many run at once, and
// still within the job's cap.
func TestModelCallsRunTogether(t *testing.T) {
	const n = 16
	var mu sync.Mutex
	in, peak := 0, 0
	all := make(chan struct{})
	var codes [n]int
	f := &machines{}
	f.guest = func(id, dir string) {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i], _ = call(guestClient(dir), "POST", "/model/v1/chat/completions", map[string]any{"max_tokens": 10})
			}()
		}
		wg.Wait()
		call(guestClient(dir), "POST", "/done", nil)
	}
	b := newBuilder(t, f, func(c *Config) {
		c.Meter = bigMeter(t)
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				in++
				peak = max(peak, in)
				if in == n {
					close(all)
				}
				mu.Unlock()
				select {
				case <-all:
				case <-time.After(3 * time.Second):
				}
				mu.Lock()
				in--
				mu.Unlock()
				io.WriteString(w, `{"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			})
		}
	})
	b.Build(context.Background(), brief(change.ClassProcedure))
	if peak != n {
		t.Errorf("%d of %d model calls ran at once", peak, n)
	}
	for i, c := range codes {
		if c != 200 {
			t.Errorf("call %d: %d", i, c)
		}
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

// keys is a JSON object of about n bytes of short entries under wrap, the
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
// costliest body shapes measured (inflight ASSUMPTIONS RES-5-membudget-I2), at every size.
func TestRouteCostsCoverWhatHandlersAllocate(t *testing.T) {
	s := &session{id: "m", ns: "procedures", b: &Builder{cfg: Config{Meter: bigMeter(t), JobTokens: 1 << 50,
		Model: func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) })
		}}}}
	model := s.model()
	for _, n := range []int{4 << 10, 64 << 10, 1 << 20, 7 << 20} {
		for _, tc := range []struct {
			name string
			h    http.Handler
			max  int
			path string
			wrap string
			cost inflight.Cost
		}{
			{"model keys", model, inflight.ModelBody, "/v1/chat/completions", "", inflight.Model},
			{"candidate files", http.HandlerFunc(s.candidate), 2 * MaxCandidateBytes, "/candidate", `"files":{`, inflight.Decode},
		} {
			if n > tc.max-16 {
				continue
			}
			body := keys(n, tc.wrap)
			got := allocated(func() {
				tc.h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", tc.path, bytes.NewReader(body)))
			})
			if want := tc.cost.Of(int64(len(body))); got > want {
				t.Errorf("%s at %d bytes allocates %d, more than the %d reserved", tc.name, len(body), got, want)
			}
		}
	}
}

// RES-5 (security on #2327): model calls in flight together cannot pass
// the job token cap by more than one call, even when the provider counts a
// token per byte, four times the meter's estimate.
func TestParallelCallsKeepJobTokenCap(t *testing.T) {
	const cap, n, rounds, pad = 10000, 16, 3, 2000
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	in, biggest := 0, 0
	all := make(chan struct{})
	var once sync.Once
	var jobID string
	f := &machines{}
	f.guest = func(id, dir string) {
		jobID = id
		c := guestClient(dir)
		for range rounds {
			var wg sync.WaitGroup
			for range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					call(c, "POST", "/model/v1/chat/completions", map[string]any{"max_tokens": 10, "pad": strings.Repeat("a", pad)})
				}()
			}
			wg.Wait()
		}
		call(c, "POST", "/done", nil)
	}
	b := newBuilder(t, f, func(c *Config) {
		c.Meter, c.JobTokens = mtr, cap
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				in++
				biggest = max(biggest, len(body))
				if in == n {
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
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"usage":{"prompt_tokens":%d,"completion_tokens":10}}`, len(body))
			})
		}
	})
	b.Build(context.Background(), brief(change.ClassProcedure))
	if got, most := mtr.Usage(jobID).Tokens, int64(cap+biggest+10); got > most {
		t.Errorf("job used %d tokens; the cap is %d, soft by one call (%d)", got, cap, most)
	}
}
