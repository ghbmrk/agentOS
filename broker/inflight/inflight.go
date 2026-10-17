// Package inflight bounds the memory a guest-facing broker socket holds
// for requests in flight (RES-5, OP-8): no fixed request or connection
// count, only a byte budget sized from the process's memory limit.
//
// Every request reserves its worst-case cost before its body is read,
// from its declared length (or the route's largest body when it declares
// none) times the route's measured cost factor. A request whose cost
// would not fit waits, in arrival order, without reading; one that could
// never fit gets 413. Reservations never grow after a read, so waiting
// cannot deadlock. Each connection reserves a fixed cost while open, and
// one guest may hold at most half the budget, so no one guest can hold
// it all. The design is the egress proxy's (#2294) with waiting in place
// of refusal.
package inflight

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Cost is a route's measured worst-case memory for one request: Floor
// plus PerByte for each byte of its body.
type Cost struct{ Floor, PerByte int64 }

// Of is the cost of a request with an n-byte body.
func (c Cost) Of(n int64) int64 {
	if n > 0 && c.PerByte > (math.MaxInt64-c.Floor)/n {
		return math.MaxInt64
	}
	return c.Floor + c.PerByte*n
}

const (
	// ConnCost is reserved for each open connection: its goroutine, its
	// read and write buffers and one header block (MaxHeaderBytes).
	ConnCost = 128 << 10
	// MaxHeaderBytes is the header block a guest socket accepts; servers
	// set it so ConnCost holds.
	MaxHeaderBytes = 16 << 10

	// ModelBody is meter.Wrap's request cap (its MaxBody default, which
	// no caller changes).
	ModelBody = 8 << 20
)

// Model is meter.Wrap's cost: every byte of the request is read, decoded
// top level into a map and re-encoded, which allocates up to 96 times the
// body for one of many short top-level keys (measured; ASSUMPTIONS I2),
// plus one copy a caller may buffer first. The floor holds the provider's
// answer as the meter examines it (at most the call's output limit,
// I3) and a small body's fixed overhead.
var Model = Cost{Floor: 4<<20 + 64<<10, PerByte: 104}

// Decode is a handler that reads its body once and decodes it into a
// struct holding a map of strings (a clean-room result, a builder's
// candidate): up to 30 times the body for many short entries (measured;
// ASSUMPTIONS I2).
var Decode = Cost{Floor: 64 << 10, PerByte: 32}

// Budget is one process's in-flight memory, in bytes.
type Budget struct {
	size int64
	sem  *semaphore.Weighted
}

// New is a budget of size bytes.
func New(size int64) *Budget {
	return &Budget{size: size, sem: semaphore.NewWeighted(size)}
}

// Size is the budget's size in bytes.
func (b *Budget) Size() int64 { return b.size }

var (
	defaultOnce sync.Once
	defaultB    *Budget
)

// Default is the process's budget: a quarter of its memory limit, shared
// by every guest socket in the process.
func Default() *Budget {
	defaultOnce.Do(func() { defaultB = New(MemoryLimit() / 4) })
	return defaultB
}

// MemoryLimit is the least of the Go runtime's memory limit (GOMEMLIMIT),
// the memory.max and memory.high of the process's cgroup and each of its
// ancestors, and the host's MemTotal.
func MemoryLimit() int64 {
	limit := debug.SetMemoryLimit(-1)
	if n, ok := memTotal("/proc/meminfo"); ok {
		limit = min(limit, n)
	}
	if n, ok := cgroupLimit("/proc/self/cgroup", "/sys/fs/cgroup"); ok {
		limit = min(limit, n)
	}
	return limit
}

func memTotal(file string) (int64, bool) {
	f, err := os.Open(file)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			return kb << 10, err == nil && kb > 0
		}
	}
	return 0, false
}

// cgroupLimit is the least memory.max or memory.high on the cgroup v2
// path from the process's group up to the root.
func cgroupLimit(self, fs string) (int64, bool) {
	data, err := os.ReadFile(self)
	if err != nil {
		return 0, false
	}
	dir := ""
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			dir = path.Clean("/" + p)
		}
	}
	if dir == "" {
		return 0, false
	}
	limit, found := int64(math.MaxInt64), false
	for {
		for _, f := range []string{"memory.max", "memory.high"} {
			v, err := os.ReadFile(path.Join(fs, dir, f))
			if err != nil {
				continue
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil && n > 0 {
				limit, found = min(limit, n), true
			}
		}
		if dir == "/" {
			return limit, found
		}
		dir = path.Dir(dir)
	}
}

// Gate admits one guest's connections and requests against a budget. A
// guest holds at most half the budget.
type Gate struct {
	b    *Budget
	own  *semaphore.Weighted
	cap  int64
	wait time.Duration
}

// Gate is a new guest's gate. A request waits at most wait for room.
func (b *Budget) Gate(wait time.Duration) *Gate {
	c := b.size / 2
	return &Gate{b: b, own: semaphore.NewWeighted(c), cap: c, wait: wait}
}

// ErrTooCostly is a request that could never fit in the guest's share.
var ErrTooCostly = errors.New("inflight: request costs more than this machine's share of broker memory")

// acquire reserves n bytes, the guest's share first and then the
// process's, waiting until ctx ends.
func (g *Gate) acquire(ctx context.Context, n int64) (func(), error) {
	if n > g.cap {
		return nil, ErrTooCostly
	}
	if err := g.own.Acquire(ctx, n); err != nil {
		return nil, err
	}
	if err := g.b.sem.Acquire(ctx, n); err != nil {
		g.own.Release(n)
		return nil, err
	}
	return g.release(n), nil
}

// tryAcquire reserves n bytes only if they are free and no request waits.
func (g *Gate) tryAcquire(n int64) (func(), bool) {
	if !g.own.TryAcquire(n) {
		return nil, false
	}
	if !g.b.sem.TryAcquire(n) {
		g.own.Release(n)
		return nil, false
	}
	return g.release(n), true
}

func (g *Gate) release(n int64) func() {
	return sync.OnceFunc(func() { g.b.sem.Release(n); g.own.Release(n) })
}

// Route admits next's requests: each reserves c.Of of its declared body
// length, or of max when it declares none, before next reads it. max is
// the most next reads; a longer declared body gets 413 unread. Once
// admitted, the request has read (if non-zero) to read its body, however
// long it waited.
func (g *Gate) Route(max int64, c Cost, read time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := r.ContentLength
		if n > max {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if n < 0 {
			n = max
		}
		ctx, cancel := context.WithTimeout(r.Context(), g.wait)
		release, err := g.acquire(ctx, c.Of(n))
		cancel()
		if errors.Is(err, ErrTooCostly) {
			http.Error(w, "request too large for the broker's memory; send a smaller body with its Content-Length", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "broker busy; retry", http.StatusServiceUnavailable)
			return
		}
		defer release()
		if read > 0 {
			http.NewResponseController(w).SetReadDeadline(time.Now().Add(read))
		}
		next.ServeHTTP(w, r)
	})
}

// Limit reserves ConnCost for each connection l accepts, until it
// closes. Past the guest's share, Accept waits, so further connections
// wait in the kernel's queue and cost the broker no file descriptor.
// Accept never queues ahead of a request: it takes room only when no
// request waits, so a guest's open connections cannot hold back the
// requests that would let them close.
func (g *Gate) Limit(l net.Listener) net.Listener {
	ctx, cancel := context.WithCancel(context.Background())
	return &listener{Listener: l, g: g, ctx: ctx, cancel: cancel}
}

type listener struct {
	net.Listener
	g      *Gate
	ctx    context.Context
	cancel context.CancelFunc
}

// connPoll is how often a waiting Accept looks for room.
const connPoll = 20 * time.Millisecond

func (l *listener) Accept() (net.Conn, error) {
	var release func()
	for ok := false; !ok; {
		if release, ok = l.g.tryAcquire(ConnCost); ok {
			break
		}
		select {
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		case <-time.After(connPoll):
		}
	}
	c, err := l.Listener.Accept()
	if err != nil {
		release()
		return nil, err
	}
	return &conn{Conn: c, release: release}, nil
}

func (l *listener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

type conn struct {
	net.Conn
	release func()
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
