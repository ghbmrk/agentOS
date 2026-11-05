package readerwire

// REQ: PLN-2, D-154, D-158, CLK-7

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const roleEnv = "AGENTOS_READERWIRE_TEST_ROLE"

// TestMain runs as the reader in TestEachEndChecksTheOthersUID's child:
// it serves a fixed class on the socket and admits only the given uid.
func TestMain(m *testing.M) {
	if os.Getenv(roleEnv) != "reader" {
		os.Exit(m.Run())
	}
	var mailUID int
	fmt.Sscan(os.Getenv(roleEnv+"_UID"), &mailUID)
	ln, err := Listen(os.Getenv(roleEnv+"_SOCK"), mailUID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, Serve(ln, func(context.Context, string) (string, error) { return "spam", nil }))
	os.Exit(2)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// sock is a socket path short enough for a unix address.
func sock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rw")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "r.sock")
}

// reader serves model on a fresh socket that admits this process's uid.
func reader(t *testing.T, model Ask, timeout time.Duration) string {
	t.Helper()
	path := sock(t)
	ln, err := Listen(path, os.Getuid())
	must(t, err)
	go serve(ln, model, timeout, time.Sleep)
	t.Cleanup(func() { ln.Close() })
	return path
}

// raw is a fake reader that answers every call with ans, verbatim, and
// records each call it read.
type raw struct {
	path  string
	ans   []byte
	mu    sync.Mutex
	calls [][]byte
	conns atomic.Int32
}

func rawReader(t *testing.T, ans string) *raw { return fakeReader(t, ans, false) }

// hungReader reads each call and never answers.
func hungReader(t *testing.T) *raw { return fakeReader(t, "", true) }

func fakeReader(t *testing.T, ans string, hang bool) *raw {
	t.Helper()
	r := &raw{path: sock(t), ans: []byte(ans)}
	ln, err := net.Listen("unix", r.path)
	must(t, err)
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.conns.Add(1)
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(io.LimitReader(c, 1<<20))
				r.mu.Lock()
				r.calls = append(r.calls, b)
				r.mu.Unlock()
				if hang {
					<-done
					return
				}
				c.Write(r.ans)
			}()
		}
	}()
	return r
}

func me() int { return os.Getuid() }

// TestReadRoundTrip: a fake model's class word comes back as the reply
// (inbox.Read over the frame: inbox_test.go).
func TestReadRoundTrip(t *testing.T) {
	var got string
	path := reader(t, func(_ context.Context, p string) (string, error) {
		got = p
		return " Spam\n", nil
	}, 5*time.Second)
	ask := Dial(path, me(), 5*time.Second)
	if r, err := ask(context.Background(), "a prompt"); err != nil || r != " Spam\n" || got != "a prompt" {
		t.Fatalf("ask = %q, %v; the model saw %q", r, err, got)
	}
}

func paused(a Ask) bool {
	_, err := a(context.Background(), "x")
	return errors.Is(err, ErrPaused)
}

// TestFrameBounds: the call's and the answer's bounds, and every answer the
// frame does not admit, which fails that mail without pausing the reader.
func TestFrameBounds(t *testing.T) {
	t.Run("a prompt over MaxPrompt is refused with nothing sent", func(t *testing.T) {
		r := rawReader(t, `{"reply":"spam"}`+"\n")
		_, err := Dial(r.path, me(), time.Second)(context.Background(), strings.Repeat("a", MaxPrompt+1))
		time.Sleep(50 * time.Millisecond)
		if !errors.Is(err, ErrTooLarge) || r.conns.Load() != 0 {
			t.Fatalf("err %v, %d dials", err, r.conns.Load())
		}
	})
	t.Run("a MaxPrompt prompt of any bytes crosses intact within the bound", func(t *testing.T) {
		p := make([]byte, MaxPrompt)
		for i := range p {
			p[i] = []byte{'<', 0, 0x1b, 0xff, 0xc3, '"', '\\', '\n'}[i%8]
		}
		b, err := json.Marshal(call{V: version, Op: opRead, Prompt: p})
		must(t, err)
		if len(b)+1 > maxCall {
			t.Fatalf("the call is %d bytes on the wire, past %d", len(b)+1, maxCall)
		}
		var got string
		path := reader(t, func(_ context.Context, s string) (string, error) { got = s; return "bulk", nil }, 5*time.Second)
		if r, err := Dial(path, me(), 5*time.Second)(context.Background(), string(p)); err != nil || r != "bulk" {
			t.Fatalf("ask = %q, %v", r, err)
		}
		if got != string(p) {
			t.Fatal("the prompt did not cross intact")
		}
	})
	t.Run("a 65-byte reply is refused, never cut", func(t *testing.T) {
		long := strings.Repeat("s", MaxReply+1)
		path := reader(t, func(context.Context, string) (string, error) { return long, nil }, 5*time.Second)
		a := Dial(path, me(), 5*time.Second)
		if r, err := a(context.Background(), "x"); r != "" || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("a 65-byte reply: %q, %v", r, err)
		}
		// A reader that sends it anyway.
		fake := rawReader(t, `{"reply":"`+long+`"}`+"\n")
		if r, err := Dial(fake.path, me(), 5*time.Second)(context.Background(), "x"); r != "" || !errors.Is(err, ErrMalformed) {
			t.Fatalf("a 65-byte reply from a lying reader: %q, %v", r, err)
		}
	})
	t.Run("a reply escaping pushes past the wire bound is refused", func(t *testing.T) {
		esc := strings.Repeat("<", MaxReply)
		path := reader(t, func(context.Context, string) (string, error) { return esc, nil }, 5*time.Second)
		if r, err := Dial(path, me(), 5*time.Second)(context.Background(), "x"); r != "" || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("an escaped 64-byte reply: %q, %v", r, err)
		}
	})
	bad := map[string]string{
		"an answer over 256 bytes": `{"reply":"spam","x":"` + strings.Repeat("a", 250) + `"}` + "\n",
		"trailing data":            `{"reply":"spam"}` + "\nx",
		"two answers":              `{"reply":"spam"}` + "\n" + `{"reply":"spam"}` + "\n",
		"an unknown error word":    `{"err":"spam"}` + "\n",
		"both fields":              `{"reply":"spam","err":"refused"}` + "\n",
		"neither field":            `{}` + "\n",
		"another key case":         `{"Reply":"spam"}` + "\n",
		"an unknown key":           `{"reply":"spam","v":2}` + "\n",
		"another spacing":          `{"reply": "spam"}` + "\n",
		"a duplicate key":          `{"reply":"bulk","reply":"spam"}` + "\n",
		"not JSON":                 "spam\n",
		"an escaped reply":         `{"reply":"` + strings.Repeat(`\u0073`, 4) + `"}` + "\n",
		"a reply escaped past 256": `{"reply":"` + strings.Repeat(`\u003c`, MaxReply) + `"}` + "\n",
	}
	for name, ans := range bad {
		t.Run(name, func(t *testing.T) {
			r := rawReader(t, ans)
			a := Dial(r.path, me(), 5*time.Second)
			if got, err := a(context.Background(), "x"); got != "" || !errors.Is(err, ErrMalformed) {
				t.Fatalf("%q: %q, %v", ans, got, err)
			}
			if paused(a) {
				t.Fatal("a malformed answer paused the reader")
			}
		})
	}
	t.Run("another version or op is closed unanswered", func(t *testing.T) {
		called := false
		path := reader(t, func(context.Context, string) (string, error) { called = true; return "spam", nil }, 5*time.Second)
		for _, c := range []string{`{"v":2,"op":"read","prompt":"eA=="}`, `{"v":1,"op":"write","prompt":"eA=="}`,
			`{"v":1,"op":"read","prompt":"eA==","x":1}`, `{"V":1,"op":"read","prompt":"eA=="}`, `{"v":1,"op":"read","prompt":"e"}`} {
			conn, err := net.Dial("unix", path)
			must(t, err)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte(c + "\n"))
			conn.(*net.UnixConn).CloseWrite()
			b, _ := io.ReadAll(conn)
			conn.Close()
			if len(b) != 0 {
				t.Errorf("%s: answered %q", c, b)
			}
		}
		if called {
			t.Error("the model was called on a refused call")
		}
	})
}

// TestEachEndChecksTheOthersUID: the mail clerk sends nothing to a listener
// under another uid, and the reader closes a caller under another uid unread.
func TestEachEndChecksTheOthersUID(t *testing.T) {
	// The listener is this process's; the mail clerk expects another uid.
	r := rawReader(t, `{"reply":"spam"}`+"\n")
	a := Dial(r.path, me()+1, 5*time.Second)
	if got, err := a(context.Background(), "secret mail"); got != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a listener under another uid: %q, %v", got, err)
	}
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	for _, c := range r.calls {
		if len(c) != 0 {
			t.Errorf("a listener under another uid got %q", c)
		}
	}
	r.mu.Unlock()
	if !paused(a) {
		t.Error("a wrong uid did not pause the reader")
	}
	// The reader admits another uid; this process calls it.
	path := sock(t)
	ln, err := Listen(path, me()+1)
	must(t, err)
	defer ln.Close()
	var called atomic.Bool
	go Serve(ln, func(context.Context, string) (string, error) { called.Store(true); return "spam", nil })
	if got, err := Dial(path, me(), 5*time.Second)(context.Background(), "x"); got != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a caller under another uid: %q, %v", got, err)
	}
	if called.Load() {
		t.Error("the model was called for a caller under another uid")
	}

	if os.Geteuid() != 0 {
		t.Skip("needs root: the reader runs as nobody")
	}
	// As root: the reader is a process under its own uid, so each end's
	// check meets a real peer of another uid.
	base, err := os.MkdirTemp("", "rw")
	must(t, err)
	defer os.RemoveAll(base)
	must(t, os.Chmod(base, 0o755))
	self, err := os.Executable()
	must(t, err)
	b, err := os.ReadFile(self)
	must(t, err)
	bin := filepath.Join(base, "bin")
	must(t, os.WriteFile(bin, b, 0o755))
	run := func(name string, mailUID int) string {
		dir := filepath.Join(base, name)
		must(t, os.Mkdir(dir, 0o711))
		must(t, os.Chown(dir, 65534, 65534))
		path := filepath.Join(dir, "r.sock")
		cmd := exec.Command(bin, "-test.run=^$")
		cmd.Env = []string{roleEnv + "=reader", roleEnv + "_SOCK=" + path, fmt.Sprintf("%s_UID=%d", roleEnv, mailUID)}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		must(t, cmd.Start())
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(path); err == nil {
				return path
			}
			if time.Now().After(deadline) {
				t.Fatalf("the reader never listened: %s", out.String())
			}
		}
	}
	admitsRoot := run("a", 0)
	if got, err := Dial(admitsRoot, 65534, 5*time.Second)(context.Background(), "x"); got != "spam" || err != nil {
		t.Fatalf("the reader as nobody, called by root: %q, %v", got, err)
	}
	if got, err := Dial(admitsRoot, 65533, 5*time.Second)(context.Background(), "x"); got != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a listener under a uid the mail clerk does not expect: %q, %v", got, err)
	}
	admitsOther := run("b", 65533)
	if got, err := Dial(admitsOther, 65534, 5*time.Second)(context.Background(), "x"); got != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("root, calling a reader that admits only 65533: %q, %v", got, err)
	}
}

// TestModelErrorsStayClosed: a model error's text never crosses, whether it
// is a class word or holds the prompt.
func TestModelErrorsStayClosed(t *testing.T) {
	for _, e := range []error{errors.New("spam"), errors.New("the prompt was: Subject: hi"), fmt.Errorf("route: %w", context.DeadlineExceeded)} {
		path := reader(t, func(context.Context, string) (string, error) { return "spam", e }, 5*time.Second)
		ask := Dial(path, me(), 5*time.Second)
		got, err := ask(context.Background(), "Subject: hi")
		if got != "" || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "spam") || strings.Contains(err.Error(), "Subject") {
			t.Errorf("model error %q reached the mail clerk as %q, %v", e, got, err)
		}
	}
	path := reader(t, func(context.Context, string) (string, error) { return "spam", fmt.Errorf("no route: %w", ErrRefused) }, 5*time.Second)
	if got, err := Dial(path, me(), 5*time.Second)(context.Background(), "x"); got != "" || err != ErrRefused {
		t.Errorf("a refused route: %q, %v", got, err)
	}
}

// TestServeBoundsConcurrency: at most maxConns calls run at once; call
// maxConns+1 is answered busy at once, never queued, and pauses its dialer;
// once a slot frees, a call is served again. A hung model ends at the
// connection's deadline.
func TestServeBoundsConcurrency(t *testing.T) {
	var now, peak, entered atomic.Int32
	release := make(chan struct{})
	path := reader(t, func(ctx context.Context, _ string) (string, error) {
		entered.Add(1)
		n := now.Add(1)
		defer now.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		return "bulk", nil
	}, 30*time.Second)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range maxConns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := Dial(path, me(), 30*time.Second)(context.Background(), "x"); err == nil && r == "bulk" {
				ok.Add(1)
			}
		}()
	}
	for deadline := time.Now().Add(10 * time.Second); now.Load() < maxConns && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := now.Load(); n != maxConns {
		t.Fatalf("%d calls running, want %d", n, maxConns)
	}
	// Call maxConns+1, several times: each is refused busy at once, the
	// model is never entered for it, and the dialer pauses.
	for range 5 {
		a := Dial(path, me(), 30*time.Second)
		start := time.Now()
		if got, err := a(context.Background(), "x"); got != "" || !errors.Is(err, ErrBusy) {
			t.Fatalf("call %d: %q, %v", maxConns+1, got, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("the busy answer took %v", d)
		}
		if !paused(a) {
			t.Error("a busy reader did not pause the dialer")
		}
	}
	time.Sleep(100 * time.Millisecond)
	if e := entered.Load(); e != maxConns {
		t.Errorf("the model was entered %d times, want %d", e, maxConns)
	}
	close(release)
	wg.Wait()
	if ok.Load() != maxConns {
		t.Errorf("%d of %d running calls were answered", ok.Load(), maxConns)
	}
	if p := peak.Load(); p != maxConns {
		t.Errorf("%d calls ran at once, want %d", p, maxConns)
	}
	// The slots are free again: a call is served.
	for deadline := time.Now().Add(5 * time.Second); ; {
		r, err := Dial(path, me(), 5*time.Second)(context.Background(), "x")
		if err == nil && r == "bulk" {
			break
		}
		if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
			t.Fatalf("after the release: %q, %v", r, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	hung := reader(t, func(ctx context.Context, _ string) (string, error) { <-ctx.Done(); return "spam", ctx.Err() }, 300*time.Millisecond)
	start := time.Now()
	if got, err := Dial(hung, me(), 30*time.Second)(context.Background(), "x"); got != "" || !errors.Is(err, ErrUnavailable) {
		t.Errorf("a hung model: %q, %v", got, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a hung model held the call %v", d)
	}
}

// TestBusyIsReadHoweverTheConnectionEnds: a busy answer sent before the
// call is read is ErrBusy whether the reader closed before the call was
// written (the write fails with EPIPE) or after (the call lands unread and
// the answer ends in a reset); any other answer on such a connection is the
// reader's failure, and busy with bytes after it is malformed. Each order is
// forced, not raced: the dialer's write waits for the reader's close, or the
// reader waits, without reading, for the call to land.
func TestBusyIsReadHoweverTheConnectionEnds(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := map[bool]string{true: "closed before the call is written", false: "closed on the call unread"}[before]
		t.Run(name, func(t *testing.T) {
			for _, ans := range []string{`{"err":"busy"}`, `{"reply":"spam"}`} {
				path := sock(t)
				ln, err := net.Listen("unix", path)
				must(t, err)
				t.Cleanup(func() { ln.Close() })
				closed := make(chan struct{})
				go func() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					if !before {
						landed(t, c)
					}
					c.Write([]byte(ans + "\n"))
					c.Close()
					close(closed)
				}()
				var werr error
				d := newDialer(path, me(), 5*time.Second, time.Now)
				d.send = func(c net.Conn, b []byte) error {
					if before {
						<-closed
					}
					_, werr = c.Write(b)
					return werr
				}
				got, err := d.ask(context.Background(), strings.Repeat("a", MaxPrompt))
				switch {
				case before && !errors.Is(werr, syscall.EPIPE):
					t.Fatalf("%s: the call's write did not fail: %v", ans, werr)
				case !before && werr != nil:
					t.Fatalf("%s: the call's write failed: %v", ans, werr)
				}
				want := ErrUnavailable
				if ans == `{"err":"busy"}` {
					want = ErrBusy
				}
				if got != "" || !errors.Is(err, want) {
					t.Fatalf("%s: %q, %v, want %v", ans, got, err, want)
				}
				if !paused(d.ask) {
					t.Fatalf("%s did not pause", ans)
				}
			}
		})
	}
	r := rawReader(t, `{"err":"busy"}`+"\nx")
	if got, err := Dial(r.path, me(), 5*time.Second)(context.Background(), "x"); got != "" || !errors.Is(err, ErrMalformed) {
		t.Fatalf("busy with trailing data: %q, %v", got, err)
	}
}

// landed blocks until c holds unread bytes, reading none (MSG_PEEK), so
// closing c then resets its peer.
func landed(t *testing.T, c net.Conn) {
	rc, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Error(err)
		return
	}
	var b [1]byte
	rc.Read(func(fd uintptr) bool {
		n, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK)
		return n > 0 || (err != syscall.EAGAIN && err != syscall.EINTR)
	})
}

// TestADownReaderFailsFast: after the reader fails, calls fail at once with
// nothing dialled, so 200 mails cost at most one timeout; after the pause
// they dial again.
func TestADownReaderFailsFast(t *testing.T) {
	var mu sync.Mutex
	clock := time.Unix(1_000_000, 0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	const timeout = 500 * time.Millisecond

	run := func(t *testing.T, d *dialer) {
		t.Helper()
		start := time.Now()
		for i := range 200 {
			if r, err := d.ask(context.Background(), fmt.Sprint("mail ", i)); r != "" || err == nil {
				t.Fatalf("call %d: %q, %v", i, r, err)
			}
		}
		if took := time.Since(start); took > timeout+time.Second {
			t.Fatalf("200 calls to a down reader took %v", took)
		}
	}

	t.Run("no listener", func(t *testing.T) {
		d := newDialer(sock(t), me(), timeout, now)
		run(t, d)
		if _, err := d.ask(context.Background(), "x"); !errors.Is(err, ErrPaused) {
			t.Fatalf("not paused: %v", err)
		}
		advance(pause + time.Second)
		if _, err := d.ask(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("after the pause the call did not dial: %v", err)
		}
	})
	t.Run("a hung reader", func(t *testing.T) {
		r := hungReader(t)
		d := newDialer(r.path, me(), timeout, now)
		run(t, d)
		if n := r.conns.Load(); n != 1 {
			t.Fatalf("200 calls dialled %d times", n)
		}
		advance(pause - time.Second)
		if _, err := d.ask(context.Background(), "x"); !errors.Is(err, ErrPaused) {
			t.Fatalf("within the pause: %v", err)
		}
		advance(2 * time.Second)
		d.ask(context.Background(), "x")
		if n := r.conns.Load(); n != 2 {
			t.Fatalf("after the pause: %d dials, want 2", n)
		}
	})
	t.Run("unavailable and refused answers pause; too-large does not", func(t *testing.T) {
		for ans, want := range map[string]bool{`{"err":"unavailable"}`: true, `{"err":"refused"}`: true, `{"err":"too-large"}`: false, `{"reply":"spam"}`: false} {
			r := rawReader(t, ans+"\n")
			d := newDialer(r.path, me(), timeout, now)
			d.ask(context.Background(), "x")
			if got := paused(d.ask); got != want {
				t.Errorf("%s: paused %v, want %v", ans, got, want)
			}
		}
	})
	t.Run("a caller that gives up does not pause", func(t *testing.T) {
		r := hungReader(t)
		d := newDialer(r.path, me(), 30*time.Second, now)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := d.ask(ctx, "x"); err == nil {
			t.Fatal("a cancelled call succeeded")
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.until.IsZero() {
			t.Fatal("the caller's own deadline paused the reader")
		}
	})
}

// TestReaderwireLinksNoKeeperCode: D-154 rule 4, the reader links no keeper
// code through the frame: only the standard library and sockets.
func TestReaderwireLinksNoKeeperCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	must(t, err)
	const b = "github.com/ghbmrk/agentos/broker/"
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		dep := sc.Text()
		if strings.Contains(dep, ".") && !strings.HasPrefix(dep, "vendor/") && dep != b+"clerk/readerwire" && dep != b+"sockets" {
			t.Errorf("readerwire links %s", dep)
		}
		for _, no := range []string{"clerk/inbox", "kernel", "clerk/model", "infer", "localsrv"} {
			if dep == b+no || strings.HasPrefix(dep, b+no+"/") {
				t.Errorf("readerwire links keeper code %s", dep)
			}
		}
	}
}

// boundsRow prefixes the ASSUMPTIONS.md rows that record each fixed bound
// with its basis (RES-5-readerwire-maxconns-1 and -2).
const boundsRow = "| RES-5-readerwire-maxconns-"

// boundProblems lists every constant in srcs (file name to Go source, the
// package's non-test files) that is not a recorded package-level bound: a
// package-level constant not named in backticks in one of rec's bounds rows
// (a mention in any other row or in prose does not count), and every
// constant declared inside a function, which no record can clear: it is
// reported as shadowing when a package-level constant has its name, and is
// otherwise told to move to package level. Only the frame's own names,
// readerwire.go's package-level version and opRead, are exempt. A number
// written outside a const is constProblems' check (bounds_test.go).
func boundProblems(t *testing.T, srcs map[string]string, rec string) []string {
	t.Helper()
	var rows strings.Builder
	for _, line := range strings.Split(rec, "\n") {
		if strings.HasPrefix(line, boundsRow) {
			rows.WriteString(line)
		}
	}
	if rows.Len() == 0 {
		return []string{"ASSUMPTIONS.md has no " + strings.TrimPrefix(boundsRow, "| ") + " row"}
	}
	recorded := func(name string) bool { return strings.Contains(rows.String(), "`"+name+"`") }
	var out []string
	var n int
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	pkgConsts := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		f, err := parser.ParseFile(fset, name, srcs[name], 0)
		must(t, err)
		files[name] = f
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, sp := range g.Specs {
					for _, id := range sp.(*ast.ValueSpec).Names {
						pkgConsts[id.Name] = true
					}
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		f := files[name]
		top := map[ast.Decl]bool{}
		for _, d := range f.Decls {
			top[d] = true
		}
		ast.Inspect(f, func(node ast.Node) bool {
			x, ok := node.(*ast.GenDecl)
			if !ok || x.Tok != token.CONST {
				return true
			}
			for _, sp := range x.Specs {
				for _, id := range sp.(*ast.ValueSpec).Names {
					if top[x] && name == "readerwire.go" && (id.Name == "version" || id.Name == "opRead") {
						continue // the frame's own names, not bounds
					}
					n++
					switch {
					case !top[x] && pkgConsts[id.Name]:
						out = append(out, fmt.Sprintf("%s: the local const %s shadows the package's bound %s: use the package's own", fset.Position(id.Pos()), id.Name, id.Name))
					case !top[x]:
						out = append(out, fmt.Sprintf("%s: the local const %s is a bound no record can clear: move it to package level and name it in a %s row", fset.Position(id.Pos()), id.Name, boundsRow))
					case !recorded(id.Name):
						out = append(out, fmt.Sprintf("the bound %s has no record in a %s row", id.Name, boundsRow))
					}
				}
			}
			return false
		})
	}
	if n == 0 {
		out = append(out, "no bounds found")
	}
	return out
}

// packageSources reads every non-test Go file in the package.
func packageSources(t *testing.T) map[string]string {
	t.Helper()
	return goSources(t, ".")
}

// goSources reads every non-test Go file in dir.
func goSources(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	must(t, err)
	srcs := map[string]string{}
	for _, e := range ents {
		if name := e.Name(); strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			b, err := os.ReadFile(filepath.Join(dir, name))
			must(t, err)
			srcs[name] = string(b)
		}
	}
	return srcs
}

// TestEveryBoundIsRecorded: every fixed bound in the package's non-test files
// is a constant named in an ASSUMPTIONS.md bounds row with its basis
// (RES-5-readerwire-maxconns-*), so a new cap cannot land without one: not
// as a literal, not in a new file, and not recorded only in another row.
// REQ: RES-5
func TestEveryBoundIsRecorded(t *testing.T) {
	rec, err := os.ReadFile("ASSUMPTIONS.md")
	must(t, err)
	srcs := packageSources(t)
	if _, ok := srcs["readerwire.go"]; !ok {
		t.Fatal("readerwire.go not read")
	}
	for _, p := range boundProblems(t, srcs, string(rec)) {
		t.Error(p)
	}
}

// TestEveryNonTestFileIsRead: the check reads each non-test Go file in the
// directory, and no test file or other file.
func TestEveryNonTestFileIsRead(t *testing.T) {
	d := t.TempDir()
	for _, n := range []string{"a.go", "b.go", "c_test.go", "notes.md"} {
		must(t, os.WriteFile(filepath.Join(d, n), []byte("package readerwire\n"), 0o600))
	}
	var got []string
	for n := range goSources(t, d) {
		got = append(got, n)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a.go", "b.go"}) {
		t.Fatalf("read %q, want a.go and b.go", got)
	}
}

// TestAcceptBackoff: a failed accept sleeps acceptBackoffMin, then twice the
// last sleep up to acceptBackoffMax, and a successful accept starts it over.
// REQ: RES-5
func TestAcceptBackoff(t *testing.T) {
	fail := errors.New("accept: too many open files")
	ms := time.Millisecond
	ln := &scriptedListener{steps: []error{fail, fail, fail, fail, fail, fail, fail, fail, fail, fail, nil, fail, fail, net.ErrClosed}}
	var slept []time.Duration
	model := func(context.Context, string) (string, error) { return "", nil }
	must(t, serve(ln, model, time.Second, func(d time.Duration) { slept = append(slept, d) }))
	want := []time.Duration{5 * ms, 10 * ms, 20 * ms, 40 * ms, 80 * ms, 160 * ms, 320 * ms, 640 * ms, time.Second, time.Second, 5 * ms, 10 * ms}
	if !slices.Equal(slept, want) {
		t.Fatalf("slept %v, want %v", slept, want)
	}
}

// scriptedListener answers each Accept with its next step: that error, or
// for nil a connection whose peer has already hung up.
type scriptedListener struct{ steps []error }

func (l *scriptedListener) Accept() (net.Conn, error) {
	err := l.steps[0]
	l.steps = l.steps[1:]
	if err != nil {
		return nil, err
	}
	c, peer := net.Pipe()
	peer.Close()
	return c, nil
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return nil }

// TestTheBoundsRecordCatchesEachGap: each record gap #4849 and #4874 name
// fails the check, starting from the package as it stands; the gaps written
// as numbers are TestEachConstantFormFails' cases.
func TestTheBoundsRecordCatchesEachGap(t *testing.T) {
	b, err := os.ReadFile("ASSUMPTIONS.md")
	must(t, err)
	rec := string(b)
	// unrecord drops the backticks around each name in the bounds rows only.
	unrecord := func(names ...string) string {
		lines := strings.Split(rec, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, boundsRow) {
				for _, n := range names {
					line = strings.ReplaceAll(line, "`"+n+"`", n)
				}
				lines[i] = line
			}
		}
		return strings.Join(lines, "\n")
	}
	withFile := func(name, src string) map[string]string {
		srcs := packageSources(t)
		srcs[name] = src
		return srcs
	}
	cases := []struct {
		name string
		srcs map[string]string
		rec  string
		want []string
	}{
		{"named only in another row", packageSources(t),
			unrecord("MaxReply") + "| OTHER-1 | `MaxReply` is named here only. | - | - |\n",
			[]string{"the bound MaxReply has no record"}},
		{"named only in prose", packageSources(t),
			unrecord("maxConns") + "\nSee `maxConns`.\n",
			[]string{"the bound maxConns has no record"}},
		{"an unrecorded constant in a new file", withFile("extra.go", "package readerwire\n\nconst maxExtra = 3\n"), rec,
			[]string{"the bound maxExtra has no record"}},
		{"a constant inside a function", withFile("extra.go", "package readerwire\n\nfunc f() int {\n\tconst maxLocal = 3\n\treturn maxLocal\n}\n"), rec,
			[]string{"extra.go:4:8: the local const maxLocal is a bound no record can clear: move it to package level"}},
		{"a constant inside a function, recorded", withFile("extra.go", "package readerwire\n\nfunc f() int {\n\tconst maxLocal = 3\n\treturn maxLocal\n}\n"),
			strings.Replace(rec, boundsRow+"2 |", boundsRow+"2 | `maxLocal`", 1),
			[]string{"extra.go:4:8: the local const maxLocal is a bound no record can clear: move it to package level"}},
		{"the backoff constants lose their record", packageSources(t), unrecord("acceptBackoffMin", "acceptBackoffMax"),
			[]string{"the bound acceptBackoffMin has no record", "the bound acceptBackoffMax has no record"}},
		{"a local const shadowing a recorded name", withFile("extra.go", "package readerwire\n\nfunc f() int {\n\tconst maxConns = 4096\n\treturn maxConns\n}\n"), rec,
			[]string{"extra.go:4:8: the local const maxConns shadows the package's bound maxConns"}},
		{"a cap named version inside a function", withFile("extra.go", "package readerwire\n\nfunc f() int {\n\tconst version = 4096\n\treturn version\n}\n"), rec,
			[]string{"extra.go:4:8: the local const version shadows the package's bound version"}},
		{"no constants at all", map[string]string{"readerwire.go": "package readerwire\n"}, rec,
			[]string{"no bounds found"}},
		{"no bounds rows", packageSources(t), strings.ReplaceAll(rec, boundsRow, "| RES-5-other-"),
			[]string{"ASSUMPTIONS.md has no RES-5-readerwire-maxconns- row"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := boundProblems(t, c.srcs, c.rec)
			if len(got) != len(c.want) {
				t.Fatalf("problems = %q, want %d matching %q", got, len(c.want), c.want)
			}
			for _, w := range c.want {
				var hit bool
				for _, g := range got {
					hit = hit || strings.HasPrefix(g, w)
				}
				if !hit {
					t.Errorf("problems = %q, want one starting %q", got, w)
				}
			}
		})
	}
}
