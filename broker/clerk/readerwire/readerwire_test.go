package readerwire

// REQ: PLN-2, D-154, D-158, CLK-7

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
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
	go serve(ln, model, timeout)
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

// TestReadRoundTrip: a fake model's class word comes back as the reply, and
// inbox.Read over it classes the mail.
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
	mails := inbox.Read(context.Background(), inbox.Ask(ask), []inbox.Mail{{Raw: []byte("Subject: win\r\n\r\nbuy now")}})
	if len(mails) != 1 || mails[0].Class != "spam" {
		t.Fatalf("inbox.Read over the frame: %+v", mails)
	}
	if !strings.HasSuffix(got, "buy now") {
		t.Fatalf("the reader did not get the mail: %q", got)
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
		mails := inbox.Read(context.Background(), inbox.Ask(Dial(path, me(), 5*time.Second)), []inbox.Mail{{Raw: []byte("Subject: hi\r\n\r\n")}})
		if mails[0].Class != "" {
			t.Errorf("model error %q classed the mail %q", e, mails[0].Class)
		}
	}
	path := reader(t, func(context.Context, string) (string, error) { return "spam", fmt.Errorf("no route: %w", ErrRefused) }, 5*time.Second)
	if got, err := Dial(path, me(), 5*time.Second)(context.Background(), "x"); got != "" || err != ErrRefused {
		t.Errorf("a refused route: %q, %v", got, err)
	}
}

// TestServeBoundsConcurrency: at most eight calls run at once, and a hung
// model ends at the connection's deadline.
func TestServeBoundsConcurrency(t *testing.T) {
	var now, peak atomic.Int32
	release := make(chan struct{})
	path := reader(t, func(ctx context.Context, _ string) (string, error) {
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
	for range 20 {
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
	time.Sleep(200 * time.Millisecond)
	if p := peak.Load(); p != maxConns {
		t.Errorf("%d calls ran at once, want %d", p, maxConns)
	}
	close(release)
	wg.Wait()
	if ok.Load() != 20 {
		t.Errorf("%d of 20 waiting calls were answered", ok.Load())
	}
	if peak.Load() > maxConns {
		t.Errorf("%d calls ran at once", peak.Load())
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
