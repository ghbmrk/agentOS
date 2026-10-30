package radio

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2

// allOps is every op this package names, plus ops no stack may ever take:
// the wide interface the test catches.
var allOps = []Op{OpRead, OpOn, OpOff, OpLevel, OpLock, OpShut, OpClose, OpReturnToDock,
	OpConnect, OpDisconnect, OpWrite, OpSubscribe,
	"unlock", "disarm", "open", "raw-hci", "scan", "pair", "set-pin", "policy", ""}

// recorder is a connection that counts what the host wrote and answers
// each request as a stack would.
type recorder struct {
	host, stack net.Conn
	mu          sync.Mutex
	got         []Request
}

func newRecorder(t *testing.T, s Stack) *recorder {
	r := &recorder{}
	r.host, r.stack = net.Pipe()
	srv := NewServer(s, r.stack)
	go srv.Serve(func(q Request) ([]byte, Code) {
		r.mu.Lock()
		r.got = append(r.got, q)
		r.mu.Unlock()
		return []byte("ok"), CodeOK
	})
	t.Cleanup(func() { r.host.Close() })
	return r
}

func (r *recorder) requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

var scale = Device{Name: "scale", Stack: StackBLE, Chars: []string{"00000001-0000-1000-8000-00805f9b34fb"}}

func newHost(t *testing.T, logs *[]string) *Host {
	h, err := NewHost(Config{Devices: []Device{scale}, Notify: func(Notification) {},
		Log: func(s string) { *logs = append(*logs, s) }, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestOnlyDeclaredOps (NET-2 Confined radio stacks): a stack is asked only
// for the ops it declares, on the devices and characteristics the policy
// gives it. The host refuses anything else before a byte reaches the
// stack, and the stack's server refuses it again when it arrives anyway.
// Catches a wide radio interface.
func TestOnlyDeclaredOps(t *testing.T) {
	t.Run("declaration", func(t *testing.T) {
		// Widening a stack's declaration is a change to this line.
		if want := []Op{OpRead, OpConnect, OpDisconnect, OpWrite, OpSubscribe}; !slices.Equal(Declared[StackBLE], want) {
			t.Fatalf("BLE declares %v, want %v", Declared[StackBLE], want)
		}
		if len(Declared) != 1 {
			t.Fatalf("stacks %v: a new stack comes with its own test", Declared)
		}
	})

	t.Run("host", func(t *testing.T) {
		for _, op := range allOps {
			var logs []string
			h := newHost(t, &logs)
			rec := newRecorder(t, StackBLE)
			h.Attach(StackBLE, rec.host)
			req := Request{Op: op, Device: scale.Name}
			switch op {
			case OpWrite:
				req.Char, req.Data = scale.Chars[0], []byte{1}
			case OpSubscribe:
				req.Char = scale.Chars[0]
			case OpLevel:
				req.Level = 50
			}
			_, err := h.Call(req)
			sent := len(rec.requests())
			if Declares(StackBLE, op) {
				if err != nil || sent != 1 {
					t.Errorf("%q: err %v, %d sent; a declared op must reach the stack", op, err, sent)
				}
				continue
			}
			if !errors.Is(err, ErrNotDeclared) || sent != 0 || len(logs) == 0 {
				t.Errorf("%q: err %v, %d sent, logs %v; want refused, logged, nothing sent", op, err, sent, logs)
			}
		}
	})

	t.Run("channel verbs", func(t *testing.T) {
		// BLE declares no device verb, so every channel command to a BLE
		// device is refused at the host.
		var logs []string
		h := newHost(t, &logs)
		rec := newRecorder(t, StackBLE)
		h.Attach(StackBLE, rec.host)
		for v := wire.Verb(0); v < 16; v++ {
			if err := h.Do(scale.Name, v, 0); !errors.Is(err, ErrNotDeclared) {
				t.Errorf("verb %d: %v", v, err)
			}
		}
		if got, err := h.State(scale.Name); err != nil || string(got) != "ok" {
			t.Errorf("State: %q %v", got, err)
		}
		if n := len(rec.requests()); n != 1 {
			t.Errorf("%d requests reached the stack, want the one read", n)
		}
	})

	t.Run("device and characteristic", func(t *testing.T) {
		var logs []string
		h := newHost(t, &logs)
		rec := newRecorder(t, StackBLE)
		h.Attach(StackBLE, rec.host)
		for _, req := range []Request{
			{Op: OpRead, Device: "lock"},
			{Op: OpWrite, Device: scale.Name, Char: "00002a19-0000-1000-8000-00805f9b34fb", Data: []byte{1}},
			{Op: OpSubscribe, Device: scale.Name, Char: "00002a19-0000-1000-8000-00805f9b34fb"},
			{Op: OpWrite, Device: scale.Name, Data: []byte{1}},
			{Op: OpRead, Device: scale.Name, Data: []byte{1}},
			{Op: OpWrite, Device: scale.Name, Char: scale.Chars[0], Data: make([]byte, MaxData+1)},
			{Op: OpConnect, Device: scale.Name, Level: 3},
		} {
			if _, err := h.Call(req); err == nil {
				t.Errorf("%+v accepted", req)
			}
		}
		if n := len(rec.requests()); n != 0 {
			t.Errorf("%d refused requests reached the stack", n)
		}
	})

	t.Run("server", func(t *testing.T) {
		// A request that skips the host (a bug, or a later caller) is
		// refused by the stack's server, and its handler never runs.
		host, stack := net.Pipe()
		defer host.Close()
		var handled []Op
		go NewServer(StackBLE, stack).Serve(func(q Request) ([]byte, Code) {
			handled = append(handled, q.Op)
			return nil, CodeOK
		})
		for i, op := range allOps {
			if err := write(host, Request{ID: uint64(i + 1), Op: op, Device: scale.Name}); err != nil {
				t.Fatal(err)
			}
			var u Up
			if err := read(host, &u); err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains([]Op{OpRead, OpConnect, OpDisconnect}, op); (u.Code == CodeOK) != want {
				t.Errorf("%q: code %d", op, u.Code)
			}
		}
		if want := []Op{OpRead, OpConnect, OpDisconnect}; !slices.Equal(handled, want) {
			t.Errorf("handler ran for %v, want %v", handled, want)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		host, stack := net.Pipe()
		defer host.Close()
		done := make(chan error, 1)
		go func() {
			done <- NewServer(StackBLE, stack).Serve(func(Request) ([]byte, Code) { return nil, CodeOK })
		}()
		raw := []byte(`{"ID":1,"Op":"read","Device":"scale","Verb":"unlock"}`)
		host.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw))))
		host.Write(raw)
		if err := <-done; !errors.Is(err, ErrMalformed) {
			t.Fatalf("serve ended with %v, want ErrMalformed", err)
		}
	})
}

// TestHostEndsLinkOnBadStack (NET-2 Confined radio stacks): a stack that
// answers what nobody asked, notifies for a device or characteristic it
// does not serve, or sends a malformed frame loses its link, and later
// calls fail rather than reading its output.
func TestHostEndsLinkOnBadStack(t *testing.T) {
	for name, up := range map[string]any{
		"unasked answer":        Up{ID: 99, Code: CodeOK, Device: scale.Name},
		"other device":          Up{Device: "lock", Char: scale.Chars[0], Data: []byte{1}},
		"undeclared char":       Up{Device: scale.Name, Char: "x", Data: []byte{1}},
		"answer with char":      Up{ID: 1, Code: CodeOK, Device: scale.Name, Char: "x"},
		"unknown code":          Up{ID: 1, Code: 9, Device: scale.Name},
		"unknown field":         json.RawMessage(`{"Device":"scale","Char":"00000001-0000-1000-8000-00805f9b34fb","Op":"unlock"}`),
		"oversize notification": Up{Device: scale.Name, Char: scale.Chars[0], Data: make([]byte, MaxData+1)},
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var logs []string
			var notes []Notification
			h, _ := NewHost(Config{Devices: []Device{scale}, Timeout: time.Second,
				Notify: func(n Notification) { mu.Lock(); notes = append(notes, n); mu.Unlock() },
				Log:    func(s string) { mu.Lock(); logs = append(logs, s); mu.Unlock() }})
			host, stack := net.Pipe()
			h.Attach(StackBLE, host)
			b, _ := json.Marshal(up)
			stack.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
			stack.Write(b)
			if _, err := io.ReadAll(stack); err != nil {
				t.Fatal(err)
			}
			if _, err := h.State(scale.Name); !errors.Is(err, ErrNoStack) {
				t.Errorf("after a bad message, State: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(notes) != 0 || len(logs) == 0 {
				t.Errorf("notes %v logs %v", notes, logs)
			}
		})
	}
}

// FuzzUp: no input from a stack panics the host's decoder or passes its
// checks with an out-of-bounds field.
func FuzzUp(f *testing.F) {
	f.Add([]byte(`{"ID":1,"Code":1,"Device":"scale","Data":"AQ=="}`))
	f.Add([]byte(`{"Device":"scale","Char":"c","Data":"AQ=="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var u Up
		if decode(b, &u) != nil || u.check() != nil {
			return
		}
		if !name(u.Device) || len(u.Data) > MaxData || (u.ID != 0 && (u.Code < CodeOK || u.Code > CodeUnreachable)) {
			t.Fatalf("passed: %+v", u)
		}
	})
}

// TestStackThatStopsReadingCannotWedgeHost (NET-2 Confined radio stacks,
// ENF-k-8): a stack that never reads its end has a full socket, and Call
// still returns within about Config.Timeout, so one exploited stack cannot
// hold the channel's lock. The buffer is filled before the first call, so
// only the write deadline can bound it (no timeout count ends the link
// first). From the Security and L3 probes on #3908.
func TestStackThatStopsReadingCannotWedgeHost(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(fds[1]), "theirs") // never read
	defer theirs.Close()
	syscall.SetNonblock(fds[0], true)
	fill := make([]byte, 64<<10)
	for {
		if _, err := syscall.Write(fds[0], fill); err == syscall.EAGAIN {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	h, err := NewHost(Config{Devices: []Device{scale}, Notify: func(Notification) {}, Log: func(string) {},
		Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	h.Attach(StackBLE, os.NewFile(uintptr(fds[0]), "ours"))
	done := make(chan error, 1)
	go func() { _, err := h.State(scale.Name); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoStack) {
			t.Fatalf("a full link answered %v; want ErrNoStack from the write deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the call blocked past 2s with a 5ms timeout: the write is not bounded")
	}
}

// TestAnswerEdges (ENF-k-6): a waiter whose answer names another device
// fails at once with the link, not after its timeout; an answer that
// arrives after its request timed out is dropped and the link stays.
func TestAnswerEdges(t *testing.T) {
	newLink := func(timeout time.Duration) (*Host, net.Conn) {
		h, _ := NewHost(Config{Devices: []Device{scale, {Name: "lamp", Stack: StackBLE}}, Timeout: timeout,
			Notify: func(Notification) {}, Log: func(string) {}})
		host, stack := net.Pipe()
		h.Attach(StackBLE, host)
		return h, stack
	}
	t.Run("wrong device", func(t *testing.T) {
		h, stack := newLink(time.Minute)
		defer stack.Close()
		go func() {
			var r Request
			read(stack, &r)
			write(stack, Up{ID: r.ID, Code: CodeOK, Device: "lamp"})
		}()
		start := time.Now()
		if _, err := h.State(scale.Name); !errors.Is(err, ErrNoStack) || time.Since(start) > 10*time.Second {
			t.Fatalf("err %v after %v; want ErrNoStack at once", err, time.Since(start))
		}
	})
	t.Run("late answer", func(t *testing.T) {
		h, stack := newLink(50 * time.Millisecond)
		defer stack.Close()
		first := make(chan uint64, 1)
		go func() {
			var r Request
			read(stack, &r)
			first <- r.ID
		}()
		if _, err := h.State(scale.Name); !errors.Is(err, ErrTimeout) {
			t.Fatalf("first call: %v", err)
		}
		if err := write(stack, Up{ID: <-first, Code: CodeOK, Device: scale.Name}); err != nil {
			t.Fatal(err)
		}
		go func() {
			var r Request
			read(stack, &r)
			write(stack, Up{ID: r.ID, Code: CodeOK, Device: scale.Name, Data: []byte("ok")})
		}()
		if got, err := h.State(scale.Name); err != nil || string(got) != "ok" {
			t.Fatalf("after a late answer: %q %v; the link should stay", got, err)
		}
	})
}
