package proc

// REQ: CLK-1, LOG-7

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The kernel sends no byte of a call to a clerk socket served by another uid.
func TestACallReachesNoClerkOfAnotherUID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "c.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(make([]byte, 1))
		got <- n
	}()
	r := remote{Remote: Remote{Socket: sock, UID: os.Getuid() + 1, Timeout: 5 * time.Second}}
	if a, sent, big := r.call("do", kernel.Request{}, snapshot{}); a != nil || sent || big {
		t.Fatalf("answer %v, sent %v, big %v", a, sent, big)
	}
	if n := <-got; n != 0 {
		t.Fatalf("the other uid's socket read %d bytes", n)
	}
}

// A clerk's detail reaches the log only bounded, valid and free of control
// characters, since STATUS shows it to the owner.
func TestDetailKeepsOnlyAPrintableBoundedLine(t *testing.T) {
	for in, want := range map[string]string{
		"sent":                           "sent",
		strings.Repeat("a", maxDetail):   strings.Repeat("a", maxDetail),
		strings.Repeat("a", maxDetail+1): "malformed",
		"bad\xff":                        "malformed",
		"two\nlines":                     "malformed",
		"bell\a":                         "malformed",
	} {
		if got := detail(in); got != want {
			t.Errorf("detail(%q) = %q, want %q", in, got, want)
		}
	}
}

// A day cap's view keeps a use made just inside the day and its skew, and no
// use made at its edge or before.
func TestADayCapsViewEndsAtTheDayAndItsSkew(t *testing.T) {
	const now = 10 * key.DayMS
	edge := now - key.DayMS - viewSkew
	all := []key.Use{{At: edge - 1}, {At: edge}, {At: edge + 1}}
	got := needed(all, []key.Cap{{Scope: key.ID{1}, Kind: key.KRateDay, N: 9}}, key.ID{1}, "", now)
	if len(got) != 1 || got[0].At != edge+1 {
		t.Fatalf("the view kept %+v, want only the use inside the window", got)
	}
}

// A kernel with no anchor or no head key is refused before its log is
// opened, so nothing is written for it.
func TestAKernelWithoutAnchorOrHeadKeyOpensNoLog(t *testing.T) {
	for name, cfg := range map[string]KernelConfig{
		"no anchor":   {Pub: headPub, Sign: headPriv},
		"no head key": {Anchor: &kernel.MemAnchor{}, Pub: headPub},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Log = filepath.Join(t.TempDir(), "log")
			if _, err := OpenKernel(cfg, 0); err == nil {
				t.Fatal("opened")
			}
			if _, err := os.Lstat(cfg.Log); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the log path after the refusal: %v", err)
			}
		})
	}
}

// A log that cannot be opened, or whose anchor it cannot verify, opens no
// kernel, and the refusal names why.
func TestAKernelOnABadLogIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  KernelConfig
		want error
	}{
		"no such directory":  {KernelConfig{Log: filepath.Join(t.TempDir(), "gone", "log"), Anchor: &kernel.MemAnchor{}}, os.ErrNotExist},
		"an unsigned anchor": {KernelConfig{Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{H: kernel.Head{Seq: 5}, Ok: true}}, kernel.ErrCorrupt},
	} {
		t.Run(name, func(t *testing.T) {
			c.cfg.Pub, c.cfg.Sign = headPub, headPriv
			if _, err := OpenKernel(c.cfg, 0); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// A closed log file answers every read and write with an error.
func TestAClosedLogFileRefuses(t *testing.T) {
	st, err := OpenFileStore(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := st.ReadAll(); err == nil {
		t.Fatal("read a closed log")
	}
	if err := st.Append([]byte("x")); err == nil {
		t.Fatal("appended to a closed log")
	}
}

// viewClerk records the view each Do is given.
type viewClerk struct{ got chan kernel.View }

func (c viewClerk) Do(_ kernel.Request, v kernel.View) kernel.Result {
	c.got <- v
	return kernel.Result{Outcome: "ok"}
}
func (viewClerk) Probe(kernel.Request, kernel.View) kernel.Result { return kernel.Result{} }

// Tick hands the clerk the view of the step it sends: its dispatch, as the
// log holds it, and a ledger entry for every scope the chain charges.
func TestTickSendsTheStepsOwnView(t *testing.T) {
	c := viewClerk{make(chan kernel.View, 1)}
	b := newBox(t, serveFake(t, c))
	id := b.submit("dave")
	b.tick(b.now)
	var req kernel.Request
	var seq uint64 // the step's dispatch entry
	b.h.With(func(k *kernel.Kernel) error {
		req = kernel.Request{Plan: k.State().Plans[id].Plan}
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TStepDispatch {
				seq = e.Seq
			}
		}
		return nil
	})
	var v kernel.View
	select {
	case v = <-c.got:
	default:
		t.Fatal("the clerk was not called")
	}
	if d, ok := v.Dispatched(req); !ok || seq == 0 || d.Seq != seq {
		t.Fatalf("the clerk got dispatch %+v %v, want the one at entry %d", d, ok, seq)
	}
	ver, err := kernel.VerifyPlan(req.Plan, anchors)
	if err != nil {
		t.Fatal(err)
	}
	if !v.(*snapshot).covers(anchors, req) || len(ver.Scopes()) == 0 {
		t.Fatalf("the clerk's view leaves out a scope of %d", len(ver.Scopes()))
	}
}

// notSent is a view whose request was never dispatched.
type notSent struct{ *fakeView }

func (notSent) Dispatched(kernel.Request) (kernel.Dispatch, bool) { return kernel.Dispatch{}, false }

// A view of a step the log never dispatched carries no dispatch and no
// ledger, so the clerk refuses it; and covers asks a ledger only of a view
// with a dispatch, and of a plan that verifies.
func TestAViewOfAnUnsentStepCarriesNoDispatch(t *testing.T) {
	b := newBox(t, filepath.Join(t.TempDir(), "unused.sock"))
	id := b.submit("dave")
	var req kernel.Request
	b.h.With(func(k *kernel.Kernel) error { req = kernel.Request{Plan: k.State().Plans[id].Plan}; return nil })
	ver, err := kernel.VerifyPlan(req.Plan, anchors)
	if err != nil || len(ver.Scopes()) == 0 {
		t.Fatalf("verify: %v, %d scopes", err, len(ver.Scopes()))
	}
	f := &fakeView{grants: map[key.ID]int64{}, ledger: map[key.ID][]key.Use{}, dispatch: kernel.Dispatch{Seq: 3}}
	s := view(notSent{f}, anchors, nil, req, b.now)
	if s.Dispatch != nil || len(s.Ledger) != 0 {
		t.Fatalf("an unsent step's view: dispatch %v, ledger %v", s.Dispatch, s.Ledger)
	}
	if !s.covers(anchors, req) {
		t.Fatal("covers asked a ledger of a view with no dispatch")
	}
	s.Dispatch = &kernel.Dispatch{Seq: 3}
	if s.covers(anchors, req) {
		t.Fatal("covers took a dispatched view with no ledger")
	}
	if !s.covers(nil, req) {
		t.Fatal("covers judged the ledger of a plan that does not verify")
	}
}

// A call with no arguments goes out as an empty object, so an op that
// takes arguments decodes them all as unset.
func TestACallWithNoArgumentsSendsAnEmptyObject(t *testing.T) {
	sock := filepath.Join(shortDir(t), "k.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		ServeOne(conn, func(_ string, args json.RawMessage) (json.RawMessage, error) {
			got <- string(args)
			return nil, nil
		})
	}()
	if err := (Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}).Call("status", nil, nil); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != "{}" {
		t.Fatalf("nil arguments went out as %s", a)
	}
}
