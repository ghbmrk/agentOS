package proc

// REQ: KRN-6, KRN-7, LOG-1, CLK-2

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// endless is the log's file with its end lost: Seek fails, writes would land.
type endless struct{ *os.File }

// noEnd is the error endless gives.
type noEnd struct{}

func (noEnd) Error() string { return "seek refused" }

func (endless) Seek(int64, int) (int64, error) { return 0, noEnd{} }

// An append that cannot find the log's end writes nothing: a write at a
// guessed offset would overwrite the entries already there (LOG-1).
func TestAppendWithoutTheEndWritesNothing(t *testing.T) {
	s, err := OpenFileStore(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Append([]byte("first")); err != nil {
		t.Fatal(err)
	}
	f := s.f.(*os.File)
	s.f = endless{f}
	if err := s.Append([]byte("x")); !errors.Is(err, noEnd{}) {
		t.Fatalf("append with no end: %v, want %v", err, noEnd{})
	}
	b, err := os.ReadFile(f.Name())
	if err != nil || string(b) != "first" {
		t.Fatalf("log holds %q (%v), want only the first append", b, err)
	}
}

// A re-seal asked of a closed kernel is refused, not handed nothing to wait
// on as if none were due.
func TestResealAfterCloseIsRefused(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	b.h.Close()
	if wg, err := b.h.reseal(b.now); err == nil {
		t.Fatalf("reseal on a closed kernel: %v, nil, want an error", wg)
	}
}

// A dispatch through the kernel process reaches the clerk with its view and
// the step ends done (CLK-2); a call naming no known op gets no answer at
// all, never one the clerk ran.
func TestClerkTakesTheViewAndAnswersOnlyKnownOps(t *testing.T) {
	sock := serveFake(t, fakeClerk{do: func() kernel.Result { return kernel.Result{Outcome: "ok"} }})
	b := newBox(t, sock)
	id := b.submit("dave")
	// The kernel's own Tick calls the clerk as the kernel.Clerk the process
	// booted it with, its view verified against the state's anchors.
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Tick(b.now) }); err != nil {
		t.Fatal(err)
	}
	if st := b.step(id); st.Phase != kernel.PDone {
		t.Fatalf("step is %s, want done", st.Phase)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte(`{"op":"bogus","req":{},"view":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(conn); err != nil || len(got) != 0 {
		t.Fatalf("an unknown op was answered %q (%v), want nothing", got, err)
	}
}

// The process pins the configured checker into the kernel: an approval
// then meets the checker's key check, not "no checker".
func TestOpenPinsTheChecker(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	b.h.Close()
	b.cfg.Checker = headPub
	b.open()
	err := b.h.With(func(k *kernel.Kernel) error { return k.ApproveCode(b.now, kernel.CodeApproval{}) })
	if !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("approval with a checker pinned: %v, want %v", err, kernel.ErrCodeApproval)
	}
}
