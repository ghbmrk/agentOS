package gmailtest

import (
	"context"
	"strings"
	"testing"
)

//go:noinline
func parkIn(c chan struct{}) { <-c }

//go:noinline
func parkElsewhere(c chan struct{}) { <-c }

// spin waits, bounded by a 30 s context as a backstop for a hang, until ok.
func spin(t *testing.T, what string, ok func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30e9)
	defer cancel()
	for !ok() {
		if ctx.Err() != nil {
			t.Fatalf("%s was not seen within the backstop", what)
		}
	}
}

// A goroutine an earlier test leaked, parked in the very function a test
// waits on, does not pass for the goroutine under test: G.Waiting reads
// only its own goroutine's stack (#5694, gmailtest.Waiting matching any
// goroutine). The process-wide Waiting is the control that the leaked one
// is parked there.
func TestWaitingIsTheGoroutineUnderTestOnly(t *testing.T) {
	leak, other, own := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(leak)
	go parkIn(leak)
	spin(t, "the leaked goroutine parked in parkIn", func() bool { return Waiting("gmailtest.parkIn", "chan receive") })
	g := Go(func() { parkElsewhere(other) })
	spin(t, "the goroutine under test parked in parkElsewhere", func() bool { return g.Waiting("gmailtest.parkElsewhere", "chan receive") })
	if g.Waiting("gmailtest.parkIn", "chan receive") {
		t.Fatal("a leaked goroutine parked in parkIn satisfied Waiting for the goroutine under test")
	}
	if g.Waiting("gmailtest.parkElsewhere", "sync.Mutex.Lock") {
		t.Fatal("Waiting matched a wait reason the goroutine under test is not blocked on")
	}
	close(other)
	h := Go(func() { parkIn(own) })
	defer close(own)
	spin(t, "the goroutine under test parked in parkIn", func() bool { return h.Waiting("gmailtest.parkIn", "chan receive") })
}

// Self covers the goroutines the test started, through others still
// running, and none whose creator has exited, as an earlier test's leaked
// goroutine's has (#5694).
func TestSelfIsWhatTheTestStarted(t *testing.T) {
	leak, own := make(chan struct{}), make(chan struct{})
	defer close(leak)
	defer close(own)
	creator := Go(func() { go parkIn(leak) })
	spin(t, "the leaked goroutine parked in parkIn", func() bool { return Waiting("gmailtest.parkIn", "chan receive") })
	spin(t, "the leaked goroutine's creator exiting", func() bool { return !alive(creator.id) })
	self := Self()
	if self.Waiting("gmailtest.parkIn", "chan receive") {
		t.Fatal("a goroutine whose creator has exited passed for one the test started")
	}
	Go(func() { go parkIn(own); <-own }) // the middle goroutine stays running
	spin(t, "the test's own goroutine's goroutine parked in parkIn", func() bool { return self.Waiting("gmailtest.parkIn", "chan receive") })
}

// alive is whether the goroutine numbered id is in the runtime's dump.
func alive(id string) bool {
	for _, g := range strings.Split(stacks(true), "\n\n") {
		if goID(g) == id {
			return true
		}
	}
	return false
}

// goID reads the number of a dump's header line and nothing else.
func TestGoIDReadsTheHeaderNumber(t *testing.T) {
	for in, want := range map[string]string{
		"goroutine 18 [chan receive]:\nmain.f()": "18",
		"goroutine 7 gp=0x1 m=nil [running]:":    "7",
		"goroutines 7 [running]:":                "",
		"goroutine":                              "",
		"":                                       "",
	} {
		if got := goID(in); got != want {
			t.Errorf("goID(%q) = %q; want %q", in, got, want)
		}
	}
}
