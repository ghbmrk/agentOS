package modemlink

import (
	"context"
	"fmt"
	"github.com/ghbmrk/agentos/broker/control"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-1

// A text agentosd asks the owner channel to send, lost to the down line,
// is logged naming agentosd's own caller, not the channel's wrappers
// (#2349): the channel's frames are skipped as the Link's are.
func TestAMissedSendThroughTheOwnerChannelNamesItsSender(t *testing.T) {
	var logged []string
	l := New(Config{Owner: ownerNum, Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }})
	st := &owner.MemStore{}
	if err := st.Save(owner.State{Pacing: owner.Pacing{PerHour: owner.MaxTextsPerHour, Urgent: []owner.Class{owner.ClassApproval}}}); err != nil {
		t.Fatal(err)
	}
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: l, Engine: idleEngine{}, Store: st, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	if err := askTheOwner(ch); err == nil {
		t.Fatal("a question before the bridge's first state went")
	}
	if len(logged) != 1 {
		t.Fatalf("logged %q, want one line", logged)
	}
	g := logged[0]
	if !strings.HasPrefix(g, MissedLog+" kind=text via modemlink.askTheOwner via modemlink.TestAMissedSendThroughTheOwnerChannelNamesItsSender") {
		t.Errorf("line %q, want the local sender and this test as the first callers", g)
	}
	if strings.Contains(g, "owner.") || strings.Contains(g, "(*Link)") || strings.Contains(g, "canary") {
		t.Errorf("line %q carries the channel's or the Link's own calls, or the text", g)
	}
	if n := strings.Count(g, " via "); n > missedFrames {
		t.Errorf("line %q names %d calls, want at most %d", g, n, missedFrames)
	}
}

// askTheOwner stands in for agentosd's code that asks the owner a question.
//
//go:noinline
func askTheOwner(ch *owner.Channel) error { return ch.NotifyNow("synthetic-canary-question") }

// The names skip the Link's, the runtime's and the owner channel's frames
// and stop at missedFrames; a send the channel started itself names its
// outermost owner frame (#2349).
func TestSendersSkipsWrappersAndFallsBackToTheOwnerEntry(t *testing.T) {
	const mod = "example.test/m/broker/"
	for _, c := range []struct {
		stack []string
		want  string
	}{
		{[]string{mod + "modemlink.(*Link).deliver", mod + "modemlink.(*Link).Send", mod + "owner.watchedLine.Send",
			mod + "owner.(*Channel).sendReserved", mod + "owner.(*Channel).NotifyNow", "main.(*ownerLink).tell", "main.loop", "main.main", "main.start", "runtime.main", "runtime.goexit"},
			" via main.(*ownerLink).tell via main.loop via main.main"},
		{[]string{mod + "modemlink.(*Link).Send", mod + "owner.watchedLine.Send", mod + "owner.(*Channel).alert",
			mod + "owner.(*Channel).Run.func1", "runtime.goexit"},
			" via owner.(*Channel).Run.func1"},
		{[]string{mod + "modemlink.(*Link).Send", mod + "owner/notice.Send", "runtime.goexit"},
			" via notice.Send"},
		{[]string{mod + "modemlink.(*Link).Send", "", "runtime.goexit"}, ""},
	} {
		i := 0
		got := senders(func() (string, bool) {
			i++
			return c.stack[i-1], i < len(c.stack)
		})
		if got != c.want {
			t.Errorf("senders(%q) = %q, want %q", c.stack, got, c.want)
		}
	}
}

type idleEngine struct{}

func (idleEngine) Stop(context.Context) (control.StopReport, error) { return control.StopReport{}, nil }
func (idleEngine) Resume() error                                    { return nil }
func (idleEngine) Stopped() bool                                    { return false }
func (idleEngine) List() []control.Status                           { return nil }
