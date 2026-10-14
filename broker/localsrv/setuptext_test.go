package localsrv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-12, ONB-6

// fakeLine is the owner line's modem bridge during setup.
type fakeLine struct {
	ready   bool
	number  string
	sendErr error
	sent    [][2]string
	inbox   chan [2]string
}

func (f *fakeLine) Ready() bool    { return f.ready }
func (f *fakeLine) Number() string { return f.number }
func (f *fakeLine) Send(_ context.Context, to, text string) error {
	f.sent = append(f.sent, [2]string{to, text})
	return f.sendErr
}
func (f *fakeLine) Next(ctx context.Context) (string, string, bool) {
	select {
	case in := <-f.inbox:
		return in[0], in[1], true
	case <-ctx.Done():
		return "", "", false
	}
}

const (
	boxNumber   = "+15550100777"
	ownerNumber = "+15550100100"
	setupCode   = "agentOS setup code: 482193. Type it on the setup page."
)

// P2-2w c4c: setup reads the box's number while the bridge reports the
// line usable, and says plainly when it cannot text.
func TestSetupLineAnswersTheBoxsNumberOnlyWhenItCanText(t *testing.T) {
	r := newSetupRig(t)
	var l localapi.SetupLine
	if err := r.call(localapi.OpSetupLine, nil, &l); err != nil || l.Ready || l.Number != "" {
		t.Fatalf("no line: %v %+v", err, l)
	}
	f := &fakeLine{number: boxNumber}
	r.s.cfg.Line = f
	if err := r.call(localapi.OpSetupLine, nil, &l); err != nil || l.Ready || l.Number != "" {
		t.Fatalf("line not ready: %v %+v", err, l)
	}
	f.ready = true
	if err := r.call(localapi.OpSetupLine, nil, &l); err != nil || !l.Ready || l.Number != boxNumber {
		t.Fatalf("ready line: %v %+v", err, l)
	}
	f.number = "0555"
	l = localapi.SetupLine{}
	if err := r.call(localapi.OpSetupLine, nil, &l); err != nil || !l.Ready || l.Number != "" {
		t.Fatalf("a bad number was answered: %v %+v", err, l)
	}
	if err := r.call(localapi.OpSetupLine, map[string]any{"x": 1}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("an extra field: %v", err)
	}
}

// Setup sends only its fixed texts, to an E.164 number, within its caps,
// and answers ErrNotSent when the bridge did not send it.
func TestSetupSendsOnlyItsFixedTextsWithinTheCaps(t *testing.T) {
	r := newSetupRig(t)
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); code(err) != localapi.ErrNotSent {
		t.Fatalf("no line: %v", err)
	}
	f := &fakeLine{ready: true}
	r.s.cfg.Line = f
	for _, a := range []any{
		localapi.SetupSend{To: ownerNumber, Text: "Hi, call me back"},
		localapi.SetupSend{To: ownerNumber, Text: setupCode + " https://example.test"},
		localapi.SetupSend{To: "5550100100", Text: setupCode},
		localapi.SetupSend{To: "", Text: setupCode},
		map[string]string{"to": ownerNumber, "text": setupCode, "line": "second"},
	} {
		if err := r.call(localapi.OpSetupSend, a, nil); code(err) != localapi.ErrBadArgs {
			t.Errorf("%#v: %v", a, err)
		}
	}
	if len(f.sent) != 0 {
		t.Fatalf("refused texts reached the line: %d", len(f.sent))
	}
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 || f.sent[0] != [2]string{ownerNumber, setupCode} {
		t.Fatalf("sent %v", f.sent)
	}
	f.sendErr = errors.New("modemlink: not sent")
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); code(err) != localapi.ErrNotSent {
		t.Fatalf("a failed send: %v", err)
	}
	f.sendErr = nil
	// Per minute: SetupTextsPerMinute, the two above included.
	for i := 2; i < SetupTextsPerMinute; i++ {
		if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); err != nil {
			t.Fatalf("text %d: %v", i, err)
		}
	}
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("over the minute's cap: %v", err)
	}
	// Per hour: SetupTextsPerHour, however they are spread.
	sent := SetupTextsPerMinute
	for sent < localapi.SetupTextsPerHour {
		r.now = r.now.Add(time.Minute)
		if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); err != nil {
			t.Fatalf("text %d: %v", sent, err)
		}
		sent++
	}
	r.now = r.now.Add(time.Minute)
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("over the hour's cap: %v", err)
	}
	r.now = r.now.Add(time.Hour)
	if err := r.call(localapi.OpSetupSend, localapi.SetupSend{To: ownerNumber, Text: setupCode}, nil); err != nil {
		t.Fatalf("an hour later: %v", err)
	}
}

// The page takes the PAIR texts that reached the box, one per call.
func TestSetupInboundAnswersEachPairTextOnce(t *testing.T) {
	r := newSetupRig(t)
	var in localapi.SetupInbound
	if err := r.call(localapi.OpSetupInbound, nil, &in); err != nil || in != (localapi.SetupInbound{}) {
		t.Fatalf("no line: %v %+v", err, in)
	}
	f := &fakeLine{ready: true, inbox: make(chan [2]string, 1)}
	r.s.cfg.Line = f
	f.inbox <- [2]string{ownerNumber, "PAIR 4821"}
	if err := r.call(localapi.OpSetupInbound, nil, &in); err != nil || in.From != ownerNumber || in.Text != "PAIR 4821" {
		t.Fatalf("inbound %v %+v", err, in)
	}
	if err := r.call(localapi.OpSetupInbound, map[string]any{"x": 1}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("an extra field: %v", err)
	}
}
