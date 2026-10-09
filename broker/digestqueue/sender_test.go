package digestqueue

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// fakeTransport records every Deliver call and answers with a fixed receipt.
type fakeTransport struct {
	mu       sync.Mutex
	texts    []string
	outcome  Outcome
	evidence string
	panics   bool
	during   func()
}

func (f *fakeTransport) Deliver(ctx context.Context, text string) (Outcome, string) {
	f.mu.Lock()
	f.texts = append(f.texts, text)
	during := f.during
	f.mu.Unlock()
	if during != nil {
		during()
	}
	if f.panics {
		panic("transport fault")
	}
	return f.outcome, f.evidence
}
func (f *fakeTransport) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.texts)
}

func renderLines(b Batch) (string, error) {
	var lines []string
	for _, s := range b.Snapshots {
		lines = append(lines, s.Lines...)
	}
	return strings.Join(lines, " "), nil
}
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }
func sender(t *testing.T, q *Queue, tr Transport) *Sender {
	t.Helper()
	s, err := NewSender(q, tr, renderLines, fixedNow(at))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderRefusalNeverCallsTransport(t *testing.T) {
	q, _ := queue(t)
	unacked := enqueue(t, q, "change", 1)
	expired := enqueue(t, q, "owner", 1)
	ack(t, q, expired)
	accepted := enqueue(t, q, "question", 1)
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	s := sender(t, q, tr)
	if _, err := s.Send(context.Background(), accepted.ID); !errors.Is(err, ErrUnacknowledged) {
		t.Fatal(err)
	}
	ack(t, q, accepted)
	if o, err := s.Send(context.Background(), accepted.ID); err != nil || o != TransportAccepted {
		t.Fatal(o, err)
	}
	late, _ := NewSender(q, tr, renderLines, fixedNow(at.Add(time.Hour)))
	cases := []struct {
		name string
		s    *Sender
		id   uint64
		want error
	}{
		{"unacknowledged", s, unacked.ID, ErrUnacknowledged},
		{"expired", late, expired.ID, ErrExpired},
		{"state", s, accepted.ID, ErrState},
		{"missing", s, 99, ErrMissing},
	}
	for _, c := range cases {
		if _, err := c.s.Send(context.Background(), c.id); !errors.Is(err, c.want) {
			t.Fatal(c.name, err)
		}
	}
	broken, _ := queue(t)
	b := enqueue(t, broken, "change", 1)
	ack(t, broken, b)
	broken.broken = true
	if _, err := sender(t, broken, tr).Send(context.Background(), b.ID); !errors.Is(err, ErrRecovery) {
		t.Fatal("recovery", err)
	}
	if tr.calls() != 1 {
		t.Fatal("transport called on a refusal", tr.calls())
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderBeginSaveFailureDoesNotCallTransport(t *testing.T) {
	st := &failAfter{}
	q, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	st.fail = true
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	if _, err = sender(t, q, tr).Send(context.Background(), b.ID); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	if tr.calls() != 0 {
		t.Fatal("transport called without a durable begin")
	}
}

type failAfter struct {
	change.MemStore
	fail bool
}

func (f *failAfter) Save(b []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.MemStore.Save(b)
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderCancelledAndNilContextsDoNotBegin(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	s := sender(t, q, tr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Send(ctx, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	//lint:ignore SA1012 a nil context is the case under test
	if _, err := s.Send(nil, b.ID); !errors.Is(err, ErrInvalid) { //nolint:staticcheck
		t.Fatal(err)
	}
	got, _ := q.Get(b.ID)
	if got.State != Ready || got.Attempts != 0 || tr.calls() != 0 {
		t.Fatal(got.State, got.Attempts, tr.calls())
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderTransportPanicOrCancelIsUnknown(t *testing.T) {
	cases := map[string]func(*fakeTransport, context.CancelFunc){
		"panic":          func(f *fakeTransport, _ context.CancelFunc) { f.panics = true },
		"cancel":         func(f *fakeTransport, c context.CancelFunc) { f.outcome, f.evidence, f.during = NotSent, "x", c },
		"no receipt":     func(f *fakeTransport, _ context.CancelFunc) { f.outcome, f.evidence = "", "" },
		"bogus outcome":  func(f *fakeTransport, _ context.CancelFunc) { f.outcome, f.evidence = "sent-probably", "x" },
		"bare accepted":  func(f *fakeTransport, _ context.CancelFunc) { f.outcome = TransportAccepted },
		"bare not-sent":  func(f *fakeTransport, _ context.CancelFunc) { f.outcome = NotSent },
		"bad evidence":   func(f *fakeTransport, _ context.CancelFunc) { f.outcome, f.evidence = TransportAccepted, "not a name" },
		"unknown itself": func(f *fakeTransport, _ context.CancelFunc) { f.outcome, f.evidence = OutcomeUnknown, "bad evidence!" },
	}
	for name, set := range cases {
		q, _ := queue(t)
		b := enqueue(t, q, "change", 1)
		ack(t, q, b)
		ctx, cancel := context.WithCancel(context.Background())
		tr := &fakeTransport{}
		set(tr, cancel)
		s := sender(t, q, tr)
		o, err := s.Send(ctx, b.ID)
		cancel()
		if err != nil || o != OutcomeUnknown {
			t.Fatal(name, o, err)
		}
		got, _ := q.Get(b.ID)
		if got.State != Unknown {
			t.Fatal(name, got.State)
		}
		if _, err = s.Send(context.Background(), b.ID); !errors.Is(err, ErrState) || tr.calls() != 1 {
			t.Fatal(name, "unknown send repeated", err, tr.calls())
		}
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderFinishFailureReopensUnknownNotResent(t *testing.T) {
	st := &failAfter{}
	q, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	tr.during = func() { st.fail = true }
	if _, err = sender(t, q, tr).Send(context.Background(), b.ID); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	st.fail = false
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if got.State != Unknown {
		t.Fatal(got.State)
	}
	if _, err = sender(t, q2, tr).Send(context.Background(), b.ID); !errors.Is(err, ErrState) || tr.calls() != 1 {
		t.Fatal("resent after a lost finish", err, tr.calls())
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderRendersOnlyBegunBatch(t *testing.T) {
	q, _ := queue(t)
	other := enqueue(t, q, "owner", 1)
	ack(t, q, other)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	var seen []Batch
	render := func(v Batch) (string, error) {
		seen = append(seen, v)
		v.Snapshots[0].Lines[0] = "Mutated by render."
		return "Rendered digest.", nil
	}
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	s, err := NewSender(q, tr, render, fixedNow(at))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Send(context.Background(), b.ID); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].ID != b.ID || seen[0].State != Sending || seen[0].Attempts != 1 {
		t.Fatal(seen)
	}
	if len(tr.texts) != 1 || tr.texts[0] != "Rendered digest." {
		t.Fatal(tr.texts)
	}
	got, _ := q.Get(b.ID)
	if got.State != Accepted || got.Evidence != "item-1" || got.Snapshots[0].Lines[0] != "Fixed broker notice." {
		t.Fatal("render reached private queue state", got)
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderRenderFailureIsNotSentWithoutTransport(t *testing.T) {
	for name, render := range map[string]func(Batch) (string, error){
		"error": func(Batch) (string, error) { return "", errors.New("too long") },
		"empty": func(Batch) (string, error) { return "", nil },
		"panic": func(Batch) (string, error) { panic("render fault") },
	} {
		q, _ := queue(t)
		b := enqueue(t, q, "change", 1)
		ack(t, q, b)
		tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
		s, _ := NewSender(q, tr, render, fixedNow(at))
		o, err := s.Send(context.Background(), b.ID)
		if err == nil || o != NotSent || tr.calls() != 0 {
			t.Fatal(name, o, err, tr.calls())
		}
		got, _ := q.Get(b.ID)
		if got.State != Ready || got.Attempts != 1 {
			t.Fatal(name, got.State, got.Attempts)
		}
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestSenderNotSentRetriesWithinLimitThenExhausts(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	tr := &fakeTransport{outcome: NotSent, evidence: "not-handed"}
	s := sender(t, q, tr)
	for i := 0; i < limits.MaxAttempts; i++ {
		if o, err := s.Send(context.Background(), b.ID); err != nil || o != NotSent {
			t.Fatal(i, o, err)
		}
	}
	got, _ := q.Get(b.ID)
	if got.State != Failed {
		t.Fatal(got.State)
	}
	if _, err := s.Send(context.Background(), b.ID); !errors.Is(err, ErrState) || tr.calls() != limits.MaxAttempts {
		t.Fatal(err, tr.calls())
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestNewSenderRequiresEveryPart(t *testing.T) {
	q, _ := queue(t)
	tr := &fakeTransport{}
	for _, c := range []struct {
		q *Queue
		t Transport
		r func(Batch) (string, error)
		n func() time.Time
	}{{nil, tr, renderLines, time.Now}, {q, nil, renderLines, time.Now}, {q, tr, nil, time.Now}, {q, tr, renderLines, nil}} {
		if s, err := NewSender(c.q, c.t, c.r, c.n); s != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal(s, err)
		}
	}
}

// REQ: OP-2 (W5-Db DB-2)
func TestConcurrentSendsDeliverOnce(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	tr := &fakeTransport{outcome: OutcomeUnknown}
	s := sender(t, q, tr)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.Send(context.Background(), b.ID) }()
	}
	wg.Wait()
	if tr.calls() != 1 {
		t.Fatal("one batch delivered more than once", tr.calls())
	}
}

// REQ: OP-2 (W5-Db DB-2)
// The gate is structural: in this package's non-test files, only
// (*Sender).Send names Transport.Deliver, begin or finish, and nothing
// exported is named Begin or Finish.
func TestOnlySenderSendCallsDeliver(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	gated := map[string]bool{"Deliver": true, "begin": true, "finish": true}
	found := map[string]int{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && (fn.Name.Name == "Begin" || fn.Name.Name == "Finish") {
				t.Errorf("%s: exported %s reopens the gate", path, fn.Name.Name)
			}
			inSend := ok && fn.Name.Name == "Send" && fn.Recv != nil && recvName(fn.Recv) == "Sender"
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !gated[sel.Sel.Name] {
					return true
				}
				found[sel.Sel.Name]++
				if !inSend {
					t.Errorf("%s: %s named outside (*Sender).Send", fset.Position(sel.Pos()), sel.Sel.Name)
				}
				return true
			})
		}
	}
	for name := range gated {
		if found[name] != 1 {
			t.Errorf("(*Sender).Send names %s %d times, want once", name, found[name])
		}
	}
}
func recvName(fl *ast.FieldList) string {
	if len(fl.List) != 1 {
		return ""
	}
	t := fl.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
