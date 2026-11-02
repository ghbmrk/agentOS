package driver

// REQ: UPD-5, HLD-2

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm/requal/wire"
)

func frames(t *testing.T, fs ...string) *bytes.Buffer {
	var b bytes.Buffer
	for _, f := range fs {
		if err := wire.Write(&b, f[0], []byte(f[1:])); err != nil {
			t.Fatal(err)
		}
	}
	return &b
}

func read(t *testing.T, b *bytes.Buffer) []string {
	var out []string
	for b.Len() > 0 {
		k, body, err := wire.Read(b, wire.MaxBody)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(k)+string(body))
	}
	return out
}

// TestRefuseRefusesEveryCase: under Refuse, the evaluator of a release
// that runs no suite, each case is a case error and the gate holds.
func TestRefuseRefusesEveryCase(t *testing.T) {
	var w bytes.Buffer
	if err := Serve(frames(t, "Ca", "Cb"), &w, Refuse); err != nil {
		t.Fatal(err)
	}
	got := read(t, &w)
	if len(got) != 2 || got[0] != "E"+ErrNoEvaluator.Error() || got[1] != got[0] {
		t.Fatalf("answers %q", got)
	}
}

func TestDriverAnswersAndCallsModels(t *testing.T) {
	var w bytes.Buffer
	in := frames(t, "Cx", "Ranswer", "Xbudget spent")
	err := Serve(in, &w, func(b []byte, m Models) ([]byte, error) {
		a, err := m.Call([]byte("q1"))
		if err != nil {
			return nil, err
		}
		_, err = m.Call([]byte("q2"))
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "budget spent") {
			return nil, errors.New("refusal not reported")
		}
		return append(b, a...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(read(t, &w), "|"); got != "Mq1|Mq2|Axanswer" {
		t.Fatalf("frames %q", got)
	}
}

func TestCaseErrorIsClipped(t *testing.T) {
	var w bytes.Buffer
	Serve(frames(t, "Cx"), &w, func([]byte, Models) ([]byte, error) { return nil, errors.New(strings.Repeat("e", 5000)) })
	if got := read(t, &w); len(got) != 1 || len(got[0]) != 1+maxReason {
		t.Fatalf("case error of %d bytes", len(got[0]))
	}
}

// TestFrameOutOfTurnEndsTheDriver: the driver takes only cases at a case
// boundary and only a model answer after a call; anything else, or a
// channel that ends mid-call, ends it with an error and no answer.
func TestFrameOutOfTurnEndsTheDriver(t *testing.T) {
	call := func(b []byte, m Models) ([]byte, error) { return m.Call(b) }
	for name, in := range map[string]*bytes.Buffer{
		"answer as a case":  frames(t, "Ax"),
		"case during call":  frames(t, "Cx", "Cy"),
		"end during a call": frames(t, "Cx"),
		"partial frame":     bytes.NewBuffer([]byte{'C', 0, 0}),
	} {
		var w bytes.Buffer
		if err := Serve(in, &w, call); err == nil {
			t.Errorf("%s: Serve passed", name)
		}
		for _, f := range read(t, &w) {
			if f[0] == wire.Answer || f[0] == wire.CaseError {
				t.Errorf("%s: answered %q", name, f)
			}
		}
	}
	if err := Serve(io.LimitReader(nil, 0), io.Discard, call); err != nil {
		t.Fatalf("an empty channel: %v", err)
	}
}
