package main

// REQ: CH-15, CAP-10

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
)

// quietFake is an owner channel whose quiet hours always apply. Approval
// is urgent unless held (URGENT APPROVAL OFF, D-129); agent is urgent
// only when switched on.
type quietFake struct {
	mu           sync.Mutex
	approvalHeld bool
	agentUrgent  bool
}

func (f *quietFake) Urgent(c owner.Class) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch c {
	case owner.ClassApproval:
		return !f.approvalHeld
	case owner.ClassAgent:
		return f.agentUrgent
	}
	return false
}
func (f *quietFake) Quiet(time.Time) bool { return true }
func (f *quietFake) QuietHours() bool     { return true }

// The quiet-hours wiring agentosd gives the book (#1563, M9-M11, #2250):
// a question carries a deadline, so it is approval class (D-129). By
// default approval is urgent and a question is texted at once in quiet
// hours, a restricted clock too; with URGENT APPROVAL OFF it is not
// texted, its wait not started, and URGENT AGENT ON no longer decides it.
func TestQuestionQuietWiring(t *testing.T) {
	for _, tc := range []struct {
		name         string
		approvalHeld bool
		agentUrgent  bool
		restricted   bool
		texts        int
	}{
		{"default urgent", false, false, false, 1},
		{"default urgent, clock restricted", false, false, true, 1},
		{"approval held", true, false, false, 0},
		{"approval held, clock restricted", true, false, true, 0},
		{"approval held, agent urgent", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &quietFake{approvalHeld: tc.approvalHeld, agentUrgent: tc.agentUrgent}
			var mu sync.Mutex
			var sent []string
			b, err := question.New(question.Config{
				Send: func(text string) error {
					mu.Lock()
					defer mu.Unlock()
					sent = append(sent, text)
					return nil
				},
				Now: func(context.Context) (time.Time, error) {
					if tc.restricted {
						return time.Time{}, context.DeadlineExceeded
					}
					return time.Date(2026, 10, 5, 23, 0, 0, 0, time.UTC), nil
				},
				Quiet:      questionQuiet(ch),
				QuietHours: questionQuietHours(ch),
				Path:       filepath.Join(t.TempDir(), "questions.json"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Ask(context.Background(), "lin1", "q1", question.Spec{
				Text: "Book the 9:30 slot?", Default: "wait", Choices: []string{"go ahead", "wait"}, Wait: time.Hour,
			}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(sent) != tc.texts {
				t.Fatalf("texts sent = %q, want %d", sent, tc.texts)
			}
		})
	}
}

// The CH-15 budget wiring (#2250, D-129): while approval is urgent a
// question skips the gate's reservation, as an urgent approval request
// skips the hourly limit (it still counts, on the owner's hour, when
// NotifyNow sends it); with URGENT APPROVAL OFF the gate decides.
func TestQuestionReserveWiring(t *testing.T) {
	for _, tc := range []struct {
		name         string
		approvalHeld bool
		agentUrgent  bool
		gate         bool
		want         bool
		calls        int
	}{
		{"default urgent, gate refuses", false, false, false, true, 0},
		{"approval held, gate refuses", true, false, false, false, 1},
		{"approval held, gate grants", true, false, true, true, 1},
		{"approval held, agent urgent, gate refuses", true, true, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &quietFake{approvalHeld: tc.approvalHeld, agentUrgent: tc.agentUrgent}
			calls := 0
			reserve := questionReserve(ch, func(bool) bool { calls++; return tc.gate })
			if got := reserve(false); got != tc.want || calls != tc.calls {
				t.Fatalf("reserve = %v after %d gate calls, want %v after %d", got, calls, tc.want, tc.calls)
			}
		})
	}
}
