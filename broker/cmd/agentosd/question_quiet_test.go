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

// quietFake is an owner channel whose quiet hours always apply.
type quietFake struct {
	mu     sync.Mutex
	urgent bool
}

func (f *quietFake) Urgent(c owner.Class) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return c == owner.ClassAgent && f.urgent
}
func (f *quietFake) Quiet(time.Time) bool { return true }
func (f *quietFake) QuietHours() bool     { return true }

// The quiet-hours wiring agentosd gives the book (#1563, M9-M11): in the
// owner's quiet hours a question is not texted, its wait not started;
// with URGENT AGENT ON it is texted at once, as Notify did, and a
// restricted clock texts too.
func TestQuestionQuietWiring(t *testing.T) {
	for _, tc := range []struct {
		name       string
		urgent     bool
		restricted bool
		texts      int
	}{
		{"quiet", false, false, 0},
		{"quiet, clock restricted", false, true, 0},
		{"urgent agent", true, false, 1},
		{"urgent agent, clock restricted", true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &quietFake{urgent: tc.urgent}
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
