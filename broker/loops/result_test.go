package loops

// REQ: CHG-1, OP-7

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

type resultJournal struct{ st journal.Status }

func (j *resultJournal) Get(string) (journal.Status, error) { return j.st, nil }
func (j *resultJournal) RecordQuality(_ string, q journal.Quality) (journal.Status, error) {
	j.st.Quality = q
	return j.st, nil
}

type resultSuite struct{ cases []change.Case }

func (s *resultSuite) AddTaskCase(c change.Case) error { s.cases = append(s.cases, c); return nil }
func (s *resultSuite) Dev(change.Class) []change.Case  { return s.cases }

func TestObservedHarvestRequiresTerminalExecutionEvidence(t *testing.T) {
	in := journal.Intent{ID: "guest/1", GoalID: "owner:1", Origin: "guest:test", Account: "mail", Action: "mail.send", Params: map[string]any{"subject": "hello", "body": "synthetic"}, Recipients: []string{"sam@example.invalid"}}
	expect, _ := change.MailSendExpectation(in)
	for _, tc := range []struct {
		name      string
		action    Action
		state     journal.State
		supported bool
	}{
		{"accepted succeeded", Approved, journal.Succeeded, true},
		{"accepted unknown", Approved, journal.OutcomeUnknown, false},
		{"accepted denied", Approved, journal.Denied, false},
		{"accepted failed", Approved, journal.NotApplied, false},
		{"rejected denied", Denied, journal.Denied, true},
		{"undone succeeded", Undone, journal.Succeeded, true},
		{"rejected unknown", Denied, journal.OutcomeUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := &resultJournal{st: journal.Status{Intent: in, State: tc.state}}
			s := &resultSuite{}
			h := &Harvester{J: j, Pipeline: s, Store: &change.MemStore{}}
			err := h.Harvest(Outcome{Intent: in.ID, Action: tc.action, Input: []byte("send the message"), Output: expect, ResultFormat: change.MailSendResultV1})
			if tc.supported {
				if err != nil || len(s.cases) != 1 || s.cases[0].ResultFormat != change.MailSendResultV1 {
					t.Fatal("supported case lost", err)
				}
			} else if !errors.Is(err, change.ErrUnsupportedResult) || len(s.cases) != 0 {
				t.Fatal("unsupported evidence entered suite", err)
			}
			if j.st.Quality.Source != "owner" {
				t.Fatal("quality signal was lost")
			}
		})
	}
	for _, format := range []string{change.MailSendResultV1, "future"} {
		j := &resultJournal{st: journal.Status{Intent: in, State: journal.Succeeded}}
		s := &resultSuite{}
		h := &Harvester{J: j, Pipeline: s, Store: &change.MemStore{}}
		if err := h.Harvest(Outcome{Intent: in.ID, Action: Approved, Input: []byte("task"), Output: []byte("Done"), ResultFormat: format}); !errors.Is(err, change.ErrUnsupportedResult) || len(s.cases) != 0 {
			t.Fatal("malformed/unsupported evidence harvested", err)
		}
	}
}
