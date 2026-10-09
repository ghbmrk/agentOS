package question

import "testing"

// REQ: RES-1

// PE7 (condition 2): the sleeper does not stop the agent while a question
// is held or waiting for the owner; an answered one does not count.
func TestOpenReportsAQuestionWaitingForTheOwner(t *testing.T) {
	r := newRig(t, nil)
	if r.b.Open() {
		t.Fatal("an empty book has an open question")
	}
	st := r.ask("lin1", "q1", slot())
	if st.State != Waiting || !r.b.Open() {
		t.Fatalf("a waiting question is not open: %+v", st)
	}
	if _, ok := r.answer(st.ID + " 9:30"); !ok {
		t.Fatal("answer not matched")
	}
	if r.b.Open() {
		t.Fatal("an answered question is still open")
	}
}
