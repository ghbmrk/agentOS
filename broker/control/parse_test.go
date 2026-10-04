package control

import (
	"reflect"
	"testing"
)

// REQ: CH-2

func TestParseControlWordsWholeMessageIgnoringCaseAndPunctuation(t *testing.T) {
	cases := []struct {
		in   string
		want Command
	}{
		{"STOP", Command{Word: WordStop}},
		{" stop! ", Command{Word: WordStop}},
		{"Stop.", Command{Word: WordStop}},
		{"status?", Command{Word: WordStatus}},
		{"help", Command{Word: WordHelp}},
		{"resume", Command{Word: WordResume}},
		{"Resume 482193", Command{Word: WordResume, Args: []string{"482193"}}},
		{"YES 1 3 4821", Command{Word: WordYes, Args: []string{"1", "3", "4821"}}},
		{"yes 1,3 4821", Command{Word: WordYes, Args: []string{"1", "3", "4821"}}},
		{"no", Command{Word: WordNo}},
		{"NO 2", Command{Word: WordNo, Args: []string{"2"}}},
		{"undo a7", Command{Word: WordUndo, Args: []string{"A7"}}},
		{"MORE b2c", Command{Word: WordMore, Args: []string{"B2C"}}},
	}
	for _, c := range cases {
		got := Parse(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseAnythingElseGoesToTheAgent(t *testing.T) {
	for _, in := range []string{
		"stop the newsletter",    // not the whole message
		"status of my order",     // not the whole message
		"help me write a letter", // not the whole message
		"YES please",             // YES takes only numbers
		"undo everything today",  // UNDO takes one ID
		"more abcd",              // request IDs are at most 3 characters
		"",
		"   ",
	} {
		got := Parse(in)
		if got.Word != WordNone || got.Text != in || got.Public {
			t.Errorf("Parse(%q) = %+v, want task text unchanged", in, got)
		}
	}
}

func TestParsePublicPrefixMarksTaskPublic(t *testing.T) {
	got := Parse("PUBLIC: find the best rated dishwasher")
	want := Command{Word: WordNone, Public: true, Text: "find the best rated dishwasher"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := Parse("public"); got.Public || got.Word != WordNone || got.Text != "public" {
		t.Fatalf("bare PUBLIC carries no task: got %+v", got)
	}
	if got := Parse("publicity plan"); got.Public {
		t.Fatalf("PUBLIC must be a whole word: got %+v", got)
	}
}

func TestParseGarbledCodeRepliesNeverReachTheAgent(t *testing.T) {
	for _, in := range []string{"resume 12ab", "RESUME 123 456", "YES 1 x 4821", "no 2 please 3"} {
		if got := Parse(in); got.Word != WordUnclear || got.Text != "" {
			t.Errorf("Parse(%q) = %+v, want unclear with no text", in, got)
		}
	}
	if got := Parse("yes please"); got.Word != WordNone {
		t.Errorf("no digits, so it is chat: %+v", got)
	}
}

func TestStopNearMiss(t *testing.T) {
	for in, want := range map[string]bool{
		"stop everything": true, "STOP NOW": true, "please stop!": true,
		"stop the newsletter": true, "STOP": false, "don't stop believing": false, "plan my week": false,
	} {
		if got := StopNearMiss(in); got != want {
			t.Errorf("StopNearMiss(%q) = %v", in, got)
		}
	}
}
