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
		"resume 12ab",            // a code is digits only
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
