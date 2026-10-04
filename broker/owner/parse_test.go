package owner

import (
	"reflect"
	"testing"
)

// REQ: CH-11, CH-13

func TestParseReplyGrammar(t *testing.T) {
	ok := map[string]reply{
		"YES 482913":          {word: "YES", code: "482913"},
		"yes k3 482913":       {word: "YES", id: "K3", code: "482913"},
		"Yes K3 1, 3 482913.": {word: "YES", id: "K3", items: []int{1, 3}, code: "482913"},
		"YES 1 3 482913":      {word: "YES", items: []int{1, 3}, code: "482913"},
		"YES K3":              {word: "YES", id: "K3"},
		"yes":                 {word: "YES"},
		"no":                  {word: "NO"},
		"NO 2":                {word: "NO", items: []int{2}},
		"no k3 2":             {word: "NO", id: "K3", items: []int{2}},
		"undo a7":             {word: "UNDO", id: "A7"},
		"MORE K3":             {word: "MORE", id: "K3"},
		"resume":              {word: "RESUME"},
		"Resume 482193":       {word: "RESUME", code: "482193"},
	}
	for in, want := range ok {
		got, isReply := parseReply(in)
		if !isReply || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %+v,%v want %+v", in, got, isReply, want)
		}
	}
	for _, in := range []string{
		"yes please book it", "no thanks, skip the newsletter", "undo", "undo the last email",
		"more", "resume the backup tonight", "stop", "status", "hello", "YES K3 1 3 4821 extra",
		"NO 123", "YES 0 482913",
	} {
		if r, isReply := parseReply(in); isReply {
			t.Errorf("%q parsed as %+v", in, r)
		}
	}
}

// REQ: CH-14

func TestTrailingCode(t *testing.T) {
	rest, code, ok := trailingCode("book the table for friday 482913")
	if !ok || code != "482913" || rest != "book the table for friday" {
		t.Fatalf("%q %q %v", rest, code, ok)
	}
	if _, _, ok := trailingCode("call me at 5551234567"); ok {
		t.Fatal("10 digits is not a code")
	}
	if _, _, ok := trailingCode("room 12"); ok {
		t.Fatal("2 digits is not a code")
	}
}
