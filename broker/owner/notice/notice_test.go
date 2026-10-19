package notice

import (
	"encoding/json"
	"strings"
	"testing"
)

// REQ: OP-9, CH-3, CAP-9

// Every code renders one fixed text, in the box's first person, and the
// only part not from the table is a provider's name of a fixed shape.
func TestEachCodeRendersAFixedText(t *testing.T) {
	cases := []struct {
		n    Notice
		want string
	}{
		{Notice{Code: MailReplaced}, "Your mail account was replaced on my Wi-Fi page."},
		{Notice{Code: MailRemoved}, "Your mail account was removed on my Wi-Fi page."},
		{Notice{Code: LineCallReplaced}, "My second line's calling account was replaced on my Wi-Fi page."},
		{Notice{Code: LineCallRemoved}, "My second line's calling account was removed on my Wi-Fi page."},
		{Notice{Code: LineTextReplaced}, "My second line's texting account was replaced on my Wi-Fi page."},
		{Notice{Code: LineTextRemoved}, "My second line's texting account was removed on my Wi-Fi page."},
		{Notice{Code: LineTextsMissed}, "Some texts to my second line may have been missed."},
		{Notice{Code: PrivateAllowed, Name: "OpenAI"}, "OpenAI may now get your private data: it was allowed on my Wi-Fi page."},
		{Notice{Code: PrivateWithdrawn, Name: "ChatGPT plan"}, "ChatGPT plan may no longer get your private data: it was withdrawn on my Wi-Fi page."},
		{Notice{Code: WrongCode}, "A wrong code was typed on my Wi-Fi page."},
		{Notice{Code: WrongCode, Name: "a vault unlock"}, "A wrong code was typed on my Wi-Fi page to unlock me."},
		{Notice{Code: WrongCode, Name: "allowing a provider private data"}, "A wrong code was typed on my Wi-Fi page to allow a provider your private data."},
		{Notice{Code: CodesLocked}, "Too many wrong codes were typed to unlock me, so that unlock was stopped."},
	}
	seen := map[Code]bool{}
	for _, c := range cases {
		got, ok := Text(c.n)
		if !ok || !strings.HasPrefix(got, c.want) {
			t.Errorf("%+v: %q, %v; want it to start %q", c.n, got, ok, c.want)
		}
		seen[c.n.Code] = true
	}
	for _, c := range Codes() {
		if !seen[c] {
			t.Errorf("code %q has no case here", c)
		}
	}
	// A change someone else could have made says what to do about it.
	for _, n := range []Notice{{Code: MailReplaced}, {Code: LineTextRemoved}, {Code: PrivateAllowed, Name: "OpenAI"}, {Code: WrongCode}, {Code: CodesLocked}} {
		if s, _ := Text(n); !strings.Contains(s, "If that wasn't you") {
			t.Errorf("%+v: %q says nothing to do", n, s)
		}
	}
}

// An unknown code, a provider notice without a name or with a name
// outside the fixed shape, a name on a notice that takes none, or a
// wrong code for something not in the table renders nothing.
func TestOnlyKnownCodesAndShapedNamesRender(t *testing.T) {
	for _, n := range []Notice{
		{Code: "something_else"},
		{Code: ""},
		{Code: PrivateAllowed},
		{Code: PrivateAllowed, Name: "Open\nAI"},
		{Code: PrivateAllowed, Name: "https://evil.example/x"},
		{Code: PrivateAllowed, Name: "evil.example.com"},
		{Code: PrivateWithdrawn, Name: "a.b"},
		{Code: PrivateAllowed, Name: strings.Repeat("a", 33)},
		{Code: PrivateWithdrawn, Name: " OpenAI"},
		{Code: MailReplaced, Name: "OpenAI"},
		{Code: WrongCode, Name: "sending money"},
	} {
		if s, ok := Text(n); ok || s != "" {
			t.Errorf("%+v rendered %q", n, s)
		}
	}
}

// FromLog knows the vault process's owner-notice lines exactly; any other
// line, including one that only starts like a known one, stays log-only.
func TestFromLogMapsOnlyTheOwnerNoticeLines(t *testing.T) {
	cases := map[string]Notice{
		"The mail account was replaced on my Wi-Fi page.":                  {Code: MailReplaced},
		"The mail account was removed on my Wi-Fi page.":                   {Code: MailRemoved},
		"The second line's calling account was replaced on my Wi-Fi page.": {Code: LineCallReplaced},
		"The second line's calling account was removed on my Wi-Fi page.":  {Code: LineCallRemoved},
		"The second line's texting account was replaced on my Wi-Fi page.": {Code: LineTextReplaced},
		"The second line's texting account was removed on my Wi-Fi page.":  {Code: LineTextRemoved},
		"Some texts to your second line may have been missed.":             {Code: LineTextsMissed},
		"private data allowed for OpenAI":                                  {Code: PrivateAllowed, Name: "OpenAI"},
		"private data withdrawn for ChatGPT plan":                          {Code: PrivateWithdrawn, Name: "ChatGPT plan"},
		"wrong code for a vault unlock":                                    {Code: WrongCode, Name: "a vault unlock"},
		"wrong code for a card rotation":                                   {Code: WrongCode, Name: "a card rotation"},
		"wrong code for something new":                                     {Code: WrongCode},
		"too many wrong codes for a vault unlock; key discarded":           {Code: CodesLocked},
	}
	for line, want := range cases {
		got, ok := FromLog(line)
		if !ok || got != want {
			t.Errorf("%q: %+v, %v; want %+v", line, got, ok, want)
		}
		if _, ok := Text(got); !ok {
			t.Errorf("%q maps to %+v, which renders nothing", line, got)
		}
	}
	for _, line := range []string{
		"",
		"vault unlocked",
		"vault passphrase accepted; waiting for a code-generator code",
		"The mail account was replaced on my Wi-Fi page. ",
		"private data allowed for ",
		"private data allowed for Open\nAI",
		"a trusted host was removed",
	} {
		if n, ok := FromLog(line); ok {
			t.Errorf("%q mapped to %+v", line, n)
		}
	}
}

// The wire shape agentosd reads: codes and names, never text.
func TestTheBatchJSON(t *testing.T) {
	b, err := json.Marshal(Batch{Boot: "b1", Notices: []Item{{Seq: 3, Notice: Notice{Code: PrivateAllowed, Name: "OpenAI"}}}, Missed: 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"boot":"b1","notices":[{"seq":3,"code":"private_allowed","name":"OpenAI"}],"missed":2}` {
		t.Fatalf("%s", b)
	}
	b, _ = json.Marshal(Batch{Boot: "b1", Notices: []Item{{Seq: 1, Notice: Notice{Code: CodesLocked}}}})
	if string(b) != `{"boot":"b1","notices":[{"seq":1,"code":"codes_locked"}]}` {
		t.Fatalf("%s", b)
	}
}
