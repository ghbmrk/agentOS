package owner

import (
	"strings"
	"testing"
)

// REQ: OP-2, CH-11

func retryItem(ref string) Item {
	return Item{Ref: ref, Object: "the email from 14:02 again", Detail: "may go twice",
		Facts: Facts{Verb: "Retry", NoRecipient: true}}
}

// RETRY asks about the digest's unclear effects with a texted code that
// warns of a duplicate; only an approved item comes back to the caller.
func TestRetryAsksWithATextedCodeAndWarnsOfADuplicate(t *testing.T) {
	r := newRig(t, nil)
	var listed []Item
	r.edit = func(c *Config) { c.Retry = func() []Item { return listed } }
	r.ch = r.open()

	if got := r.say("RETRY"); got != "Nothing to retry." {
		t.Fatalf("empty RETRY: %q", got)
	}
	listed = []Item{retryItem("retry:a")}
	if got := r.say("RETRY"); got != "" {
		t.Fatalf("RETRY reply: %q", got)
	}
	text := r.inbox()
	m := lowCodeRe.FindStringSubmatch(text)
	if m == nil || !strings.Contains(text, "may go twice") {
		t.Fatalf("retry request text: %q", text)
	}
	if len(r.decisions()) != 0 {
		t.Fatal("asking decided something")
	}
	if got := r.say("YES " + m[1] + " " + m[2]); got != "Approved "+m[1]+"." {
		t.Fatalf("approve: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 1 || ds[0].Ref != "retry:a" || !ds[0].Approved {
		t.Fatalf("decisions %+v", ds)
	}
}

// Declining, or a wrong code, retries nothing.
func TestRetryDeclinedOrWrongCodeRetriesNothing(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Retry = func() []Item { return []Item{retryItem("retry:b")} } }
	r.ch = r.open()
	r.say("RETRY")
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	wrong := "000000"
	if m[2] == wrong {
		wrong = "111111"
	}
	if got := r.say("YES " + m[1] + " " + wrong); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("wrong code: %q", got)
	}
	r.say("NO " + m[1])
	for _, d := range r.decisions() {
		if d.Approved {
			t.Fatalf("approved without the code: %+v", d)
		}
	}
}

// With no Retry hook, RETRY says there is nothing to retry.
func TestRetryWithoutAHookIsNothing(t *testing.T) {
	r := newRig(t, nil)
	if got := r.say("retry"); got != "Nothing to retry." {
		t.Fatalf("got %q", got)
	}
	if _, ok := parseReply("RETRY now"); ok {
		t.Fatal("RETRY with arguments parsed as the word")
	}
}
