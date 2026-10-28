package owner

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// REQ: OP-2, CH-11, KRN-7

func retryItem(ref string) Item {
	return Item{Ref: ref, Object: "the email from 14:02 again", Detail: "may go twice",
		Facts: Facts{Verb: "Retry", NoRecipient: true}}
}

// RETRY asks about the digest's unclear effects with a texted code that
// warns of a duplicate; only an approved item comes back to the caller.
func TestRetryAsksWithATextedCodeAndWarnsOfADuplicate(t *testing.T) {
	r := newRig(t, nil)
	var listed []Item
	r.edit = func(c *Config) { c.Retry = func() ([]Item, error) { return listed, nil } }
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

// A part of the box whose waiting effects cannot be read is named, never
// answered "Nothing to retry.": alone it gives the fixed line, and with
// items it asks about them and adds the line (KRN-7). Revert mutant: drop
// the error, and the first RETRY answers "Nothing to retry.".
func TestRetrySaysWhenPartOfTheBoxIsNotAnswering(t *testing.T) {
	r := newRig(t, nil)
	var listed []Item
	r.edit = func(c *Config) { c.Retry = func() ([]Item, error) { return listed, errors.New("kernel down") } }
	r.ch = r.open()
	if got := r.say("RETRY"); got != retryUnread || !strings.HasSuffix(got, "Text RETRY again later.") {
		t.Fatalf("unread, nothing listed: %q", got)
	}
	listed = []Item{retryItem("retry:c")}
	if got := r.say("RETRY"); got != retryUnread {
		t.Fatalf("unread, one listed: %q", got)
	}
	if m := lowCodeRe.FindStringSubmatch(r.inbox()); m == nil {
		t.Fatal("the listed item was not asked about")
	}
}

// With too many requests open, RETRY says so and ends with one step: the
// unread line when part of the box is not answering, else "for the rest"
// (KRN-7, CH-12). Revert mutant: askRetry returns the short line alone
// when unread, and the unread part is never named.
func TestRetryAtTheCapStillNamesPartOfTheBoxNotAnswering(t *testing.T) {
	r := newRig(t, nil)
	var unread error
	r.edit = func(c *Config) {
		c.Retry = func() ([]Item, error) { return []Item{retryItem("retry:d")}, unread }
	}
	r.ch = r.open()
	for range MaxOpen {
		if _, err := r.ch.Request([]Item{lowItem("x")}, 0); err != nil {
			t.Fatal(err)
		}
		r.inbox()
	}
	const full = "Too many open requests to ask about every retry now."
	if got := r.say("RETRY"); got != full+" Text RETRY again later for the rest." {
		t.Fatalf("at the cap: %q", got)
	}
	unread = errors.New("kernel down")
	got := r.say("RETRY")
	if got != full+" "+retryUnread || strings.Count(got, "Text RETRY") != 1 {
		t.Fatalf("at the cap, unread: %q", got)
	}
}

// Declining, or a wrong code, retries nothing.
func TestRetryDeclinedOrWrongCodeRetriesNothing(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Retry = func() ([]Item, error) { return []Item{retryItem("retry:b")}, nil } }
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

// A retry of an effect that moves money is approved only with the code
// generator, whatever its facts would otherwise give; each retry item is
// its own request, says when it was first tried, and none offers a YES for
// all of them.
func TestRetryOfMoneyNeedsTheCodeGeneratorAndEachItemIsAsked(t *testing.T) {
	r := newRig(t, nil)
	first := r.clock().Add(-3 * time.Hour)
	money := Item{Ref: "retry:pay", Object: "invoice 1042", Recipient: "billing@acme.example", Amount: "$1.00", Retried: first,
		Facts: Facts{Verb: "pay", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true, HasAmount: true, Amount: 100, Kind: MoneyRetry}}
	plain := retryItem("retry:mail")
	plain.Retried = first
	r.edit = func(c *Config) { c.Retry = func() ([]Item, error) { return []Item{money, plain}, nil } }
	r.ch = r.open()

	if got := r.say("RETRY"); got != "" {
		t.Fatalf("RETRY reply: %q", got)
	}
	text := r.inbox()
	if strings.Contains(strings.ToLower(text), "for all") {
		t.Fatalf("retry request offers a YES for all: %q", text)
	}
	// One request per item, each with its own ID.
	starts := regexp.MustCompile(`(?:^|\. )([A-Z][0-9]{1,2}): `).FindAllStringSubmatchIndex(text, -1)
	if len(starts) != 2 {
		t.Fatalf("not one request per item: %q", text)
	}
	stamp := "first tried " + first.In(r.ch.cfg.Location).Format("15:04 Jan 2")
	var id, hi, lo string
	for i, st := range starts {
		end := len(text)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		part := text[st[0]:end]
		if !strings.Contains(part, stamp) {
			t.Fatalf("retry item without when it was first tried: %q", part)
		}
		if strings.Contains(part, "invoice 1042") {
			id, hi = text[st[2]:st[3]], part
		} else {
			lo = part
		}
	}
	if lowCodeRe.MatchString(hi) || !strings.Contains(hi, "code generator") || !strings.Contains(hi, "$1.00") {
		t.Fatalf("money retry request %q", hi)
	}
	m := lowCodeRe.FindStringSubmatch(lo)
	if m == nil || m[1] == id {
		t.Fatalf("plain retry request %q", lo)
	}
	if got := r.say("YES " + id + " " + m[2]); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("texted code approved a money retry: %q", got)
	}
	if got := r.say("YES " + id + " " + r.totp()); got != "Approved "+id+"." {
		t.Fatalf("money approve: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 1 || ds[0].Ref != "retry:pay" || !ds[0].Approved {
		t.Fatalf("decisions %+v", ds)
	}
}
