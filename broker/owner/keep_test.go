package owner

// REQ: CH-19, CH-21

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// recKeeper records what it was asked to keep, and how many texts had
// reached the owner's phone when it was asked.
type recKeeper struct {
	mu    sync.Mutex
	err   error
	kinds []string
	texts []string
	sent  []int
	phone *modem.Line
}

func (k *recKeeper) Keep(kind, text string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kinds = append(k.kinds, kind)
	k.texts = append(k.texts, text)
	k.sent = append(k.sent, len(k.phone.Inbox()))
	return k.err
}

// The two withheld shapes, each with what is kept and the pointer sent.
var heldCases = []struct {
	name, text, kept, kind, pointer, notKept string
}{
	{"secret", "Your Acme verification\x07 code is 482913", "Your Acme verification code is 482913", KeptSecret, HiddenPointer, Hidden},
	{"code", "I fixed the code‮ you asked about.", "I fixed the code you asked about.", KeptCode, HeldCodePointer, HeldCode},
}

var heldSends = map[string]func(*Channel, string) error{
	"Converse":  (*Channel).Converse,
	"Notify":    (*Channel).Notify,
	"NotifyNow": (*Channel).NotifyNow,
}

// TestHeldTextIsKeptBeforePointer (HELD-1): a Converse, Notify and
// NotifyNow of a CH-21 ask and of a secret-shaped text each keep the text,
// stripped of controls, before the pointer is sent, and the pointer is
// the only text sent. Catches a pointer sent with nothing kept.
func TestHeldTextIsKeptBeforePointer(t *testing.T) {
	for _, c := range heldCases {
		for name, send := range heldSends {
			r := pacedRig(t, quiet22to7(), 12, 0)
			k := &recKeeper{phone: r.phone}
			r.ch.SetKeeper(k)
			if err := send(r.ch, c.text); err != nil {
				t.Fatalf("%s %s: %v", name, c.name, err)
			}
			got := r.sentTexts()
			if len(got) != 1 || got[0] != c.pointer {
				t.Fatalf("%s %s sent %q, want only %q", name, c.name, got, c.pointer)
			}
			if len(k.kinds) != 1 || k.kinds[0] != c.kind || k.texts[0] != c.kept || k.sent[0] != 0 {
				t.Fatalf("%s %s: kept %q %q with %v texts already sent", name, c.name, k.kinds, k.texts, k.sent)
			}
		}
	}
}

// TestBrokerTextIsKeptBeforePointer (HELD-1): the channel's own Post
// keeps a secret-shaped text before pointing to it too (CH-12).
func TestBrokerTextIsKeptBeforePointer(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 12, 0)
	k := &recKeeper{phone: r.phone}
	r.ch.SetKeeper(k)
	if err := r.ch.Post(ClassUpdate, "Your Acme verification code is 482913"); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != HiddenPointer || len(k.kinds) != 1 || k.kinds[0] != KeptSecret || k.sent[0] != 0 {
		t.Fatalf("sent %q, kept %q", got, k.kinds)
	}
}

// TestKeepFailureSaysNotKept (HELD-1): with a keeper that fails, and with
// none, each path sends the kind's could-not-be-kept text, which names no
// page. Catches a false pointer.
func TestKeepFailureSaysNotKept(t *testing.T) {
	for _, c := range heldCases {
		for name, send := range heldSends {
			for _, failing := range []bool{true, false} {
				r := pacedRig(t, quiet22to7(), 12, 0)
				if failing {
					r.ch.SetKeeper(&recKeeper{phone: r.phone, err: errors.New("disk full")})
				}
				if err := send(r.ch, c.text); err != nil {
					t.Fatal(err)
				}
				got := r.sentTexts()
				if len(got) != 1 || got[0] != c.notKept || strings.Contains(strings.ToLower(got[0]), "page") {
					t.Fatalf("%s %s (keeper failing %v) sent %q, want only %q", name, c.name, failing, got, c.notKept)
				}
			}
		}
	}
}

// TestHoldLogCarriesNoText (HELD-4): a synthetic canary code that is held,
// kept or not, never appears in a log line.
func TestHoldLogCarriesNoText(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	const canary = "CANARY-7Q4Z"
	for _, err := range []error{nil, errors.New("disk full")} {
		r := pacedRig(t, quiet22to7(), 12, 0)
		r.ch.SetKeeper(&recKeeper{phone: r.phone, err: err})
		for _, text := range []string{"Your login code is 4829 " + canary, "Here is the code " + canary} {
			if err := r.ch.Notify(text); err != nil {
				t.Fatal(err)
			}
		}
		r.sentTexts()
	}
	if strings.Contains(buf.String(), canary) || strings.Contains(buf.String(), "4829") {
		t.Fatalf("a log line carries the held text: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "not kept") {
		t.Fatal("a held text that was not kept was not logged")
	}
}

// TestPointersAreOneTextAndNotHeldAgain: each stand-in for a withheld
// text is one GSM-7 segment, goes without the agent prefix, and only the
// pointers name the page.
func TestPointersAreOneTextAndNotHeldAgain(t *testing.T) {
	for _, s := range []string{Hidden, HiddenPointer, HeldCode, HeldCodePointer} {
		if n, gsm := modem.Segments(s); !gsm || n != 1 {
			t.Fatalf("%q is %d segments (GSM-7 %v)", s, n, gsm)
		}
		if got := agentText(s); got != s {
			t.Fatalf("agentText(%q) = %q", s, got)
		}
		pointer := s == HiddenPointer || s == HeldCodePointer
		// CH-12: a not-kept text says what the owner can do.
		if !pointer && !strings.HasSuffix(s, "Ask me to put it another way.") {
			t.Fatalf("%q gives no next step", s)
		}
		if strings.Contains(s, "Wi-Fi page") != pointer || strings.Contains(s, "could not keep") == pointer {
			t.Fatalf("%q: pointer %v", s, pointer)
		}
	}
}

// TestRetriedHeldTextKeepsAskingTheKeeper: a held owner question retried
// while the line is down is withheld, and offered to the keeper, on every
// try; the keeper (agentosd's kept replies) keeps one copy (#3986 L3 1,
// cmd/agentosd TestRetriedKeepIsKeptOnce).
func TestRetriedHeldTextKeepsAskingTheKeeper(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 12, 0)
	k := &recKeeper{phone: r.phone}
	r.ch.SetKeeper(k)
	r.box.SetDown(true)
	for range 3 {
		if err := r.ch.NotifyNow("I fixed the code. Shall I push it?"); !errors.Is(err, modem.ErrNotSent) {
			t.Fatalf("send on a down line: %v", err)
		}
	}
	if len(k.kinds) != 3 {
		t.Fatalf("offered %d times", len(k.kinds))
	}
}
