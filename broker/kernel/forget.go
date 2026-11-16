package kernel

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// A Forget erases only on the owner's YES (D-314, #5124): a passkey never
// shows what it signs, so the kernel renders the ask from every subject
// Named finds (the name as typed, items by kind, never content), the owner
// side texts it unchanged, and ForgetReply hands the subjects out only for
// "YES <code>" from it. One ask waits at a time, unlogged: a newer ask,
// STOP, any other reply, ForgetAskFor or a restart ends it, erasing nothing.
// The text names the time a reply has, which a wide reading shortens; a
// reading too wide for any reply to arrive in time asks nothing.

const ForgetAskFor int64 = 600_000 // ms

var (
	ErrForgetName  = errors.New("kernel: a Forget needs a name in plain letters that something live is under, so nothing is erased")
	ErrForgetReply = errors.New("kernel: no Forget waits for that reply, so nothing was erased")
	ErrForgetStop  = errors.New("kernel: STOP holds, so no Forget is asked")
	// ErrForgetClock is the owner's text as it stands: a reading at least
	// ForgetAskFor wide has lapsed the ask before it is sent (TIM-1, CH-12).
	// The kernel process's clock (proc's onLog) keeps a forward step of the
	// box clock as width until it starts again, and a start commits the step,
	// ending KEY-8 and KEY-4 holds early if the box clock is wrong-ahead. A
	// wrong clock may only make the box more cautious (TIM-1's interval
	// rule), so the text names no restart for the owner to make: it names
	// the weekly restart (UPD-10), which commits the step anyway (KRN-clock-a).
	ErrForgetClock = errors.New("I can't ask to forget anything right now, because my two clocks disagree by 10 minutes or more, so nothing is erased. Send FORGET again after my weekly restart.")
)

// kindWords names a kind as the household says it, for one and for more; the
// ask calls any other kind an "other item" (#5163).
var kindWords = map[string][2]string{
	"message":          {"message", "messages"},
	"photo":            {"photo", "photos"},
	"vision-wrap-key":  {"face", "faces"},
	"retrieve-vectors": {"search entry", "search entries"},
}

type forgetAsk struct {
	subjects []string
	code     string
	until    int64
}

// AskForget holds every live subject under label until the owner's YES,
// and returns the text that asks for it.
func (k *Kernel) AskForget(at int64, label string) (string, error) {
	now := k.read(at)
	k.forget = nil
	if k.s.Stopped {
		return "", ErrForgetStop
	}
	subjects, unread, err := k.Named(label)
	if err != nil || len(subjects) == 0 || len(label) > MaxShown || strings.ContainsFunc(label, func(r rune) bool {
		return !unicode.In(r, unicode.L, unicode.M, unicode.N) && !strings.ContainsRune(" -_.,()'’/+&@", r)
	}) {
		return "", errors.Join(ErrForgetName, err)
	}
	// ForgetReply refuses a YES once Latest reaches the lapse, so it would
	// refuse every YES while Latest does not narrow; were it to narrow, the
	// refusal costs one retry and never an unwanted erase.
	// The YES is refused once Latest has run left more, wherever true time
	// sits in the reading, so the text promises left rounded down; under a
	// second no promise is true, and the refusal's "10 minutes or more" is
	// true to the second (#5938).
	left := now.Earliest + ForgetAskFor - now.Latest
	if left < 1_000 {
		return "", ErrForgetClock
	}
	within := plural(left/60_000, "minute")
	if left < 60_000 {
		within = plural(left/1_000, "second")
	}
	all := "everything"
	if len(unread) > 0 {
		all = "everything I can read" // a label that cannot be read may name it too
	}
	kinds, other := map[[2]string]int{}, [2]string{"other item", "other items"}
	for _, s := range subjects {
		for _, it := range k.s.subjects[s].items {
			if w, ok := kindWords[it.Class]; ok {
				kinds[w]++
			} else if it.Class != ClassLabel {
				kinds[other]++
			}
		}
	}
	rank := func(w [2]string) string { // by word, other items last
		if w == other {
			return "\x7f"
		}
		return w[0]
	}
	var list []string
	for _, w := range slices.SortedFunc(maps.Keys(kinds), func(a, b [2]string) int { return strings.Compare(rank(a), rank(b)) }) {
		list = append(list, fmt.Sprintf("%d %s", kinds[w], w[min(kinds[w], 2)-1]))
	}
	items := "nothing but the name"
	if len(list) > 0 {
		items = strings.Join(list, ", ")
	}
	var b [8]byte // 10^6 codes from 2^64 draws: no code is notably likelier
	if _, err := io.ReadFull((*k.log.p).cfg.Rand, b[:]); err != nil {
		return "", err
	}
	k.forget = &forgetAsk{subjects, fmt.Sprintf("%06d", binary.BigEndian.Uint64(b[:])%1_000_000), now.Earliest + ForgetAskFor}
	return fmt.Sprintf("Forget %s under “%s”, %s? Reply YES %s to forget it. Any other reply, or none within %s, forgets nothing.",
		all, label, items, k.forget.code, within), nil
}

func plural(n int64, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// ForgetReply ends the waiting ask and, if reply is "YES <code>" from its
// text (any case and punctuation) in time, returns its subjects for Erase.
func (k *Kernel) ForgetReply(at int64, reply string) ([]string, error) {
	now := k.read(at)
	a := k.forget
	k.forget = nil
	f := strings.FieldsFunc(strings.ToUpper(reply), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	if a == nil || now.Latest >= a.until || len(f) != 2 || f[0] != "YES" || subtle.ConstantTimeCompare([]byte(f[1]), []byte(a.code)) != 1 {
		return nil, ErrForgetReply
	}
	return a.subjects, nil
}
