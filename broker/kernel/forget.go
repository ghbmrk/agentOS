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

const ForgetAskFor int64 = 600_000 // ms

var (
	ErrForgetName  = errors.New("kernel: a Forget needs a name in plain letters that something live is under, so nothing is erased")
	ErrForgetReply = errors.New("kernel: no Forget waits for that reply, so nothing was erased")
	ErrForgetStop  = errors.New("kernel: STOP holds, so no Forget is asked")
)

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
	all := "everything"
	if len(unread) > 0 {
		all = "everything I can read" // a label that cannot be read may name it too
	}
	kinds := map[string]int{}
	for _, s := range subjects {
		for _, it := range k.s.subjects[s].items {
			kinds[it.Class]++
		}
	}
	delete(kinds, ClassLabel)
	n, list, items := 0, "", "nothing but the name"
	for _, c := range slices.Sorted(maps.Keys(kinds)) {
		n += kinds[c]
		list += fmt.Sprintf(", %s %d", c, kinds[c])
	}
	if n > 0 {
		items = fmt.Sprintf("%d %s (%s)", n, map[bool]string{true: "item", false: "items"}[n == 1], list[2:])
	}
	var b [8]byte // 10^6 codes from 2^64 draws: no code is notably likelier
	if _, err := io.ReadFull((*k.log.p).cfg.Rand, b[:]); err != nil {
		return "", err
	}
	k.forget = &forgetAsk{subjects, fmt.Sprintf("%06d", binary.BigEndian.Uint64(b[:])%1_000_000), now.Earliest + ForgetAskFor}
	return fmt.Sprintf("Forget %s under “%s”, %s? Reply YES %s to forget it. Any other reply, or none within 10 minutes, forgets nothing.",
		all, label, items, k.forget.code), nil
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
