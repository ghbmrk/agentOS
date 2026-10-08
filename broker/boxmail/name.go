// Package boxmail holds the broker's side of the box's own mailbox
// (ADP-13). This file is the address choice on the Wi-Fi page: four
// choices, each checked with the provider as available before it is shown
// (the box's name, an adjective and noun, email.assistant.<digits>, and one
// the owner types, checked live), a shuffle that asks again, and the
// confirm screen's wording. An address never contains a phone number.
//
// Creating the account (a credentialed executor, CRED-4b), its recovery and
// upkeep are later parts; the provider check is Config.Available, which
// that executor will answer.
package boxmail

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Kind says which of the page's four choices an address is.
type Kind int

const (
	FromName Kind = iota // the box's name: dave.smith
	Words                // a random adjective and noun: sleepy.llama
	Digits               // email.assistant.<random digits>
	Owner                // one the owner types
)

// Choice is one address the page may show: its local part, checked as
// available when it was offered.
type Choice struct {
	Kind  Kind
	Local string
}

// Config is what an offer needs.
type Config struct {
	// Name is the box's name (CH-21), e.g. "Dave Smith".
	Name string
	// Available asks the provider whether a local part is free. An error
	// stops the offer: nothing is shown as available that was not checked.
	Available func(ctx context.Context, local string) (bool, error)
	// Intn returns a uniform int in [0, n); nil uses crypto/rand.
	Intn func(n int) int
}

var (
	// ErrForm: a typed name is not 3 to 30 lowercase letters, digits and
	// single inner dots.
	ErrForm = errors.New("boxmail: use 3 to 30 letters, digits and single dots")
	// ErrPhoneNumber: the name holds seven or more digits, which could be
	// a phone number.
	ErrPhoneNumber = errors.New("boxmail: an address never contains a phone number")
	// ErrTaken: the provider says the name is in use.
	ErrTaken = errors.New("boxmail: that address is taken")
)

const (
	// maxTries bounds the provider checks for each generated kind.
	maxTries = 4
	// maxDigits is the most digits an address may hold: seven or more
	// could be a phone number (ADP-13).
	maxDigits = 6
	minLen    = 3
	maxLen    = 30
)

var adjectives = []string{
	"sleepy", "sunny", "quiet", "brave", "clever", "gentle", "lucky", "merry",
	"nimble", "patient", "steady", "tidy", "witty", "cheerful", "calm", "bright",
}

var nouns = []string{
	"llama", "otter", "falcon", "maple", "harbor", "pebble", "comet", "meadow",
	"badger", "willow", "lantern", "heron", "acorn", "beacon", "puffin", "cedar",
}

// Offer returns the generated choices in page order (name, words, digits),
// each one the provider said is free. A kind with nothing free after
// maxTries checks is left out; the box's name gets a two-digit suffix when
// taken, and no choice when it does not fold to an address. Calling Offer
// again is the shuffle. The fourth choice is the owner's (Typed).
func Offer(ctx context.Context, cfg Config) ([]Choice, error) {
	intn := cfg.Intn
	if intn == nil {
		intn = cryptoIntn
	}
	var out []Choice
	if base := localFromName(cfg.Name); base != "" {
		c, err := first(ctx, cfg, FromName, func(try int) string {
			if try == 0 {
				return base
			}
			return fmt.Sprintf("%s.%d", base, 10+intn(90))
		})
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	c, err := first(ctx, cfg, Words, func(int) string {
		return adjectives[intn(len(adjectives))] + "." + nouns[intn(len(nouns))]
	})
	if err != nil {
		return nil, err
	}
	out = append(out, c...)
	c, err = first(ctx, cfg, Digits, func(int) string {
		return fmt.Sprintf("email.assistant.%04d", intn(10000))
	})
	if err != nil {
		return nil, err
	}
	return append(out, c...), nil
}

// first checks up to maxTries candidates of one kind and returns the first
// free one, or none.
func first(ctx context.Context, cfg Config, k Kind, next func(try int) string) ([]Choice, error) {
	for try := 0; try < maxTries; try++ {
		local := next(try)
		if formErr(local) != nil {
			continue
		}
		ok, err := cfg.Available(ctx, local)
		if err != nil {
			return nil, err
		}
		if ok {
			return []Choice{{Kind: k, Local: local}}, nil
		}
	}
	return nil, nil
}

// Typed checks the owner's own choice live: its form first (lowercased and
// trimmed), then the provider. Nothing malformed, or holding a phone
// number, is sent to the provider.
func Typed(ctx context.Context, cfg Config, s string) (Choice, error) {
	local := strings.ToLower(strings.TrimSpace(s))
	if err := formErr(local); err != nil {
		return Choice{}, err
	}
	ok, err := cfg.Available(ctx, local)
	if err != nil {
		return Choice{}, err
	}
	if !ok {
		return Choice{}, ErrTaken
	}
	return Choice{Kind: Owner, Local: local}, nil
}

// ConfirmText is the confirm screen's wording, in the box's first-person
// voice (CH-21): the final address, and that it cannot be renamed later.
func ConfirmText(addr string) string {
	return fmt.Sprintf("My address will be %s. It cannot be renamed later; a new address would replace it.", addr)
}

// formErr reports whether local may be an address: the phone-number rule
// first, then the form.
func formErr(local string) error {
	if digitCount(local) > maxDigits {
		return ErrPhoneNumber
	}
	if len(local) < minLen || len(local) > maxLen {
		return ErrForm
	}
	for _, part := range strings.Split(local, ".") {
		if part == "" {
			return ErrForm
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return ErrForm
			}
		}
	}
	return nil
}

// digitCount counts the digits in s, wherever they are, so a number split
// by dots still counts whole.
func digitCount(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// fold maps the accented Latin letters a name commonly holds to plain
// ones; a letter outside a-z and this table gives no name choice.
var fold = map[rune]string{
	'\u00e0': "a", '\u00e1': "a", '\u00e2': "a", '\u00e3': "a", '\u00e4': "a", '\u00e5': "a",
	'\u00e7': "c",
	'\u00e8': "e", '\u00e9': "e", '\u00ea': "e", '\u00eb': "e",
	'\u00ec': "i", '\u00ed': "i", '\u00ee': "i", '\u00ef': "i",
	'\u00f1': "n",
	'\u00f2': "o", '\u00f3': "o", '\u00f4': "o", '\u00f5': "o", '\u00f6': "o", '\u00f8': "o",
	'\u00f9': "u", '\u00fa': "u", '\u00fb': "u", '\u00fc': "u",
	'\u00fd': "y", '\u00ff': "y",
	'\u00df': "ss",
}

// localFromName turns the box's name into dot-joined lowercase words
// ("Dave Smith" to dave.smith), dropping hyphens and apostrophes. A name
// with digits, another script, or too short or long a result gives "".
func localFromName(name string) string {
	var words []string
	for _, w := range strings.Fields(strings.ToLower(name)) {
		var b strings.Builder
		for _, r := range w {
			switch {
			case r >= 'a' && r <= 'z':
				b.WriteRune(r)
			case r == '-' || r == '\'' || r == '\u2019':
			case fold[r] != "":
				b.WriteString(fold[r])
			default:
				return ""
			}
		}
		if b.Len() > 0 {
			words = append(words, b.String())
		}
	}
	local := strings.Join(words, ".")
	if formErr(local) != nil {
		return ""
	}
	return local
}

func cryptoIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("boxmail: crypto/rand: " + err.Error())
	}
	return int(v.Int64())
}
