package boxmail

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// REQ: ADP-13

// fakeProvider answers the availability check from a taken set and
// records every local part it was asked about.
type fakeProvider struct {
	taken  map[string]bool
	asked  []string
	failOn string
}

func (p *fakeProvider) available(_ context.Context, local string) (bool, error) {
	p.asked = append(p.asked, local)
	if p.failOn != "" && local == p.failOn {
		return false, errors.New("provider unreachable")
	}
	return !p.taken[local], nil
}

// seq is a deterministic Intn: it walks vals, wrapping, each modulo n.
func seq(vals ...int) func(int) int {
	i := 0
	return func(n int) int {
		v := vals[i%len(vals)]
		i++
		return v % n
	}
}

func asked(p *fakeProvider, local string) bool {
	for _, a := range p.asked {
		if a == local {
			return true
		}
	}
	return false
}

var (
	wordsRe  = regexp.MustCompile(`^[a-z]+\.[a-z]+$`)
	digitsRe = regexp.MustCompile(`^email\.assistant\.[0-9]{4}$`)
)

// The page offers the box's name, an adjective and noun, and
// email.assistant.<digits>, each checked as available before it is shown.
func TestOfferThreeCheckedChoices(t *testing.T) {
	p := &fakeProvider{}
	got, err := Offer(context.Background(), Config{Name: "Dave Smith", Available: p.available, Intn: seq(3, 7, 1, 2, 3, 4)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("choices %+v", got)
	}
	if got[0].Kind != FromName || got[0].Local != "dave.smith" {
		t.Errorf("name choice %+v", got[0])
	}
	if got[1].Kind != Words || !wordsRe.MatchString(got[1].Local) {
		t.Errorf("words choice %+v", got[1])
	}
	if got[2].Kind != Digits || !digitsRe.MatchString(got[2].Local) {
		t.Errorf("digits choice %+v", got[2])
	}
	for _, c := range got {
		if !asked(p, c.Local) {
			t.Errorf("%q offered without an availability check", c.Local)
		}
	}
}

// A taken address is never shown: another of the same kind is tried, and
// a kind with nothing free after its tries is left out.
func TestOfferSkipsTakenAddresses(t *testing.T) {
	p := &fakeProvider{taken: map[string]bool{"dave.smith": true}}
	got, err := Offer(context.Background(), Config{Name: "Dave Smith", Available: p.available, Intn: seq(5, 9, 2, 8)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if p.taken[c.Local] {
			t.Errorf("taken %q offered", c.Local)
		}
	}
	if got[0].Kind != FromName || !strings.HasPrefix(got[0].Local, "dave.smith.") || !asked(p, "dave.smith") {
		t.Errorf("name choice after a taken name: %+v (asked %v)", got[0], p.asked)
	}

	all := &fakeProvider{}
	all.taken = map[string]bool{}
	every := func(ctx context.Context, local string) (bool, error) {
		all.asked = append(all.asked, local)
		return false, nil
	}
	got, err = Offer(context.Background(), Config{Name: "Dave Smith", Available: every, Intn: seq(1, 2, 3)})
	if err != nil || len(got) != 0 {
		t.Errorf("nothing free: %+v, %v", got, err)
	}
	if len(all.asked) > 3*maxTries {
		t.Errorf("%d checks for three kinds", len(all.asked))
	}
}

// The shuffle control asks again and gets new random choices.
func TestShuffleOffersNewChoices(t *testing.T) {
	p := &fakeProvider{}
	cfg := Config{Name: "Dave Smith", Available: p.available, Intn: seq(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)}
	a, err := Offer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Offer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a[1].Local == b[1].Local && a[2].Local == b[2].Local {
		t.Errorf("shuffle gave the same choices: %+v, %+v", a, b)
	}
}

// An address never contains a phone number: a typed one with seven or
// more digits, split by dots or not, is refused before any provider check,
// and a box name with a number in it gives no name choice.
func TestAddressNeverHoldsAPhoneNumber(t *testing.T) {
	for _, s := range []string{"dave.2125551234", "d.212.555.1234", "5551234.box", "call.me.0044.20.7946.0958"} {
		p := &fakeProvider{}
		if _, err := Typed(context.Background(), Config{Available: p.available}, s); !errors.Is(err, ErrPhoneNumber) {
			t.Errorf("%q: %v", s, err)
		}
		if len(p.asked) != 0 {
			t.Errorf("%q checked with the provider: %v", s, p.asked)
		}
	}
	p := &fakeProvider{}
	got, err := Offer(context.Background(), Config{Name: "Dave 2125551234", Available: p.available, Intn: seq(1, 2, 3)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Kind == FromName || digitCount(c.Local) >= 7 {
			t.Errorf("choice %+v", c)
		}
	}
	for i := 0; i < 50; i++ {
		got, _ := Offer(context.Background(), Config{Name: "Dave Smith", Available: p.available, Intn: seq(i, 9, 9, 9, 9, 9, 9)})
		for _, c := range got {
			if digitCount(c.Local) >= 7 {
				t.Errorf("generated %q", c.Local)
			}
		}
	}
}

// The owner's own choice is checked live: its form first, then the
// provider.
func TestTypedCheckedLive(t *testing.T) {
	p := &fakeProvider{taken: map[string]bool{"dave": true}}
	cfg := Config{Available: p.available}
	for _, s := range []string{"", "ab", ".dave", "dave.", "da..ve", "Dave Smith", "dave+box", "dave@example.com", strings.Repeat("a", 31)} {
		if _, err := Typed(context.Background(), cfg, s); !errors.Is(err, ErrForm) {
			t.Errorf("%q: %v", s, err)
		}
	}
	if len(p.asked) != 0 {
		t.Errorf("malformed names checked: %v", p.asked)
	}
	if _, err := Typed(context.Background(), cfg, "dave"); !errors.Is(err, ErrTaken) {
		t.Errorf("taken: %v", err)
	}
	c, err := Typed(context.Background(), cfg, "  Dave.Box ")
	if err != nil || c.Kind != Owner || c.Local != "dave.box" || !asked(p, "dave.box") {
		t.Errorf("typed: %+v, %v", c, err)
	}
}

// A failed availability check shows nothing as available.
func TestCheckFailureOffersNothing(t *testing.T) {
	p := &fakeProvider{failOn: "dave.smith"}
	got, err := Offer(context.Background(), Config{Name: "Dave Smith", Available: p.available, Intn: seq(1)})
	if err == nil || len(got) != 0 {
		t.Errorf("got %+v, %v", got, err)
	}
	if _, err := Typed(context.Background(), Config{Available: p.available}, "dave.smith"); err == nil || errors.Is(err, ErrTaken) {
		t.Errorf("typed: %v", err)
	}
}

// Accented Latin names fold to plain letters; other scripts give no name
// choice rather than a mangled one.
func TestNameFolding(t *testing.T) {
	for name, want := range map[string]string{
		"Dave Smith":                "dave.smith",
		"  Mary   Ann  Lee ":        "mary.ann.lee",
		"Jos\u00e9 N\u00fa\u00f1ez": "jose.nunez",
		"Anne-Marie O'Neil":         "annemarie.oneil",
		"\u738b\u5c0f\u660e":        "",
		"Q":                         "",
	} {
		if got := localFromName(name); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}

// The confirm screen shows the final address and says it cannot be
// renamed later.
func TestConfirmText(t *testing.T) {
	got := ConfirmText("dave.smith@example.com")
	if !strings.Contains(got, "dave.smith@example.com") || !strings.Contains(got, "cannot be renamed later") {
		t.Errorf("%q", got)
	}
}
