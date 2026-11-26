package card

// Mutant kills for #6000 (KRN-keys-print-factors): storekey_test.go's
// secret.Hide edit made every line its tests run a mutation target, and
// these statements had no test that failed when they were deleted. Each
// test here fails on one or more such deletions (named by line at
// 32b378b3).

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// REQ: REC-1

// stream is a deterministic byte source: SHA-256 in counter mode. failAt,
// when non-zero, makes that one Read call (counted from 1) fail; every
// other call succeeds, so a statement that swallows the error lets
// Generate carry on to a whole card.
type stream struct {
	ctr, calls, failAt int
	buf                []byte
}

// errStream is the planted read failure. A type, not an initialized
// var: mutgate reads a changed package-level var as reaching every test.
type errStream struct{}

func (errStream) Error() string { return "stream: planted read failure" }

func (s *stream) Read(p []byte) (int, error) {
	s.calls++
	if s.calls == s.failAt {
		return 0, errStream{}
	}
	for len(s.buf) < len(p) {
		h := sha256.Sum256([]byte{byte(s.ctr), byte(s.ctr >> 8), byte(s.ctr >> 16)})
		s.buf = append(s.buf, h[:]...)
		s.ctr++
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func fixedCard(t *testing.T) *Card {
	t.Helper()
	c, err := Generate(&stream{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Each read Generate makes can fail; every failure must come back as an
// error with no card, never a card built past it (card.go:61, :69, :167,
// :179, :190).
func generateFailsOnEveryReadError(t *testing.T) {
	probe := &stream{}
	if _, err := Generate(probe); err != nil {
		t.Fatal(err)
	}
	if probe.calls < 4 {
		t.Fatalf("Generate made %d reads, want one per value at least", probe.calls)
	}
	for k := 1; k <= probe.calls; k++ {
		c, err := Generate(&stream{failAt: k})
		if err == nil || c != nil {
			t.Fatalf("read %d of %d failing: Generate returned (%v, %v), want (nil, error)", k, probe.calls, c != nil, err)
		}
		if !errors.Is(err, errStream{}) {
			t.Fatalf("read %d failing: error %v does not wrap the read error", k, err)
		}
	}
}

// Validate refuses each value that is not its full size or form, with
// every other value valid (card.go:90, :93, :94, :100, :106, :110, :113,
// :114, :118).
func validateRefusesEachBadValue(t *testing.T) {
	if err := fixedCard(t).Validate(); err != nil {
		t.Fatalf("a generated card: %v", err)
	}
	cases := []struct {
		name string
		edit func(c *Card)
		want string
	}{
		{"short setup secret", func(c *Card) {
			c.SetupSecret = group(Normalize(c.SetupSecret)[:setupSymbols-1], 4)
			c.SetupCode = SetupCodeFor(c.SetupSecret)
		}, "setup secret has 25 symbols"},
		{"setup secret symbol off the alphabet", func(c *Card) {
			c.SetupSecret = group("0"+Normalize(c.SetupSecret)[1:], 4)
			c.SetupCode = SetupCodeFor(c.SetupSecret)
		}, "outside the alphabet"},
		{"setup code of another secret", func(c *Card) {
			c.SetupCode = SetupCodeFor(group(strings.Repeat("A", setupSymbols), 4))
		}, "setup code does not match"},
		{"passphrase a word short", func(c *Card) {
			ws := strings.Fields(c.VaultPassphrase)
			c.VaultPassphrase = strings.Join(ws[1:], " ")
		}, "passphrase has"},
		{"passphrase word off the list", func(c *Card) {
			ws := strings.Fields(c.VaultPassphrase)
			ws[len(ws)-1] = "qqqqzzzz"
			c.VaultPassphrase = strings.Join(ws, " ")
		}, "is not on the list"},
		{"grid seed short", func(c *Card) { c.GridSeed = c.GridSeed[:gridSeedBytes-1] }, "grid seed too short"},
	}
	for _, tc := range cases {
		c := fixedCard(t)
		tc.edit(c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate = %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
}

// The setup code is HMAC-SHA256 keyed by the normalized secret over the
// domain string "agentos setup code v1": a known answer pins the domain
// string, so a code printed by one build pairs on another (card.go:129).
func setupCodeKnownAnswer(t *testing.T) {
	const secret = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-23"
	if got, want := SetupCodeFor(secret), "956A-7TYD"; got != want {
		t.Fatalf("SetupCodeFor(%q) = %q, want %q", secret, got, want)
	}
	if !CheckSetupCode(strings.ToLower(secret), "956a 7tyd") {
		t.Fatal("CheckSetupCode refused the code typed in lower case with a space")
	}
}

// A mistyped group returns no partial key: the bits already read from the
// groups before it are cleared from the returned array, for both a symbol
// off the alphabet and a failed check symbol (recoverykey.go:118, :124).
func mistypedRecoveryKeyReturnsNoPartialKey(t *testing.T) {
	gs := strings.Split(fixedCard(t).RecoveryKey, "-")
	if len(gs) != recoveryGroups {
		t.Fatalf("recovery key %d groups", len(gs))
	}
	if b, err := parseRecoveryKey(strings.Join(gs, "-")); err != nil || b == ([recoveryKeyBytes]byte{}) {
		t.Fatalf("the valid key: %v, %x", err, b)
	}
	check := gs[1][recoveryGroupKey]
	other := Alphabet[(strings.IndexByte(Alphabet, check)+1)%len(Alphabet)]
	for name, g2 := range map[string]string{
		"symbol off the alphabet": "I" + gs[1][1:],
		"wrong check symbol":      gs[1][:recoveryGroupKey] + string(other),
	} {
		bad := append([]string{gs[0], g2}, gs[2:]...)
		b, err := parseRecoveryKey(strings.Join(bad, "-"))
		var me *MistypedError
		if !errors.As(err, &me) || me.Group != 2 {
			t.Fatalf("%s: err %v, want a MistypedError for group 2", name, err)
		}
		if b != ([recoveryKeyBytes]byte{}) {
			t.Fatalf("%s: the refused key returned bits %x", name, b)
		}
	}
}

// mutgateKills runs, as subtests of TestRotationNeedsAPart, the checks this PR adds here.
// mutgate reads an init or package var of this package, or of one it
// imports, as order-dependent, so a new top-level test changes the run list
// and makes every test of the package a changed test (#6000). These run as
// subtests of TestRotationNeedsAPart instead.
func mutgateKills(t *testing.T) {
	t.Run("GenerateFailsOnEveryReadError", generateFailsOnEveryReadError)
	t.Run("ValidateRefusesEachBadValue", validateRefusesEachBadValue)
	t.Run("SetupCodeKnownAnswer", setupCodeKnownAnswer)
	t.Run("MistypedRecoveryKeyReturnsNoPartialKey", mistypedRecoveryKeyReturnsNoPartialKey)
	t.Run("DisplayNeedsAProvisioner", displayNeedsAProvisioner)
}

// A display with a good authority but no provisioner is refused before it
// draws any randomness, so a card is never shown that Confirm cannot keep.
func displayNeedsAProvisioner(t *testing.T) {
	r := &countingRand{}
	d, err := NewDisplay(DisplayConfig{Rand: r, Authority: testAuthority(t)})
	if err == nil || d != nil || !strings.Contains(err.Error(), "provisioner") || r.n != 0 {
		t.Fatalf("no provisioner: %v %v, %d bytes read", d, err, r.n)
	}
}
