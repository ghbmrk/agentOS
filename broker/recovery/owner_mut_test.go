package recovery

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// These tests pin owner.go's lost-phone and lost-number steps line by line
// (OWN-page-session mutants part 4, #5849): each fails if one statement
// or comparison they name is removed or turned.

var errShort = errors.New("test: the random source ran dry")

// dryReader yields n bytes, then fails.
type dryReader struct{ n int }

func (r *dryReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errShort
	}
	k := min(len(p), r.n)
	for i := range p[:k] {
		p[i] = 7
	}
	r.n -= k
	return k, nil
}

func TestReEnrollStopsWhenTheRandomSourceFails(t *testing.T) {
	x := newBox(t)
	if _, err := ReEnroll(x.b, x.rk, true, &dryReader{n: 3}); err == nil {
		t.Fatal("a short random seed was enrolled")
	}
	s, ok := x.b.V.Secret(SeedName)
	if !ok || !bytes.Equal([]byte(s.Reveal()), x.seed) {
		t.Fatal("a failed re-enrollment replaced the seed")
	}
}

func TestReEnrollRefusesASeedEntryOfAnotherKind(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Put(SeedName, vault.KindAPIKey, []byte("sk-synthetic-not-a-seed")))
	if _, err := ReEnroll(x.b, x.rk, true, nil); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("err = %v, want ErrWrongKind", err)
	}
	if k, _ := entryKind(x.b.V, SeedName); k != vault.KindAPIKey {
		t.Fatalf("the entry of another kind was overwritten: kind %q", k)
	}
}

func TestOtpauthNamesEveryParameterTheCodeGeneratorNeeds(t *testing.T) {
	u, err := url.Parse(otpauth([]byte("12345678901234567890")))
	must(t, err)
	label, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":")
	q := u.Query()
	want := url.Values{"secret": {"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}, "issuer": {label},
		"algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	if u.Scheme != "otpauth" || u.Host != "totp" || label == "" || len(q) != len(want) {
		t.Fatalf("otpauth = %s", u)
	}
	for k, v := range want {
		if q.Get(k) != v[0] {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v[0])
		}
	}
}

func TestBeginNumberChangeStopsWhenTheRandomSourceFails(t *testing.T) {
	x := newBox(t)
	if nc, err := BeginNumberChange(x.b, x.rk, true, t0, &dryReader{n: 5}); err == nil || nc != nil {
		t.Fatalf("a short random pairing code was issued: %v, %v", nc, err)
	}
}

func TestPairingCodeIsTheRandomBytesModuloOneHundredMillion(t *testing.T) {
	x := newBox(t)
	// 0x0102030405060708 = 72623859790382856; mod 1e8 = 90382856.
	nc, err := BeginNumberChange(x.b, x.rk, true, t0, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	must(t, err)
	if nc.Code != "90382856" {
		t.Fatalf("code = %q, want 90382856", nc.Code)
	}
	if !nc.Expires.Equal(t0.Add(PairingTTL)) {
		t.Fatalf("expires = %v", nc.Expires)
	}
}

func TestANilNumberChangeCompletesNothing(t *testing.T) {
	var nc *NumberChange
	if n, _, err := nc.Complete(ownerNum, "+15550000002", "12345678", t0); n != "" || !errors.Is(err, ErrPairing) {
		t.Fatalf("nil change completed: %q, %v", n, err)
	}
}

func TestOnlyEightDigitsCountAsAPairingTry(t *testing.T) {
	for s, want := range map[string]bool{
		"12345678": true, "00000000": true, "99999999": true,
		"1234567": false, "123456789": false, "": false,
		"1234a678": false, "/2345678": false, ":2345678": false, "1234567:": false,
	} {
		if got := eightDigits(s); got != want {
			t.Errorf("eightDigits(%q) = %v, want %v", s, got, want)
		}
	}
}

// failStore fails its Load, or records its Save.
type failStore struct {
	load  error
	saved *owner.State
}

func (f *failStore) Load() (owner.State, error) {
	return owner.State{UnlockedUntil: t0, GridUsed: []string{"A1"}}, f.load
}

func (f *failStore) Save(s owner.State) error { f.saved = &s; return nil }

func TestEndSessionSavesNothingWhenTheStoreCannotLoad(t *testing.T) {
	st := &failStore{load: errShort}
	if err := EndSession(st, true); !errors.Is(err, errShort) {
		t.Fatalf("err = %v", err)
	}
	if st.saved != nil {
		t.Fatalf("saved %+v over a state it could not read", *st.saved)
	}
}

func TestTailShowsAtMostTheLastFourDigits(t *testing.T) {
	for in, want := range map[string]string{"": "", "1234": "1234", "12345": "...2345", "+15550000002": "...0002"} {
		if got := tail(in); got != want {
			t.Errorf("tail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrimSpaceOfBlankBodies(t *testing.T) {
	for in, want := range map[string]string{"": "", " ": "", " \t\r\n ": "", "  1  ": "1", "\n12345678\r\n": "12345678",
		"\t12345678": "12345678", "12345678\t": "12345678", " 12345678": "12345678", "12345678 ": "12345678", "\r12345678": "12345678", "12345678\r": "12345678", "\n12345678": "12345678", "12345678\n": "12345678"} {
		if got := trimSpace(in); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.TrimSpace(" x ") != trimSpace(" x ") {
		t.Fatal("trimSpace differs from strings.TrimSpace on ASCII space")
	}
}

func TestAWrongPairingCodeCompletesNothingAndThreeEndTheAttempt(t *testing.T) {
	nc := &NumberChange{Code: "12345678", Expires: t0.Add(PairingTTL)}
	const newNum = "+15550000002"
	for i := 0; i < 3; i++ {
		if n, _, err := nc.Complete(ownerNum, newNum, "87654321", t0); n != "" || !errors.Is(err, ErrPairing) {
			t.Fatalf("wrong code %d completed: %q, %v", i+1, n, err)
		}
	}
	if n, _, err := nc.Complete(ownerNum, newNum, "12345678", t0); n != "" || !errors.Is(err, ErrPairing) {
		t.Fatalf("the right code after three wrong ones completed: %q, %v", n, err)
	}
	ok := &NumberChange{Code: "12345678", Expires: t0.Add(PairingTTL)}
	if n, txt, err := ok.Complete(ownerNum, newNum, " 12345678\n", t0); err != nil || n != newNum || !strings.Contains(txt.ToOld, "...0002") {
		t.Fatalf("the right code: %q, %+v, %v", n, txt, err)
	}
}
