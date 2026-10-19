package recall

// REQ: CRED-1

import (
	"math/rand/v2"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
)

// The gates in front of the scrub patterns only skip work: whenever a
// pattern matches, its gate is open, including for the Unicode case variants
// a (?i) pattern accepts (the Kelvin sign for k, the long s for s). Synthetic
// shapes only.
func TestAnchoredGatesNeverSkipAMatch(t *testing.T) {
	guarded := map[int]*regexp.Regexp{
		gatePEM: pemBlock, gateOTPAuth: otpauthURI, gateAuthHeader: authHeader, gateAuthScheme: authScheme,
		gateSecretKV: secretKV, gateKnownTokens: knownTokens, gateURL: urlRe,
		gateKeyedCodes: codeKey, gateGroupedCodes: codeRun,
	}
	if len(guarded) != len(anchoredGates) {
		t.Fatalf("%d gates, %d patterns under test", len(anchoredGates), len(guarded))
	}
	frags := []string{
		"password", "passwd", "passcode", "passphrase", "pass", "pwd", "pin", "secret", "client_secret", "client-secret",
		"clientsecret", "api_key", "api-key", "apikey", "access_key", "access-token", "refresh_token", "id_token", "idtoken",
		"session", "session_id", "sessionid", "cookie", "set-cookie", "proxy-authorization", "authorization", "x-api-key",
		"x-auth-token", "recovery codes", "recovery_code", "recoverycode", "backup code", "backup-codes", "code(s)", "totp",
		"2fa seed", "2fa_seed", "seed", "bearer", "basic", "token", "digest", "otpauth://totp/x", "https://h/p",
		"-----BEGIN RSA KEY-----", "-----END RSA KEY-----", "eyJabcdefgh.abcdefgh.abcdefgh",
		"ghp_" + strings.Repeat("a", 20), "github_pat_" + strings.Repeat("b", 20), "sk-ant-" + strings.Repeat("c", 20),
		"AKIA" + strings.Repeat("Q", 16), "xoxb-" + strings.Repeat("d", 10),
		"is", " is ", " are ", ":", "=", ": ", "\n", " ", "\t", "Zq9vLm2xWp", "A7KQ-M3XZ-9RTB", "a.b", "x_y",
	}
	variant := map[rune][]string{'k': {"k", "K", "K"}, 's': {"s", "S", "ſ"}}
	r := rand.New(rand.NewPCG(1, 2))
	mutate := func(f string) string {
		var b strings.Builder
		for _, c := range f {
			lc := c | 0x20
			switch v, ok := variant[lc]; {
			case c < 0x80 && ok && r.IntN(3) == 0:
				b.WriteString(v[r.IntN(len(v))])
			case c >= 'a' && c <= 'z' && r.IntN(2) == 0:
				b.WriteRune(c - 'a' + 'A')
			case c >= 'A' && c <= 'Z' && r.IntN(2) == 0:
				b.WriteRune(c - 'A' + 'a')
			default:
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	for i := 0; i < 50000; i++ {
		var b strings.Builder
		for n := 1 + r.IntN(6); n > 0; n-- {
			b.WriteString(mutate(frags[r.IntN(len(frags))]))
		}
		s := b.String()
		sk := caseSkeleton(s)
		for g, re := range guarded {
			if re.MatchString(s) && !anchoredGates[g](s, sk) {
				t.Fatalf("gate %d closed on %q, which %v matches", g, s, re)
			}
		}
	}
	for _, s := range []string{"toKen abcdefgh12", "paſſ: x", "api_Key=x", "ſeſſion: x"} {
		sk := caseSkeleton(s)
		for g, re := range guarded {
			if re.MatchString(s) && !anchoredGates[g](s, sk) {
				t.Fatalf("gate %d closed on %q, which %v matches", g, s, re)
			}
		}
	}
}

// A mail can hold any number of keys. Before keyedRun read its list lazily,
// every recovery code key read the rest of the text, so 64 KB of keys took
// 18 s and grew with the square of the length (review of #2228). Each input
// here is 64 KB; the bound is far above linear cost and far below that.
func TestManyKeysScrubFast(t *testing.T) {
	sc := NewScrubber(nil)
	for name, unit := range map[string]string{
		"keyed":   "recovery code: A1 ",
		"prose":   "Your backup codes are below, see notes. ",
		"kv":      "password: x ",
		"is":      "pin is 1234 ",
		"header":  "Authorization: Bearer abcdefgh12\n",
		"token":   "ghp_" + strings.Repeat("a", 20) + " ",
		"url":     "https://u:p@h/p?token=x ",
		"removed": "secret: " + Removed + " ",
		"folded":  "ｒｅｃｏｖｅｒｙ ｃｏｄｅ： Ａ１ ",
	} {
		in := strings.Repeat(unit, 65536/len(unit)+1)
		start := time.Now()
		out := sc.Scrub(in)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v for %d bytes", name, d, len(in))
		}
		if name == "keyed" && strings.Contains(out, "A1") {
			t.Errorf("keyed: a code survived")
		}
	}
}

// skeletonByte gives every rune the small ASCII letter in its case-fold
// orbit, as a (?i) pattern folds it, and 0 when the orbit holds none.
func TestSkeletonMatchesFoldOrbits(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want := byte(0)
		if r < 0x80 {
			want = byte(unicode.ToLower(r))
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f >= 'a' && f <= 'z' {
				want = byte(f)
			}
		}
		if got := skeletonByte(r); got != want {
			t.Fatalf("skeletonByte(%U) = %q, want %q", r, got, want)
		}
	}
}

// secretKVMatches finds exactly what secretKV's FindAll finds, word
// boundaries, Unicode case variants and invalid UTF-8 included. Synthetic
// shapes only.
func TestSecretKVMatchesFindAll(t *testing.T) {
	frags := []string{
		"password", "passwd", "passcode", "passphrase", "pass", "pwd", "pin", "secret", "client_secret", "client-secret",
		"clientsecret", "client", "api_key", "api-key", "apikey", "api", "access_key", "access-token", "accesstoken", "refresh_token",
		"refresh", "id_token", "idtoken", "id", "session", "session_id", "session-id", "sessionid", "cookie", "recovery codes",
		"recovery_code", "recovery-codes", "backup code", "backupcodes", "totp", "2fa seed", "2fa_seed", "2fa", "seed",
		"is", " is ", "is ", ":", "=", ": ", " = ", "\t", "\n", "\r\n", " ", ",", ";", "x", "_", "-", "9", "\"", "'",
		"\"q v\"", "'q v'", "Zq9vLm2x", Removed, "\xff", "é", "K", "ſ", "Ａ",
	}
	variant := map[rune][]string{'k': {"k", "K", "K"}, 's': {"s", "S", "ſ"}}
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for n := 1 + r.IntN(8); n > 0; n-- {
			for _, c := range frags[r.IntN(len(frags))] {
				switch v, ok := variant[c|0x20]; {
				case c < 0x80 && ok && r.IntN(4) == 0:
					b.WriteString(v[r.IntN(len(v))])
				case c >= 'a' && c <= 'z' && r.IntN(3) == 0:
					b.WriteRune(c - 'a' + 'A')
				default:
					b.WriteRune(c)
				}
			}
		}
		s := b.String()
		if got, want := secretKVMatches(s), secretKV.FindAllStringSubmatchIndex(s, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got %v, want %v", s, got, want)
		}
	}
}
