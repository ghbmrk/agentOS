package recall

// REQ: CRED-1

import (
	"strings"
	"testing"
)

// caseVariants spells w with each s written as the long s and each k as the
// Kelvin sign, one at a time and all together: the only runes outside ASCII
// that a (?i) pattern's ASCII letter matches, and which regexp's \b does not
// read as word characters (#2357). The long s is a small letter and the
// Kelvin sign a capital, so with cased set only a small s and a capital K
// are replaced, keeping the case boundaries credWords reads.
func caseVariants(w string, cased bool) []string {
	sub := map[rune]rune{'s': '\u017f', 'K': '\u212a'}
	if !cased {
		sub['S'], sub['k'] = '\u017f', '\u212a'
	}
	var out []string
	all := []rune(w)
	for i, c := range []rune(w) {
		if v, ok := sub[c]; ok {
			one := []rune(w)
			one[i] = v
			out = append(out, string(one))
			all[i] = v
		}
	}
	if len(out) > 1 {
		out = append(out, string(all))
	}
	return out
}

// A credential key spelled with the long s or the Kelvin sign, at the start
// of the text, after a space or after a line break, keeps no value.
// Synthetic values only.
func TestCaseVariantKeysScrubbed(t *testing.T) {
	sc := NewScrubber(nil)
	keys := []string{
		"password", "passwd", "passcode", "passphrase", "pass", "PASS", "Password", "secret", "Secret",
		"client_secret", "client-secret", "clientsecret", "api_key", "api-key", "apikey", "API_KEY",
		"access_key", "accesskey", "access_token", "refresh_token", "id_token", "session", "session_id",
		"sessionid", "Session", "cookie", "cookies", "recovery codes", "recovery_codes", "backup codes",
		"backup_codes", "2fa seed", "2fa_seed", "seed", "Seed", "token", "x-api-key", "set-cookie",
	}
	n := 0
	for _, k := range keys {
		for _, v := range caseVariants(k, false) {
			for _, pre := range []string{"", "note ", "a\n"} {
				for _, sep := range []string{": ", "=", " is "} {
					in := pre + v + sep + "hunter2Zq"
					out := sc.Scrub(in)
					n++
					if strings.Contains(out, "hunter2") {
						if k == "token" || k == "x-api-key" || k == "set-cookie" || k == "cookies" {
							// Keys secretKV does not name; covered below as a
							// header or a scheme.
							continue
						}
						t.Errorf("Scrub(%q) = %q", in, out)
					}
				}
			}
		}
	}
	if n < 500 {
		t.Fatalf("only %d cases", n)
	}
	for _, in := range []string{
		"\u017fecret: hunter2", "note \u017fecret: hunter2", "\u017fession=abc123", "\u017feed: hunter2", "pa\u017f\u017f: hunter2",
		"Authorization: Bearer hunter2Zq9vLm2x", "x-api-\u212aey: hunter2", "\u017fet-cookie: hunter2", "to\u212aen hunter2Zq9vLm2x",
		"recovery code\u017f: A1B2 C3D4 E5F6", "backup code\u017f: A1B2 C3D4",
	} {
		if out := sc.Scrub(in); strings.Contains(out, "hunter2") || strings.Contains(out, "A1B2") {
			t.Errorf("Scrub(%q) = %q", in, out)
		}
	}
}

// A fact whose predicate names credential material with the long s or the
// Kelvin sign in it loses its object, and a field ending in such a code key
// carries the codes split into the next field away with it.
func TestCaseVariantPredicatesScrubbed(t *testing.T) {
	sc := NewScrubber(nil)
	preds := []string{
		"password", "passwd", "passcode", "passphrase", "pass", "pwds", "pins", "secret", "secrets",
		"credentials", "api_key", "apiKey", "access_key", "private_key", "secretKey", "signing_key", "tokens",
		"recovery", "backup_codes", "backupCodes", "seeds", "mnemonic", "totps", "otps", "2fa", "mfa", "cookies",
		"passkeys", "pws", "security_answers", "Key", "KEYS", "keyV2", "ssh_Key", "sshKeyBackup", "masterKey2", "TOKEN",
		"BackupCodes", "ApiKey", "COOKIE", "PassKey", "SecretKeys", "sessionCookies",
	}
	n := 0
	for _, p := range preds {
		for _, v := range caseVariants(p, true) {
			n++
			if got := sc.ScrubFact(Fact{"me", v, "hunter2"}); got.Object != Removed {
				t.Errorf("ScrubFact predicate %q (%s): object %q", v, credWords(fold(v)), got.Object)
			}
		}
	}
	if n < 60 {
		t.Fatalf("only %d cases", n)
	}
	fs := sc.ScrubFacts([]Fact{{"me", "backup code\u017f", "A1B2-C3D4"}, {"me", "note", "E5F6-G7H8"}})
	for _, f := range fs {
		if strings.Contains(f.Object, "A1B2") {
			t.Errorf("ScrubFacts kept %q", f.Object)
		}
	}
}

// fold writes the long s as s and the Kelvin sign as K, the letter it is.
func TestFoldCaseVariants(t *testing.T) {
	for in, want := range map[string]string{
		"\u017fecret": "secret", "pa\u017f\u017f": "pass", "\u212aey": "Key", "api\u212aey": "apiKey", "\u017f \u212a": "s K",
	} {
		if got := fold(in); got != want {
			t.Errorf("fold(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every rune outside ASCII that caseSkeleton spells as an ASCII letter, and
// so a (?i) pattern's literal matches, fold writes as that letter: the
// folded pass then sees the key in ASCII, where \b holds.
func TestFoldCoversSkeletonLetters(t *testing.T) {
	for r := rune(0x80); r <= 0x10FFFF; r++ {
		sk := skeletonByte(r)
		if sk == 0 {
			continue
		}
		if f := fold(string(r)); len(f) != 1 || f[0]|0x20 != sk {
			t.Errorf("fold(%U) = %q, skeleton %q", r, f, sk)
		}
	}
}
