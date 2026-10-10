package recall

// REQ: CRED-1, CAP-3

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
)

const (
	upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower = "abcdefghijklmnopqrstuvwxyz"
)

// Property: a random letters-only token of 16 or more characters, with no
// grouping and no key beside it, is removed at every length, in one case or
// mixed. Before RECALL-canary-2 one under 20 characters was always kept, and
// 16% of 20-letter and 3% of 24-letter uppercase ones were too.
func TestRandomLettersRemoved(t *testing.T) {
	r := canaryRand(t)
	sc := NewScrubber(nil)
	lengths := []int{48, 64, 96}
	for n := 16; n <= 40; n++ {
		lengths = append(lengths, n)
	}
	for _, n := range lengths {
		for _, a := range []string{upper, lower, upper + lower} {
			for i := 0; i < 600; i++ {
				v := pick(r, a, n)
				if out := sc.Scrub(v); out != Removed {
					t.Fatalf("alone: %q -> %q", v, out)
				}
				if out := sc.Scrub("use (" + v + "), then"); strings.Contains(out, v[:15]) {
					t.Fatalf("in text: %q -> %q", v, out)
				}
			}
		}
	}
}

// capture is a 30-letter run the old floors kept (entropy 3.48, under 3.5;
// Security R6 on #624): canary-1's leaked code without its dashes.
var capture = strings.ReplaceAll(leakedCode, "-", "")

// Deterministic regressions: the 30-letter run, a digit-free base32 TOTP seed
// (with and without padding), and a 16-letter token, as text, fact object and
// URL path segment, on disk and through Get.
func TestLettersOnlyRegressions(t *testing.T) {
	const (
		seed  = "JMNOXCPMGJJYTLJOOYJGPXOYYJDNTGJM" // 32 base32 letters, no digit, entropy 3.34
		short = "QZXWVKJPMRTBLGHF"
	)
	path := filepath.Join(t.TempDir(), "recall")
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ix := open(t, st)
	var cs []canary
	for _, v := range []string{capture, seed, seed + "====", short, strings.ToLower(short)} {
		core := strings.TrimRight(v, "=")
		cs = append(cs, canary{"letters", v, core})
		id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "https://example.org/k/" + v},
			Text:  "Keep this safe: " + v + ".",
			Facts: []Fact{{"account", "note", v}}})
		it, _ := ix.Get(id)
		if hits := leaked(cs[len(cs)-1:], it.Text+" "+it.Source.Ref+" "+it.Facts[0].Object); len(hits) > 0 {
			t.Fatalf("returned %q: %q %q %+v", v, it.Text, it.Source.Ref, it.Facts)
		}
	}
	if hits := leaked(cs, string(readDir(t, path))); len(hits) > 0 {
		t.Fatalf("stored: %v", hits)
	}
}

// The floor trades recall for custody (R11). Real words and identifiers of 16
// or more letters, in any case style, are kept when the letter model finds
// them likelier as English than as random letters; words far from English
// letter patterns are removed like random tokens. Moving a line between these
// lists is a deliberate change to that trade.
func TestLongWordsTradeoff(t *testing.T) {
	sc := NewScrubber(nil)
	kept := []string{
		"internationalization", "INTERNATIONALIZATION", "Internationalization",
		"counterproductive", "uncharacteristically", "misunderstandings",
		"telecommunications", "characterization", "disproportionately",
		"interchangeability", "overcompensation", "institutionalization",
		"compartmentalization", "unconstitutional", "incomprehensibilities",
		"establishmentarianism",
		"getAccountSettingsForUser", "XMLHttpRequestUpload", "NSURLSessionConfiguration",
		"InternalServerError", "handleIncomingMessage", "TestCredentialsNeverStored",
		"AbstractSingletonProxyFactoryBean", "onBeforeUnloadHandler", "UnsubscribeFromNewsletter",
		"MaxConcurrentStreams", "DescribeInstances", "ListObjectVersions",
	}
	for _, w := range kept {
		in := "see " + w + " here"
		if out := sc.Scrub(in); out != in {
			t.Errorf("expected kept: %q -> %q", in, out)
		}
	}
	for _, w := range []string{
		"responsibilities", "acknowledgements", // 21.8 bits each
		"electroencephalogram", "straightforwardly", // 19.0, 18.6
		"Rechtsschutzversicherung", // German compound
		"Llanfairpwllgwyngyll",     // Welsh place name
	} {
		if out := sc.Scrub(w); out != Removed {
			t.Errorf("expected removal: %q -> %q", w, out)
		}
	}
}

// The floor's miss rate rests on the letter model being a probability
// distribution: in every context, the probabilities its entries stand for sum
// to at most one. Then a uniformly random letter string scores at least F
// bits with probability at most 2^-F, at any length (Markov's inequality on
// 2^score), so a corrupt or hand-edited table fails here.
func TestLetterModelNormalized(t *testing.T) {
	if len(letterModel) != 26*26+26*26*26 {
		t.Fatalf("model size %d", len(letterModel))
	}
	for ctx := 0; ctx < len(letterModel)/26; ctx++ {
		var s float64
		for _, q := range letterModel[ctx*26 : ctx*26+26] {
			s += math.Exp2(float64(int8(q))/letterScale) / 26
		}
		if s > 1 {
			t.Fatalf("context %d sums to %v", ctx, s)
		}
	}
	if wordFloor < 24*letterScale {
		t.Fatalf("floor %d is under 24 bits", wordFloor)
	}
}

// A fact whose predicate names credential material has its object removed
// whole: the object alone may look like an ordinary word, and the predicate is
// the only context saying it is a secret. One subtest per predicate family.
func TestCredentialPredicateRemovesObject(t *testing.T) {
	const obj = "Sunflower Tuesday"
	for _, tc := range []struct{ name, preds string }{
		{"password", "password,Password,passwd,passphrase,passcode,pwd,new_password,wifiPassword,PIN"},
		{"recovery", "recovery,recovery_code,recoveryCodes,Recovery Codes,backup_codes,backup code"},
		{"api_key", "api_key,apiKey,APIKey,API-Key,access_key,secret_key,private_key,client_secret,access_token,refreshToken,token"},
		{"seed", "seed,totp_seed,2fa seed,seed phrase,seedPhrase,mnemonic,totp,otp_secret"},
		// Acronym plurals and trailing digits (Security 4a point 1).
		{"spelling", "PINs,OTPs,TOTPs,PINsReset,password1,pin2,PIN2,backupCodes2,PWs,PWDs,2FA,2FA_code,2FACodes,2FA seed,TOTP2FA,oauth2Token,OAuth2Token,aes256Key,ssh2Key,v2Password,user1Password,account2Pin,sha256Secret,md5Token,x509Key,ed25519Key,2FaCode,v2PIN,user1PWD,v2OTP,app2TOTP"},
		// Any predicate ending in key(s), and other names (Security 4a point 2).
		{"key", "ssh_key,sshKey,SSH key,encryption_key,master_key,license_key,keys,passkey,pw,security_answer,securityAnswers,key2,keyV2,master_key2,ssh_key_1,ssh_key_2,encryptionKeyV2,ssh_keys_old,sshKeyBackup,master_key_hex,license_key_value,gpgKeyId,walletKeys1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recall")
			st, err := OpenDir(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			ix := open(t, st)
			for _, p := range strings.Split(tc.preds, ",") {
				id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<" + p + "@x>"},
					Text: "note", Facts: []Fact{{"account", p, obj}}})
				it, _ := ix.Get(id)
				if f := it.Facts[0]; f.Object != Removed || f.Predicate != p {
					t.Fatalf("predicate %q: %+v", p, f)
				}
			}
			if strings.Contains(string(readDir(t, path)), "Sunflower") {
				t.Fatal("object stored")
			}
		})
	}
}

// Every spelling of a credential word with a digit or version beside it
// removes the object: each word in lower, Title and UPPER case, with each
// affix before or after it, joined by nothing, '_' or a case change
// (Security and L3 round 4 on #642). Skipped: spellings with no word
// boundary where the parts meet (v2password is split, v22fa, passwordv2
// and PASSWORDV2 are not; RECALL-canary-6), and a leading key with a
// lettered qualifier after it (key_user1; LATER RECALL-canary-2 l5).
func TestCredentialWordAffixes(t *testing.T) {
	sc := NewScrubber(nil)
	words := []string{"password", "passwd", "passcode", "passphrase", "pwd", "pw", "pin", "secret", "credential", "token", "recovery", "seed", "mnemonic", "otp", "totp", "2fa", "mfa", "cookie", "passkey", "key"}
	affixes := []string{"v2", "user1", "x509", "256"}
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	upper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	capital := func(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
	n := 0
	for _, w := range words {
		for _, cased := range []string{w, capital(w), strings.ToUpper(w)} {
			for _, a := range affixes {
				for _, j := range []string{"", "_", "camel"} {
					right := a
					if j == "camel" {
						right = capital(a)
					}
					for i, lr := range [][2]string{{a, cased}, {cased, right}} {
						if i == 0 && j == "camel" {
							lr[1] = capital(cased)
						}
						left, right := lr[0], lr[1]
						p := left + right
						if j == "_" {
							p = left + "_" + right
						}
						// The words meet at a boundary: '_', letter against
						// digit, or a capital after a non-capital or opening
						// a capitalised word. Without one the split is ambiguous.
						l, r := left[len(left)-1], right[0]
						split := j == "_" || digit(l) != digit(r) ||
							upper(r) && (!upper(l) || len(right) > 1 && right[1] >= 'a' && right[1] <= 'z')
						if !split || w == "key" && i == 1 && !digit(a[0]) && a != "v2" {
							continue // ambiguous, or a lettered qualifier after a leading key (l5)
						}
						n++
						if got := sc.ScrubFact(Fact{"account", p, "Sunflower Tuesday"}); got.Object != Removed {
							t.Errorf("%q (%s) kept its object", p, credWords(p))
						}
					}
				}
			}
		}
	}
	if n < 300 {
		t.Fatalf("only %d spellings checked", n)
	}
}

// Predicates that only resemble credential names keep their object.
func TestOtherPredicatesKeepObject(t *testing.T) {
	sc := NewScrubber(nil)
	for _, p := range []string{"email", "employer", "passport_country", "pinned_note", "seeded_by", "keyboard", "tokenizer", "birthday", "compass", "key_points", "keys_count", "keynote", "keyring", "monkey", "PINned", "pwm_duty", "answer"} {
		f := Fact{"account", p, "Sunflower Tuesday"}
		if got := sc.ScrubFact(f); got != f {
			t.Errorf("%q: %+v", p, got)
		}
	}
}
