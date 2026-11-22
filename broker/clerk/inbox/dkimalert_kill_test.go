package inbox

// REQ: VRB-2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"maps"
	"slices"
	"strings"
	"testing"
)

// killSigned is "From: a@sig.test" mail signed with testKey under tags (no
// bh= or b=, which it adds), and testKey's base64 public key.
func killSigned(t *testing.T, tags string) (raw []byte, key string) {
	t.Helper()
	head := "From: a@sig.test\r\nSubject: Hi\r\n"
	body := []byte("Hello.\r\n")
	bh := sha256.Sum256(relaxedBody(body, -1))
	sig := tags + "; bh=" + base64.StdEncoding.EncodeToString(bh[:]) + "; b="
	hs, _ := splitMessage([]byte(head + "\r\n"))
	var in []byte
	for _, p := range signedHeaders(hs, strings.Split(sigTags([]byte(sig))["h"], ":")) {
		in = append(in, relaxedHeader(string(p.name), p.value)...)
	}
	in = append(in, strings.TrimRight(string(relaxedHeader("DKIM-Signature", []byte(" "+sig))), "\r\n")...)
	sum := sha256.Sum256(in)
	b, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return []byte("DKIM-Signature: " + sig + base64.StdEncoding.EncodeToString(b) + "\r\n" + head + "\r\n" + string(body)),
		base64.StdEncoding.EncodeToString(der)
}

// The relaxed body folds runs of space within a line, drops trailing space
// and trailing empty lines, and ends the last line with CRLF.
func TestRelaxedBodyFoldsSpaceAndTrailingLines(t *testing.T) {
	cases := map[string]string{
		"a \t b  \r\n\r\n\r\n": "a b\r\n",
		"a  b":                 "a b\r\n",
		"\r\n\r\n":             "",
	}
	for in, want := range cases {
		if got := string(relaxedBody([]byte(in), -1)); got != want {
			t.Errorf("relaxedBody(%q) = %q, want %q", in, got, want)
		}
	}
}

// An empty tag is skipped, and a repeated one fails the whole list.
func TestSigTagsSkipsEmptyAndRefusesRepeats(t *testing.T) {
	got := sigTags([]byte(" v=1;; a = b ;"))
	if want := map[string]string{"v": "1", "a": "b"}; !maps.Equal(got, want) {
		t.Errorf("sigTags = %v, want %v", got, want)
	}
	if got := sigTags([]byte("d=a; d=b")); got != nil {
		t.Errorf("sigTags with d= twice = %v, want nil", got)
	}
}

// Each check verifyOne makes fails a signature that is otherwise good: the
// control case passes, and every changed one does not.
func TestVerifyOneRefusesEachBadPart(t *testing.T) {
	const base = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sig.test"
	good, key := killSigned(t, base+"; s=s1; h=from:subject")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	name := "s1._domainkey.sig.test"
	verify := func(raw []byte, keys map[string]string) bool {
		sigs := VerifyDKIM(raw, keys)
		if len(sigs) != 1 {
			t.Fatalf("VerifyDKIM gave %d results, want 1", len(sigs))
		}
		return sigs[0].Pass
	}
	if !verify(good, map[string]string{name: key}) {
		t.Fatal("the good signature does not pass")
	}
	sha1, _ := killSigned(t, "v=1; a=rsa-sha1; c=relaxed/relaxed; d=sig.test; s=s1; h=from:subject")
	noFrom, _ := killSigned(t, base+"; s=s1; h=subject")
	noS, _ := killSigned(t, base+"; h=from:subject")
	// The b= value with a bad character after it: decoding stops at the
	// character and keeps every byte of the signature before it.
	badB := []byte(strings.Replace(string(good), "\r\nFrom:", "!\r\nFrom:", 1))
	cases := []struct {
		name string
		raw  []byte
		keys map[string]string
	}{
		{"a=rsa-sha1", sha1, map[string]string{name: key}},
		{"h= without from", noFrom, map[string]string{name: key}},
		{"no s= but a key under the empty name", noS, map[string]string{"": key}},
		{"an ECDSA key", good, map[string]string{name: base64.StdEncoding.EncodeToString(ecDER)}},
		{"a key record with a bad character after it", good, map[string]string{name: key + "!"}},
		{"a b= with a bad character after it", badB, map[string]string{name: key}},
		{"no key", good, nil},
	}
	for _, c := range cases {
		if verify(c.raw, c.keys) {
			t.Errorf("%s: the signature passes", c.name)
		}
	}
}

// DKIMNames reads only DKIM-Signature fields, and only those naming both s=
// and d=.
func TestDKIMNamesReadsOnlyNamedSignatures(t *testing.T) {
	raw := []byte("X-Note: v=1; d=other.test; s=s1\r\n" +
		"DKIM-Signature: v=1; d=sig.test; h=from\r\n" +
		"DKIM-Signature: v=1; s=s2; h=from\r\n" +
		"DKIM-Signature: v=1; d=sig.test; s=s3; h=from\r\n" +
		"From: a@sig.test\r\n\r\nHello.\r\n")
	if got, want := DKIMNames(raw), []string{"s3._domainkey.sig.test"}; !slices.Equal(got, want) {
		t.Errorf("DKIMNames = %q, want %q", got, want)
	}
}

// smtpHop ignores the date after the last ";", and refuses two "by" or two
// "with" clauses.
func TestSMTPHopReadsOneByAndOneWith(t *testing.T) {
	cases := []struct {
		v    string
		by   string
		smtp bool
	}{
		{"from a by mx.test with ESMTPS id 1; Sun, 25 Oct 2026 with x", "mx.test", true},
		{"from a by one.test by two.test with ESMTP id 1", "", false},
		{"from a by mx.test with HTTP with ESMTP id 1", "", false},
	}
	for _, c := range cases {
		if by, ok := smtpHop(c.v); by != c.by || ok != c.smtp {
			t.Errorf("smtpHop(%q) = %q, %v, want %q, %v", c.v, by, ok, c.by, c.smtp)
		}
	}
}

// Below the provider's SMTP hop no Received is read, and an
// Authentication-Results above that hop ends the walk with none.
func TestProviderAuthResultsStopsAtTheProvidersHop(t *testing.T) {
	const prov = "Received: from relay.test by mx.test with ESMTPS id 1; Sun, 25 Oct 2026\r\n"
	cases := []struct {
		head, want string
	}{
		{prov + "Received: from inside by relay.test; Sun, 25 Oct 2026\r\nAuthentication-Results: mx.test; dmarc=pass\r\n", " mx.test; dmarc=pass"},
		{"Authentication-Results: mx.test; dmarc=fail\r\n" + prov + "Authentication-Results: mx.test; dmarc=pass\r\n", ""},
	}
	for _, c := range cases {
		hs, _ := splitMessage([]byte(c.head + "\r\n"))
		if got := providerAuthResults(hs, "mx.test"); got != c.want {
			t.Errorf("providerAuthResults(%q) = %q, want %q", c.head, got, c.want)
		}
	}
}

// Results of other methods do not decide DMARC.
func TestDMARCPassIgnoresOtherMethods(t *testing.T) {
	h := "mx.test; spf=fail smtp.mailfrom=x.test; dmarc=pass header.from=bank.test"
	if !dmarcPass(h, "a@bank.test", "mx.test") {
		t.Errorf("dmarcPass(%q) = false, want true", h)
	}
}

// Addresses and entries match whatever their case and surrounding space; a
// blank entry matches nothing, not even a domain ending in a dot.
func TestSenderInFoldsCaseAndSkipsBlankEntries(t *testing.T) {
	cases := []struct {
		addr    string
		entries []string
		want    bool
	}{
		{"Alerts@Bank.test", []string{"alerts@bank.test"}, true},
		{"alerts@bank.test", []string{" ALERTS@bank.test "}, true},
		{"a@bank.test.", []string{"", " "}, false},
		{"b@bank.test", []string{"a@bank.test"}, false},
	}
	for _, c := range cases {
		if got := senderIn(c.addr, c.entries); got != c.want {
			t.Errorf("senderIn(%q, %q) = %v, want %v", c.addr, c.entries, got, c.want)
		}
	}
}
