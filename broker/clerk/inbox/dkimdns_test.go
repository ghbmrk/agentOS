package inbox

// REQ: VRB-2, D-154

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// signedBy is a mail from from signed for d under selector s; key is the
// base64 public key its record serves.
func signedBy(t *testing.T, from, d, s string) (raw []byte, key string) {
	t.Helper()
	head := "From: " + from + "\r\nSubject: Hi\r\n"
	body := []byte("Hello.\r\n")
	bh := sha256.Sum256(relaxedBody(body, -1))
	sig := "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + d + "; s=" + s + "; h=from:subject; bh=" +
		base64.StdEncoding.EncodeToString(bh[:]) + "; b="
	hs, _ := splitMessage([]byte(head + "\r\n"))
	var in []byte
	for _, p := range signedHeaders(hs, []string{"from", "subject"}) {
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

// The names DKIMNames gives are the keys VerifyDKIM reads, for a Unicode
// d=, mixed case and a dotted selector: a key served under each makes the
// signature pass. Fails if the two forms drift.
func TestDKIMNamesMatchVerifyOne(t *testing.T) {
	for _, c := range []struct{ from, d, s, want string }{
		{"news@bücher.test", "bücher.test", "s1", "s1._domainkey.xn--bcher-kva.test"},
		{"news@News.Example.TEST", "News.Example.TEST", "Sel2026", "Sel2026._domainkey.news.example.test"},
		{"news@shop.test", "shop.test", "a.b", "a.b._domainkey.shop.test"},
	} {
		raw, key := signedBy(t, c.from, c.d, c.s)
		names := DKIMNames(raw)
		if !slices.Equal(names, []string{c.want}) {
			t.Fatalf("%s: DKIMNames %q, want %q", c.d, names, c.want)
		}
		sigs := VerifyDKIM(raw, map[string]string{names[0]: key})
		if len(sigs) != 1 || !sigs[0].Pass {
			t.Fatalf("%s: a key served under %q did not verify: %+v", c.d, names[0], sigs)
		}
	}
}

// fakeTXT serves TXT answers by rooted name and records every query.
type fakeTXT struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	hang    bool
	queries []string
}

func (f *fakeTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.queries = append(f.queries, name)
	a, err, hang := f.answers[name], f.errs[name], f.hang
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("no such name")
	}
	return a, nil
}

func (f *fakeTXT) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.queries)
}

// Only a name with exactly one usable key record is kept: two DKIM
// records, a wrong version, key type, hash or service, a test flag, an
// empty or non-base64 p=, an oversized answer and an error all leave the
// name absent. Every query is rooted.
func TestLookupDKIMRecords(t *testing.T) {
	const p = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	bad := map[string][]string{
		"two":     {"v=DKIM1; p=" + p, "v=DKIM1; p=" + p},
		"v2":      {"v=DKIM2; p=" + p},
		"vlate":   {"k=rsa; v=DKIM1; p=" + p},
		"ed":      {"v=DKIM1; k=ed25519; p=" + p},
		"sha1":    {"v=DKIM1; h=sha1; p=" + p},
		"tlsrpt":  {"v=DKIM1; s=tlsrpt; p=" + p},
		"test":    {"v=DKIM1; t=y; p=" + p},
		"testsy":  {"v=DKIM1; t=s:y; p=" + p},
		"revoked": {"v=DKIM1; p="},
		"b64":     {"v=DKIM1; p=not*base64"},
		"big":     {"v=DKIM1; p=" + p + strings.Repeat("A", 9<<10)},
	}
	f := &fakeTXT{answers: map[string][]string{
		"good._domainkey.shop.test.":  {"v=DKIM1; k=rsa; h=sha1:sha256; s=email; t=s; p=" + p[:20] + " " + p[20:], "v=spf1 -all"},
		"split._domainkey.shop.test.": {"v=DKIM1; p=" + p},
	}, errs: map[string]error{"err._domainkey.shop.test.": errors.New("servfail")}}
	names := []string{"good._domainkey.shop.test", "split._domainkey.shop.test", "err._domainkey.shop.test"}
	for k, v := range bad {
		n := k + "._domainkey.shop.test"
		f.answers[n+"."] = v
		names = append(names, n)
	}
	got := LookupDKIM(context.Background(), f, names)
	want := map[string]string{"good._domainkey.shop.test": p, "split._domainkey.shop.test": p}
	if len(got) != len(want) || got["good._domainkey.shop.test"] != p || got["split._domainkey.shop.test"] != p {
		t.Fatalf("kept %v, want only %v", got, want)
	}
	for _, q := range f.asked() {
		if !strings.HasSuffix(q, ".") {
			t.Fatalf("query %q is not rooted", q)
		}
	}
	if len(f.asked()) != len(names) {
		t.Fatalf("%d queries for %d names: a lookup was retried or skipped", len(f.asked()), len(names))
	}
}

// Three signatures on one mail look up two names; 500 names look up 400; a
// name over 253 bytes or with an empty label is not looked up; a resolver
// that hangs ends at the per-read bound.
func TestLookupDKIMBounds(t *testing.T) {
	var three []byte
	for _, s := range []string{"a", "b", "c"} {
		raw, _ := signedBy(t, "news@shop.test", "shop.test", s)
		sig, _, _ := strings.Cut(string(raw), "\r\n")
		three = append(three, sig+"\r\n"...)
	}
	three = append(three, "From: news@shop.test\r\n\r\nHi\r\n"...)
	if ns := KeyNames([][]byte{three}); len(ns) != 2 {
		t.Fatalf("three signatures gave %d names, want 2: %q", len(ns), ns)
	}

	var many []string
	for i := range 500 {
		many = append(many, fmt.Sprintf("s%d._domainkey.shop.test", i))
	}
	long := strings.Repeat("a.", 127) + "test" // 258 bytes
	f := &fakeTXT{answers: map[string][]string{}}
	LookupDKIM(context.Background(), f, append([]string{long, "s.._domainkey.shop.test", "._domainkey.shop.test"}, many...))
	asked := f.asked()
	if len(asked) != 400 {
		t.Fatalf("%d names looked up, want 400", len(asked))
	}
	for _, q := range asked {
		if q == long+"." || strings.Contains(q, "..") || strings.HasPrefix(q, ".") {
			t.Fatalf("an invalid name was looked up: %q", q)
		}
	}

	prevRead, prevOne := dkimReadWait, dkimLookupWait
	dkimReadWait, dkimLookupWait = 200*time.Millisecond, time.Hour
	defer func() { dkimReadWait, dkimLookupWait = prevRead, prevOne }()
	start := time.Now()
	got := LookupDKIM(context.Background(), &fakeTXT{hang: true}, many)
	if d := time.Since(start); d > 2*time.Second || len(got) != 0 {
		t.Fatalf("a hanging resolver held the read %v and gave %v; want the per-read bound and nothing", d, got)
	}
}
