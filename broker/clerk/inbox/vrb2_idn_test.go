package inbox

// REQ: VRB-2 (assumptions MIG-3-R3, MIG-3-R4)

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// signed is a one-click bulk mail from from, its List-Unsubscribe at url,
// signed (over-signed, relaxed/relaxed) for d with the extra tags; keys is
// the key record it verifies under.
func signed(t *testing.T, from, url, d, extra string) (raw []byte, keys map[string]string) {
	t.Helper()
	head := "From: News <" + from + ">\r\nTo: owner@home.test\r\nSubject: Offers\r\n" +
		"List-Unsubscribe: <" + url + ">\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	body := []byte("Hello.\r\n")
	bh := sha256.Sum256(relaxedBody(body, -1))
	h := "from:from:list-unsubscribe:list-unsubscribe:list-unsubscribe-post:list-unsubscribe-post"
	sig := "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + d + "; s=s1; h=" + h + extra +
		"; bh=" + base64.StdEncoding.EncodeToString(bh[:]) + "; b="
	hs, _ := splitMessage([]byte(head + "\r\n"))
	var in []byte
	for _, p := range signedHeaders(hs, strings.Split(h, ":")) {
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
	raw = []byte("DKIM-Signature: " + sig + base64.StdEncoding.EncodeToString(b) + "\r\n" + head + "\r\n" + string(body))
	return raw, map[string]string{"s1._domainkey." + alabel(d): base64.StdEncoding.EncodeToString(der)}
}

// world is a day on which from's mail, first seen in June, may be
// unsubscribed from.
func world(keys map[string]string, from string) World {
	return World{
		DKIMKeys: keys,
		History:  []Delivery{{From: from, Folder: "inbox", Date: "2026-06-01"}},
		Today:    "2026-10-19",
	}
}

func unix(t *testing.T, s string) string {
	t.Helper()
	d, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(d.Unix(), 10)
}

// A DKIM pass counts only while the signature is current against the
// world's day: one expired (x=), expiring at any hour of today, or signed
// after today (t=) is not, and a malformed or reversed t= and x= fails
// (RFC 6376 section 3.5, #2602).
func TestDKIMSignatureMustBeCurrentOnToday(t *testing.T) {
	const from = "news@shop.test"
	for _, c := range []struct {
		name, extra, today, want string
	}{
		{"no t or x", "", "", ROK},
		{"signed yesterday, expires next week", "; t=" + unix(t, "2026-10-18T09:00:00Z") + "; x=" + unix(t, "2026-10-26T00:00:00Z"), "", ROK},
		{"signed today", "; t=" + unix(t, "2026-10-19T23:00:00Z"), "", ROK},
		{"expires at the end of today", "; x=" + unix(t, "2026-10-20T00:00:00Z"), "", ROK},
		{"expired yesterday", "; x=" + unix(t, "2026-10-18T12:00:00Z"), "", RDKIMNotCurrent},
		{"expires during today", "; x=" + unix(t, "2026-10-19T12:00:00Z"), "", RDKIMNotCurrent},
		{"signed tomorrow", "; t=" + unix(t, "2026-10-20T00:00:00Z"), "", RDKIMNotCurrent},
		{"x before t", "; t=" + unix(t, "2026-10-18T00:00:00Z") + "; x=" + unix(t, "2026-10-17T00:00:00Z"), "", RDKIMFail},
		{"x equal to t", "; t=1760000000; x=1760000000", "", RDKIMFail},
		{"x not digits", "; x=never", "", RDKIMFail},
		{"x past 12 digits", "; x=1234567890123", "", RDKIMFail},
		{"t signed and today unreadable", "; t=" + unix(t, "2026-10-18T00:00:00Z"), "19 Oct", RBadDate},
	} {
		raw, keys := signed(t, from, "https://shop.test/u", "shop.test", c.extra)
		w := world(keys, from)
		if c.today != "" {
			w.Today = c.today
		}
		if got, _ := Evaluate(raw, w); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A Unicode domain and its punycode are one name: for the organizational
// domain, DKIM alignment, the URL host, history and the owner's opens, so a
// sender written one way and recorded the other is neither refused for it
// nor unsubscribed while its mail is still opened (#2602).
func TestIDNDomainsCompareInALabelForm(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"bücher.example", "xn--bcher-kva.example"},
		{"news.BÜCHER.example.", "xn--bcher-kva.example"},
		{"mail.xn--bcher-kva.co.uk", "bücher.co.uk"},
	} {
		if !aligned(c.a, c.b) {
			t.Errorf("aligned(%q, %q) = false (orgs %q, %q)", c.a, c.b, org(c.a), org(c.b))
		}
	}
	if o := org("news.bücher.example"); o != "xn--bcher-kva.example" {
		t.Errorf("org is %q, want the A-label", o)
	}
	for _, d := range []string{"ｂücher.example", "a_b.example", "xn--zz.example"} {
		if o := org(d); o != "" {
			t.Errorf("org(%q) = %q, want none for a name IDNA refuses", d, o)
		}
	}

	const uFrom, aFrom = "news@bücher.test", "news@xn--bcher-kva.test"
	cases := []struct {
		name, from, url, d string
		w                  func(World) World
		want               string
	}{
		{"unicode from, punycode d and url", uFrom, "https://xn--bcher-kva.test/u", "xn--bcher-kva.test", nil, ROK},
		{"punycode from, unicode d and url", aFrom, "https://bücher.test/u", "bücher.test", nil, ROK},
		{"history recorded in the other form", uFrom, "https://bücher.test/u", "bücher.test",
			func(w World) World { w.History[0].From = aFrom; return w }, ROK},
		{"provider table in the other form", uFrom, "https://mail.bücher-hub.test/u", "bücher.test",
			func(w World) World { w.ProviderTable = []string{"xn--bcher-hub-q9a.test"}; return w }, ROK},
		{"opened recently, recorded in the other form", uFrom, "https://bücher.test/u", "bücher.test",
			func(w World) World { w.LastOpened = map[string]string{aFrom: "2026-10-12"}; return w }, RRecentlyOpened},
		{"one of two opens recent", aFrom, "https://bücher.test/u", "bücher.test",
			func(w World) World {
				w.LastOpened = map[string]string{uFrom: "2026-01-01", "NEWS@XN--BCHER-KVA.TEST": "2026-10-12"}
				return w
			}, RRecentlyOpened},
		{"d of another organization", uFrom, "https://bücher.test/u", "xn--bcher-kva.example", nil, RDKIMUnaligned},
	}
	for _, c := range cases {
		raw, keys := signed(t, c.from, c.url, c.d, "")
		w := world(keys, c.from)
		if c.w != nil {
			w = c.w(w)
		}
		if got, _ := Evaluate(raw, w); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The lookalike check folds by UTS #39's skeleton, over the domain as
// written and its U-label, plus vv/w and cl/d: a Cyrillic homoglyph, its
// punycode, a capital I for l and the letter pairs all read as the known
// domain (#2603).
func TestLookalikeUsesTheUTS39Skeleton(t *testing.T) {
	for _, c := range []struct {
		domain, known string
		want          bool
	}{
		{"vvikipedia.test", "wikipedia.test", true},
		{"wikipedia.test", "vvikipedia.test", true},
		{"cloud.test", "doud.test", true},
		{"аpple.test", "apple.test", true},           // Cyrillic а
		{"news.раураl.test", "paypal.test", true},    // Cyrillic р, а, у
		{"xn--pple-43d.test", "apple.test", true},    // аpple, as punycode
		{"paypaI.test", "paypal.test", true},         // capital I as written
		{"gооgle.test", "xn--ggle-55da.test", false}, // the same name: one organization
		{"exаmple.test", "mail.exаmple.test", false}, // one organization
		{"bücher.test", "bucher.test", false},        // a diaeresis shows: UTS #39 keeps it
		{"apple.test", "orange.test", false},
		{"apple.test", "аpple.test", true},
	} {
		if got := lookalike(c.domain, c.known); got != c.want {
			t.Errorf("lookalike(%q, %q) = %v, want %v (skeletons %q, %q)", c.domain, c.known, got, c.want,
				skeleton(ulabel(c.domain)), skeleton(ulabel(c.known)))
		}
	}
}

// Evaluate folds the From domain in its own case, so a capital I stands for
// an l though the address is compared lower-cased (#2603).
func TestEvaluateRefusesALookalikeWrittenInCapitals(t *testing.T) {
	raw, keys := signed(t, "news@paypaI.test", "https://paypai.test/u", "paypai.test", "")
	w := world(keys, "news@paypai.test")
	w.Contacts = []string{"help@paypal.test"}
	if got, _ := Evaluate(raw, w); got != RLookalike {
		t.Fatalf("%q, want %q", got, RLookalike)
	}
}
