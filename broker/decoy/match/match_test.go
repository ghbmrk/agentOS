package match_test

// REQ: CLK-4, KRN-12

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/decoy/match"
)

var rangeAddrs = []netip.Addr{
	netip.MustParseAddr("192.168.10.250"),
	netip.MustParseAddr("192.168.20.250"),
}

// CLK-4's cases, as broker/browser's detector tests had them (synthetic
// canaries only, CLAUDE.md): every one must still match after the move.
var clk4 = []string{
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJlLWNhbmFyeQ", // JWT
	"ghp_CanaryGitHubToken0123456789abcd",                                // GitHub
	"sk-ant-gatecanaryDisplayedKey0123456789abcdef",                      // API key
	"AKIACANARY0123456789",                                               // AWS
	"xoxb-canary-0123456789",                                             // Slack
	"q7Xz2pL9mW4vR8tY3nB6kJ5h",                                           // high entropy
	"api key: 9f86d081884c7d659a2feaa0c55ad015",                          // labelled hex
	"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",   // labelled '/'
	`{"accessToken": "9f86d081884c7d659a2feaa0c55ad015"}`,                // camelCase label
	"https://a.test/cb#access_token=abc123&state=x",                      // URL fragment
	"https://a.test/order?item=7&token=short1",                           // URL query
}

func split(t *testing.T, m *match.Matcher, s string, at int) match.Result {
	t.Helper()
	st := m.Stream()
	st.Write([]byte("POST /x HTTP/1.1\r\n\r\nbefore " + s[:at]))
	st.Write([]byte(s[at:] + " after"))
	return st.Result()
}

// CLK-4, KRN-12: every table value and every existing CLK-4 pattern
// matches, split across two writes too; random high-entropy text without a
// table entry does not trip.
func TestTableAndPatterns(t *testing.T) {
	tab, err := decoy.Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	m := tab.Matcher()
	for id, e := range tab.Entries() {
		if e.Value == "" {
			continue
		}
		j, _ := json.Marshal(e.Value)
		for _, form := range []string{
			e.Value,
			string(j[1 : len(j)-1]),
			url.QueryEscape(e.Value),
			hex.EncodeToString([]byte(e.Value)),
			base64.StdEncoding.EncodeToString([]byte(e.Value)),
			base64.RawURLEncoding.EncodeToString([]byte(e.Value)),
		} {
			if got := m.Scan([]byte("x " + form + " y")).Trips; !slices.Equal(got, []int{id}) {
				t.Fatalf("%v: one write tripped %v, want [%d]", e, got, id)
			}
			for _, at := range []int{1, len(form) / 2, len(form) - 1} {
				if got := split(t, m, form, at).Trips; !slices.Equal(got, []int{id}) {
					t.Fatalf("%v split at %d tripped %v, want [%d]", e, at, got, id)
				}
			}
		}
	}
	// Many writes, one byte each.
	e := tab.Entries()[7]
	st := m.Stream()
	for i := range len(e.Value) {
		st.Write([]byte{e.Value[i]})
	}
	if got := st.Result().Trips; len(got) != 1 || got[0] != 7 {
		t.Fatalf("a value sent a byte at a time tripped %v", got)
	}

	for _, c := range clk4 {
		if !match.Pattern(c) {
			t.Errorf("CLK-4 case %q no longer matches", c)
		}
		for _, at := range []int{1, len(c) / 2, len(c) - 1} {
			r := split(t, m, c, at)
			if !r.Pattern {
				t.Errorf("CLK-4 case %q split at %d does not match", c, at)
			}
			if len(r.Trips) != 0 {
				t.Errorf("CLK-4 case %q tripped %v", c, r.Trips)
			}
		}
	}

	for range 200 {
		b := make([]byte, 48)
		rand.Read(b)
		for _, s := range []string{base64.RawURLEncoding.EncodeToString(b), hex.EncodeToString(b), "sk-ant-api03-" + base64.RawURLEncoding.EncodeToString(b)} {
			r := m.Scan([]byte("token: " + s))
			if len(r.Trips) != 0 {
				t.Fatalf("random text tripped %v", r.Trips)
			}
			if !r.Pattern {
				t.Fatalf("random token %q is not CLK-4-shaped", s)
			}
		}
	}
	for _, s := range []string{"Order 7 shipped to Nairobi on Tuesday", "internationalization-and-localization"} {
		if r := m.Scan([]byte(s)); r.Pattern || len(r.Trips) != 0 {
			t.Errorf("%q: %+v", s, r)
		}
	}
}

// KRN-12: a table destination trips in every form Forms gives, zoned or
// not; a neighbour does not.
func TestDestForms(t *testing.T) {
	tab, err := decoy.Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	m := tab.Matcher()
	for _, s := range []string{"169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "192.168.10.250", "::ffff:192.168.20.250",
		"64:ff9b::a9fe:a9fe%eth0", "::ffff:169.254.169.254%1", "::169.254.169.254", "64:ff9b:1::a9fe:a9fe",
		"64:ff9b:1:a9fe:a9:fe00::", "2002:a9fe:a9fe::1", "fe80::5efe:a9fe:a9fe%eth0", "fe80::200:5efe:a9fe:a9fe", "2001:0:a9fe:a9fe::",
		"2001:0:4136:e378:8000:63bf:5601:5601"} {
		if _, ok := m.Dest(netip.MustParseAddr(s)); !ok {
			t.Errorf("%s does not trip", s)
		}
	}
	for _, s := range []string{"169.254.169.253", "192.168.10.251", "fe80::a9fe:a9fe", "2003:a9fe:a9fe::1", "fe80::100:5efe:a9fe:a9fe", "::1", "8.8.8.8"} {
		if _, ok := m.Dest(netip.MustParseAddr(s)); ok {
			t.Errorf("%s trips", s)
		}
	}
	// A destination named in text is no trip: a page that names the
	// metadata address is refused at connect time, not read as a leak.
	if r := m.Scan([]byte("see http://169.254.169.254/latest/meta-data/")); len(r.Trips) != 0 {
		t.Errorf("an address in text tripped %v", r.Trips)
	}
}
