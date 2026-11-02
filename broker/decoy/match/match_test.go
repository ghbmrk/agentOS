package match_test

// REQ: CLK-4, KRN-12

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

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

// KRN-12: a table destination trips in plain, IPv4-mapped and NAT64 form;
// a neighbour does not.
func TestDestForms(t *testing.T) {
	tab, err := decoy.Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	m := tab.Matcher()
	for _, s := range []string{"169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "192.168.10.250", "::ffff:192.168.20.250"} {
		if _, ok := m.Dest(netip.MustParseAddr(s)); !ok {
			t.Errorf("%s does not trip", s)
		}
	}
	for _, s := range []string{"169.254.169.253", "192.168.10.251", "64:ff9b:1::a9fe:a9fe", "fe80::a9fe:a9fe", "8.8.8.8"} {
		if _, ok := m.Dest(netip.MustParseAddr(s)); ok {
			t.Errorf("%s trips", s)
		}
	}
	// A zone names the link, not the address: a zoned form trips as the
	// zoneless one does (#3876).
	for _, s := range []string{"::ffff:192.168.10.250%eth0", "64:ff9b::a9fe:a9fe%eth0"} {
		if _, ok := m.Dest(netip.MustParseAddr(s)); !ok {
			t.Errorf("%s does not trip", s)
		}
	}
	// A zoned table address is held zoneless, so either form trips.
	zm := match.New(nil, map[netip.Addr]int{netip.MustParseAddr("2001:db8::7%eth0"): 3})
	for _, s := range []string{"2001:db8::7", "2001:db8::7%eth1"} {
		if id, ok := zm.Dest(netip.MustParseAddr(s)); !ok || id != 3 {
			t.Errorf("%s against a zoned table address: %d, %v", s, id, ok)
		}
	}
	// A destination named in text is no trip: a page that names the
	// metadata address is refused at connect time, not read as a leak.
	if r := m.Scan([]byte("see http://169.254.169.254/latest/meta-data/")); len(r.Trips) != 0 {
		t.Errorf("an address in text tripped %v", r.Trips)
	}
}

// KRN-12: a value inside a longer base64 run trips at every byte offset,
// with any bytes before and after it, in both alphabets, padded or not and
// split across writes; the same run without the value does not (#3876).
func TestBase64AnyOffset(t *testing.T) {
	tab, err := decoy.Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	m := tab.Matcher()
	encs := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	for id, e := range tab.Entries() {
		if e.Value == "" {
			continue
		}
		for pre := range 6 {
			for post := range 4 {
				before, after := make([]byte, pre), make([]byte, post)
				rand.Read(before)
				rand.Read(after)
				run := append(append(append([]byte(nil), before...), e.Value...), after...)
				for _, enc := range encs {
					s := enc.EncodeToString(run)
					if got := m.Scan([]byte("x " + s + " y")).Trips; !slices.Equal(got, []int{id}) {
						t.Fatalf("%v at offset %d, %d after, tripped %v, want [%d]", e, pre, post, got, id)
					}
					if got := split(t, m, s, len(s)/2).Trips; !slices.Equal(got, []int{id}) {
						t.Fatalf("%v at offset %d split tripped %v, want [%d]", e, pre, got, id)
					}
					without := enc.EncodeToString(append(before, after...))
					if got := m.Scan([]byte(without)).Trips; len(got) != 0 {
						t.Fatalf("a run without the value tripped %v", got)
					}
				}
			}
		}
		if got := m.Scan([]byte(strings.ToUpper(hex.EncodeToString([]byte(e.Value))))).Trips; !slices.Equal(got, []int{id}) {
			t.Fatalf("%v in upper hex tripped %v, want [%d]", e, got, id)
		}
	}
}

// wrap breaks s into lines of width characters with br, as base64(1) (76),
// MIME (76), PEM (64) and xxd -p (60) do.
func wrap(s string, width int, br string) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width] + br)
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

// KRN-12: a value in base64 or hex broken into lines trips wherever a break
// falls in it, at any width, with LF or CRLF, raw, URL-escaped or
// \u-escaped, raw or JSON-escaped (what the kernel scans of a plan step) at
// any depth, in one write or split at a break; the same wrapped run without
// the value does not (#4500, #4582).
func TestBase64Wrapped(t *testing.T) {
	tab, err := decoy.Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	m := tab.Matcher()
	encs := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	forms := func(s string, width int) []string {
		var out []string
		for _, br := range []string{"\n", "\r\n", "%0A", "%0d%0a", `\u000a`, `\u000D\u000A`} {
			w := wrap(s, width, br)
			j, _ := json.Marshal(w)
			jj, _ := json.Marshal(string(j)) // a JSON body inside a plan step's string
			out = append(out, w, string(j), string(jj))
		}
		return out
	}
	for id, e := range tab.Entries() {
		if e.Value == "" {
			continue
		}
		// Every byte offset, then steps of 5 bytes (under 7 characters, less
		// than any value's length) up to a 76-character line, so a break
		// falls inside the value at many places in it.
		pres := []int{0, 1, 2, 3, 4}
		for p := 5; p < 58; p += 5 {
			pres = append(pres, p)
		}
		for _, pre := range pres {
			before := make([]byte, pre)
			rand.Read(before)
			run := append(append([]byte(nil), before...), e.Value...)
			for _, enc := range encs {
				for _, width := range []int{4, 64, 76} {
					if width == 4 && pre > 4 {
						continue // a 4-character line repeats every 3 bytes
					}
					for _, s := range forms(enc.EncodeToString(run), width) {
						if got := m.Scan([]byte("x " + s + " y")).Trips; !slices.Equal(got, []int{id}) {
							t.Fatalf("%v at %d bytes in, wrapped at %d, tripped %v, want [%d]", e, pre, width, got, id)
						}
						if at := strings.LastIndexAny(s, `\`+"\n"); at > 0 {
							if got := split(t, m, s, at+1).Trips; !slices.Equal(got, []int{id}) {
								t.Fatalf("%v at %d bytes in, wrapped at %d, split at a break tripped %v", e, pre, width, got)
							}
						}
					}
					for _, s := range forms(enc.EncodeToString(before), width) {
						if got := m.Scan([]byte(s)).Trips; len(got) != 0 {
							t.Fatalf("a wrapped run without the value tripped %v", got)
						}
					}
				}
			}
			for _, s := range forms(hex.EncodeToString(run), 60) {
				if got := m.Scan([]byte(s)).Trips; !slices.Equal(got, []int{id}) {
					t.Fatalf("%v in hex at %d bytes in, wrapped at 60, tripped %v, want [%d]", e, pre, got, id)
				}
			}
		}
	}
}

// KRN-12: a form whose first characters could end a line-break escape
// trips after text that makes them read as one: a literal '\' before n or
// r (JSON "C:\\n..."), '%' or "%0" before hex 0a or a, "\u000" before a,
// wrapped, raw or JSON-escaped at any depth, also after another break; the
// same text without the value does not, nor a break whose characters share
// only a form's first one (#4582).
func TestWrappedAfterEscapeHead(t *testing.T) {
	vals := []string{"nq7Xz2pL9mW4vR8tY3nB6kJ5h", "rW4vR8tY3nB6kJ5hq7Xz2pL9m", "u000aY3nB6kJ5hq7Xz2pL9mW4vR8t",
		"aJ5hq7Xz2pL9mW4vR8tY3nB6k", "DpL9mW4vR8tY3nB6kJ5hq7Xz2", "0AvR8tY3nB6kJ5hq7Xz2pL9mW4", "n0AnB6kJ5hq7Xz2pL9mW4vR8tY3"}
	var values []match.Value
	for i, v := range vals {
		values = append(values, match.Value{ID: i, Bytes: []byte(v)})
	}
	hexv := []byte{0x0a, 0xd0, 0x7f, 0x13, 0x99, 0x42, 0xee, 0x01, 0x5c, 0x77, 0x31, 0xa8}
	values = append(values, match.Value{ID: len(vals), Bytes: hexv})
	m := match.New(values, nil)
	texts := append(slices.Clone(vals), hex.EncodeToString(hexv), strings.ToUpper(hex.EncodeToString(hexv)))
	for i, v := range texts {
		id := min(i, len(vals))
		for _, head := range []string{`\`, `\\`, `\u000`, `\u00`, `%`, `%0`, `%\`} {
			for _, width := range []int{3, 4, 5, 24} {
				w := `\r` + head + wrap(v, width, "\n") // a second break at the head's place
				j, _ := json.Marshal(w)
				jj, _ := json.Marshal(string(j))
				for _, s := range []string{w, string(j), string(jj)} {
					if got := m.Scan([]byte("C:" + s + " y")).Trips; !slices.Equal(got, []int{id}) {
						t.Fatalf("%q tripped %v, want [%d]", s, got, id)
					}
					if got := split(t, m, s, len(head)+1).Trips; !slices.Equal(got, []int{id}) {
						t.Fatalf("%q split after its head tripped %v, want [%d]", s, got, id)
					}
				}
				if got := m.Scan([]byte(head + wrap(v[len(v)/2:], width, "\n"))).Trips; len(got) != 0 {
					t.Fatalf("%q without the value tripped %v", head+v[len(v)/2:], got)
				}
			}
		}
	}
	upper := strings.ToUpper(hex.EncodeToString(hexv))
	m2 := match.New([]match.Value{{ID: 1, Bytes: hexv}, {ID: 2, Bytes: []byte("uQQQQq7Xz2pL9mW4vR8tY3nB6kJ5h")}}, nil)
	for _, s := range []string{"%0a" + upper[2:], `C:\u000aq7Xz2pL9m\nW4vR8tY3nB6kJ5h`} {
		if got := m2.Scan([]byte(s)).Trips; len(got) != 0 {
			t.Fatalf("%q, a break sharing only a form's first character, tripped %v", s, got)
		}
	}
	repro := `{"a":"C:\\nq7Xz2pL9m\nW4vR8tY3nB6kJ5h"}`
	for _, pad := range []string{"", strings.Repeat(" ", 2000)} { // the break let go before the scan
		if got := m.Scan([]byte(repro + pad)).Trips; !slices.Equal(got, []int{0}) {
			t.Fatalf("%s and %d bytes tripped %v, want [0]", repro, len(pad), got)
		}
	}
}

// KRN-12: a break is kept while a later break's head is still open in the
// form's rest (a '\' run of any length, "%0"), and until the longest form's
// rest has come, in one write or a byte at a time (#4582), for any form
// length: past the 4 KiB tail and at MaxValue, with a head open at a scan
// (#4622).
func TestBreakHeldWhileOpen(t *testing.T) {
	for _, n := range []int{700, match.MaxValue - 2} {
		v := "n" + strings.Repeat("<", n) + "z"
		j, _ := json.Marshal(v)
		f := string(j[1 : len(j)-1]) // n\u003c...z, the longest form
		lm := match.New([]match.Value{{ID: 2, Bytes: []byte(v)}}, nil)
		for _, w := range [][]string{{`C:\\` + f[:len(f)-1] + "%0", "a" + f[len(f)-1:]}, {`C:\\` + f}} {
			st := lm.Stream()
			for _, p := range w {
				st.Write([]byte(p))
			}
			one := lm.Stream()
			for _, c := range []byte(strings.Join(w, "") + strings.Repeat(" ", 2000)) {
				one.Write([]byte{c})
			}
			if got, got1 := st.Result().Trips, one.Result().Trips; !slices.Equal(got, []int{2}) || !slices.Equal(got1, []int{2}) {
				t.Fatalf("a %d-character form begun in a break tripped %v, a byte at a time %v, want [2]", len(f), got, got1)
			}
		}
	}
	hv := append([]byte{0xab}, "q7Xz2pL9mW4vR8tY3nB6kJ5h"...)
	h := hex.EncodeToString(hv)
	m := match.New([]match.Value{{ID: 0, Bytes: []byte("nq7Xz2pL9mW4vR8tY3nB6kJ5h")}, {ID: 1, Bytes: hv}}, nil)
	cases := map[string]int{}
	for k := 1; k < len(h); k++ { // h is the longest form; it begins one character into a break
		for _, br := range []string{"\n", "%0A", `\u000a`, strings.Repeat(`\`, 32) + "n"} {
			cases["%0"+h[:k]+br+h[k:]] = 1
		}
	}
	for _, run := range []int{1, 60, 5000} {
		for _, head := range []string{`C:\\n`, `C:\n`} {
			cases[head+"q7Xz2pL9m"+strings.Repeat(`\`, run)+"nW4vR8tY3nB6kJ5h"] = 0
		}
	}
	for s, id := range cases {
		for _, pad := range []string{"", strings.Repeat(" ", 2000)} {
			if got := m.Scan([]byte(s + pad)).Trips; !slices.Equal(got, []int{id}) {
				t.Fatalf("%.80q and %d bytes tripped %v, want [%d]", s, len(pad), got, id)
			}
			st := m.Stream()
			for i := range len(s + pad) {
				st.Write([]byte{(s + pad)[i]})
			}
			if got := st.Result().Trips; !slices.Equal(got, []int{id}) {
				t.Fatalf("%.80q and %d bytes, a byte at a time, tripped %v, want [%d]", s, len(pad), got, id)
			}
		}
	}
}

// KRN-12: a '\' run collapses only after the last break, so a run before
// one never merges with a run after it: a value's '\' before "%0a" stays
// in the joined text when a JSON break follows (#4622).
func TestRunCollapseFloor(t *testing.T) {
	v := `q7Xz\2pL9mW4vR8tY3nB6kJ5h`
	m := match.New([]match.Value{{ID: 3, Bytes: []byte(v)}}, nil)
	for _, s := range []string{`q7Xz\%0a\n2pL9mW4vR8tY3nB6kJ5h`, `q7Xz\%0A\r\n2pL9mW4vR8tY3nB6kJ5h`} {
		if got := m.Scan([]byte(s)).Trips; !slices.Equal(got, []int{3}) {
			t.Fatalf("%q tripped %v, want [3]", s, got)
		}
	}
}

// KRN-12: a value holding a '\' trips in its JSON form split by a break at
// every place (near the '\' in a form over 4 KiB), at JSON depth one and
// two, also right after the escaped '\', where the break's run holds it,
// and with other JSON escapes in it ('<', '"'), whole, in two writes and in
// one write then Result, with a scan before or inside it; the break alone in
// its place does not (#4622).
func TestJSONBackslashWrapped(t *testing.T) {
	long := strings.Repeat("<", 700) + `\q7Xz2pL9mW4v`
	for _, v := range []string{`q7Xz\2pL9mW4vR8tY3nB6kJ5h`, `q7Xz\2pL9<mW4vR8tY3nB6kJ5h`, `q7Xz\2pL9"mW4vR8tY3nB6kJ5h`, long} {
		m := match.New([]match.Value{{ID: 5, Bytes: []byte(v)}}, nil)
		j, _ := json.Marshal(v)
		jj, _ := json.Marshal(string(j))
		for d, f := range []string{string(j[1 : len(j)-1]), string(jj[3 : len(jj)-3])} {
			at := strings.LastIndex(f, `\\`) + 1 // in the escaped '\'
			for cut := 1; cut < len(f); cut++ {
				if len(f) > 200 && (cut < at-4 || cut > at+6*(d+1)) {
					continue
				}
				for _, br := range []string{"\n", "\r\n", `\n`, `\r\n`, `\u000a`, `\\n`, "%0A"} {
					s := `{"a":"` + f[:cut] + br + f[cut:] + `"}`
					wrappedTrips(t, m, s, 6+cut+len(br), 5)
				}
			}
		}
		if got := m.Scan([]byte(strings.Replace(v, `\`, "%0a", 1))).Trips; len(got) != 0 {
			t.Fatalf("a %%0a break in the '\\' place tripped %v", got)
		}
	}
	// A "\\" split by "%0a" stays in the joined text, so its '\'s are read
	// back too (Security, #4663).
	m := match.New([]match.Value{{ID: 9, Bytes: []byte(`C\y z91-Byz>_"zzCzC1`)}}, nil)
	s := `C\%0a\y\\n z9` + "\n" + `1-Byz\u00\u000D3e_\\\n"zzCzC1`
	wrappedTrips(t, m, s, len(`C\%0a`), 9)
	// A form's prefix before a held break outlasts a scan: a long form split
	// after its escaped '\', or with a JSON break in its first '\'s place,
	// then a head open at the scan (Security, #4663).
	for _, v := range []string{`ab\cd` + strings.Repeat("<", 700) + "z", `ab\cd` + strings.Repeat("<", 1018) + "z", "n" + strings.Repeat("<", 1022) + "z"} {
		m := match.New([]match.Value{{ID: 7, Bytes: []byte(v)}}, nil)
		j, _ := json.Marshal(v)
		f := string(j[1 : len(j)-1])
		at := strings.Index(f, `\\`) + 2
		if v[0] == 'n' {
			f, at = f[:1]+f[2:], 1
		}
		for _, head := range []string{`\u000`, "%0"} {
			st := m.Stream()
			st.Write([]byte(f[:at] + `\n` + f[at:] + head))
			st.Write([]byte("x "))
			if got := st.Result().Trips; !slices.Equal(got, []int{7}) {
				t.Fatalf("a %d-character form, then %q, tripped %v, want [7]", len(f), head, got)
			}
		}
	}
	// Each later break is read back too, so a form split twice trips: a
	// form begun in a break (its leading n after "C:\\") and split after
	// one of its escapes' '\', and a value with two '\'s split after both;
	// without the n (past the first escape, where the break's n is the
	// form's), or with a break alone in a '\' place, it does not (#4681).
	v := "n" + strings.Repeat("<", 4) + "q7Xz2pL9mW4v"
	m = match.New([]match.Value{{ID: 6, Bytes: []byte(v)}}, nil)
	j, _ := json.Marshal(v)
	f := string(j[1 : len(j)-1]) // n\u003c\u003c\u003c\u003cq7Xz2pL9mW4v
	for at := 2; at < len(f); at++ {
		if f[at-1] != '\\' {
			continue
		}
		for _, br := range []string{`\n`, `\u000a`, `\\r`} {
			wrappedTrips(t, m, `C:\\`+f[:at]+br+f[at:], 3+at+len(br), 6)
			if got := m.Scan([]byte(`C:\\` + f[1:at] + br + f[at:])).Trips; at > 2 && len(got) != 0 {
				t.Fatalf("%q without the form's n tripped %v", f[1:], got)
			}
		}
	}
	two := `q7Xz\2pL9\mW4vR8tY3nB6kJ5h`
	m = match.New([]match.Value{{ID: 8, Bytes: []byte(two)}}, nil)
	for _, br := range []string{`\n`, `\r\n`, `\u000a`, "%0a"} {
		s := `{"a":"q7Xz\\` + `\n` + `2pL9\\` + br + `mW4vR8tY3nB6kJ5h"}`
		wrappedTrips(t, m, s, len(`{"a":"q7Xz\\\n`), 8)
	}
	if got := m.Scan([]byte(`q7Xz\n2pL9mW4vR8tY3nB6kJ5h`)).Trips; len(got) != 0 {
		t.Fatalf("one '\\' kept and one break alone in a '\\' place tripped %v", got)
	}
}

// KRN-12: the same JSON form wrapped with a raw LF or CRLF, and split by
// one after its escaped '\', trips (#4681, Security on #4663).
func TestJSONFormRawWrapped(t *testing.T) {
	v := `q7Xz\2pL9<mW4vR8tY3nB6kJ5h`
	m := match.New([]match.Value{{ID: 1, Bytes: []byte(v)}}, nil)
	j, _ := json.Marshal(v)
	f := string(j[1 : len(j)-1])
	for cut := 1; cut < len(f); cut++ {
		for _, br := range []string{"\n", "\r\n"} {
			wrappedTrips(t, m, f[:cut]+br+f[cut:], cut+len(br), 1)
		}
	}
}

// KRN-12: an attacker-written stream of JSON breaks costs about what plain
// text does, whatever '\'s the table's forms hold: here a MaxValue value of
// '<'s, a '\' in every sixth byte of its JSON form. Each break looks up only
// the '\'s with its own bytes beside them (#4681). Timed against plain text
// in the same run, so a slow runner or -race moves both.
func TestBreakStreamCost(t *testing.T) {
	m := match.New([]match.Value{{ID: 1, Bytes: []byte(strings.Repeat("<", match.MaxValue))},
		{ID: 2, Bytes: []byte(`q7Xz\2pL9<mW4vR8tY3nB6kJ5h`)}}, nil)
	run := func(unit string) time.Duration {
		w := []byte(strings.Repeat(unit, 512/len(unit))) // 512-byte writes
		start := time.Now()
		s := m.Stream()
		for range 128 {
			s.Write(w)
		}
		if r := s.Result(); len(r.Trips) != 0 {
			t.Fatalf("a stream of %q tripped %v", unit, r.Trips)
		}
		return time.Since(start)
	}
	plain, breaks := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
	for range 2 {
		plain, breaks = min(plain, run("xy")), min(breaks, run(`x\n`))
	}
	if breaks > 3*plain {
		t.Fatalf("64 KiB of x\\n took %v, plain text %v: over 3 times as long", breaks, plain)
	}
}

// wrappedTrips checks that s trips [id] whole, in two writes split right
// after its break, halfway and before its last byte, and in one write then
// Result; the first and last also after 4 KiB, so that a scan falls inside.
func wrappedTrips(t *testing.T, m *match.Matcher, s string, after, id int) {
	t.Helper()
	if got := m.Scan([]byte(s)).Trips; !slices.Equal(got, []int{id}) {
		t.Fatalf("%.80q tripped %v, want [%d]", s, got, id)
	}
	for k, pad := range []string{"", strings.Repeat(" ", 4096)} {
		for _, i := range []int{after, len(s), len(s) / 2, len(s) - 1}[:4-2*k] {
			st := m.Stream()
			st.Write([]byte(pad + s[:i]))
			st.Write([]byte(s[i:]))
			if got := st.Result().Trips; !slices.Equal(got, []int{id}) {
				t.Fatalf("%.80q after %d bytes, written to %d then the rest, tripped %v, want [%d]", s, len(pad), i, got, id)
			}
		}
	}
}
