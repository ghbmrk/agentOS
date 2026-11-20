package inbox

// Direct tests of the Authentication-Results parser (RFC 8601): each case
// pins one statement of authres.go, so deleting or bending it changes an
// output here (#6330).

import (
	"reflect"
	"testing"
)

func TestStripCommentsCases(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`a(c)b`, `a b`},
		{`a (c) b`, `a   b`},
		{`a(x(y)z)b`, `a b`},
		{`a)b`, `a)b`},
		{`a\(b)`, `a\ `},
		{`"(x)" y`, `"(x)" y`},
		{`"a" (c)`, `"a"  `},
		{`"a\"b" (c)`, `"a\"b"  `},
		{`"a\\" (c)`, `"a\\"  `},
		{`(a\)b) x`, `  x`},
		{`(a\(b) x`, `  x`},
		{`(a\\) x`, `  x`},
		{`x (open`, `x `},
	} {
		if got := stripComments(c.in); got != c.want {
			t.Errorf("stripComments(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitOutsideQuotesCases(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{``, []string{``}},
		{`a;b`, []string{`a`, `b`}},
		{`a;;b;`, []string{`a`, ``, `b`, ``}},
		{`"a;b";c`, []string{`"a;b"`, `c`}},
		{`"a\";b";c`, []string{`"a\";b"`, `c`}},
		{`"a\\";b`, []string{`"a\\"`, `b`}},
		{`a\;b`, []string{`a\`, `b`}},
	} {
		if got := splitOutsideQuotes(c.in, ';'); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitOutsideQuotes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFieldsCases(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{``, nil},
		{"a b\tc\r\nd", []string{`a`, `b`, `c`, `d`}},
		{`  a  `, []string{`a`}},
		{`"a b" c`, []string{`"a b"`, `c`}},
		{`"a\" b" c`, []string{`"a\" b"`, `c`}},
		{`"a\\" b`, []string{`"a\\"`, `b`}},
		{`a\ b`, []string{`a\`, `b`}},
		{`a = b c`, []string{`a=b`, `c`}},
		{`= b`, []string{`=b`}},
		{`a =`, []string{`a=`}},
		{`a= b c`, []string{`a=b`, `c`}},
		{`a=`, []string{`a=`}},
		{`"a"= b`, []string{`"a"=`, `b`}},
		{`a =b c`, []string{`a=b`, `c`}},
		{`=b c`, []string{`=b`, `c`}},
		{`a = b = c`, []string{`a=b=c`}},
	} {
		if got := fields(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("fields(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnquoteCases(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{``, ``},
		{`a`, `a`},
		{`"`, `"`},
		{`""`, ``},
		{`"ab"`, `ab`},
		{`a"b"`, `a"b"`},
		{`"ab`, `"ab`},
		{`"a\"b"`, `a"b`},
		{`"\\x\y"`, `\xy`},
	} {
		if got := unquote(c.in); got != c.want {
			t.Errorf("unquote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseAuthResultsCases(t *testing.T) {
	type res = authResult
	for _, c := range []struct {
		in   string
		id   string
		want []authResult
	}{
		{``, ``, nil},
		{`(only a comment)`, ``, nil},
		{` ; dkim=pass`, ``, nil},
		{`mx.test`, `mx.test`, nil},
		{`"mx.test" 1`, `mx.test`, nil},
		{`mx.test; ; dkim=pass`, `mx.test`, []res{{"dkim", "pass", map[string]string{}}}},
		{`mx.test; none`, `mx.test`, nil},
		{`mx.test; =pass; dkim=; dkim=pass`, `mx.test`, []res{{"dkim", "pass", map[string]string{}}}},
		{`mx.test; DKIM/1=PASS`, `mx.test`, []res{{"dkim", "pass", map[string]string{}}}},
		{`mx.test; spf="Pass"`, `mx.test`, []res{{"spf", "pass", map[string]string{}}}},
		{
			`mx.test; dmarc=pass reason="x.y" noeq Header.From="a;b.test" header.from=c.test policy.dmarc = reject`,
			`mx.test`,
			[]res{{"dmarc", "pass", map[string]string{"header.from": "a;b.test", "policy.dmarc": "reject"}}},
		},
		{
			`mx.test (dmarc=pass); dkim=fail (x; dmarc=pass) header.d=e.test; dmarc=none`,
			`mx.test`,
			[]res{
				{"dkim", "fail", map[string]string{"header.d": "e.test"}},
				{"dmarc", "none", map[string]string{}},
			},
		},
	} {
		id, got := parseAuthResults(c.in)
		if id != c.id || !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAuthResults(%q) = %q, %v; want %q, %v", c.in, id, got, c.id, c.want)
		}
	}
}
