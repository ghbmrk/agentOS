package browser

// REQ: CRED-4

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAcceptsEachVerbOnTheClosedList(t *testing.T) {
	cases := map[string]Request{
		`{"v":0,"verb":"navigate","url":"https://example.test/a"}`:  {Verb: "navigate", URL: "https://example.test/a"},
		`{"v":0,"verb":"click","ref":"e12"}`:                        {Verb: "click", Ref: "e12"},
		`{"v":0,"verb":"type","ref":"f1e3","text":"kettle"}`:        {Verb: "type", Ref: "f1e3", Text: "kettle"},
		`{"v":0,"verb":"type","ref":"e3","text":"x","submit":true}`: {Verb: "type", Ref: "e3", Text: "x", Submit: true},
		`{"v":0,"verb":"select","ref":"e4","option":"Kenya"}`:       {Verb: "select", Ref: "e4", Option: "Kenya"},
		`{"v":0,"verb":"snapshot"}`:                                 {Verb: "snapshot"},
		`{"v":0,"verb":"screenshot"}`:                               {Verb: "screenshot"},
		`{"v":0,"verb":"download","ref":"e9"}`:                      {Verb: "download", Ref: "e9"},
	}
	for raw, want := range cases {
		got, err := Parse([]byte(raw))
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", raw, got, want)
		}
	}
}

// CRED-4: developer tools, arbitrary JavaScript and cookie, storage or header
// access do not exist in the protocol.
func TestParseRefusesVerbsOutsideTheList(t *testing.T) {
	for _, verb := range []string{"evaluate", "cookies", "storage", "set_header", "devtools",
		"eval", "press", "tabs", "local_storage", "Navigate", ""} {
		_, err := Parse([]byte(`{"v":0,"verb":"` + verb + `"}`))
		if !isProtocol(err) {
			t.Errorf("verb %q: want protocol error, got %v", verb, err)
		}
	}
}

func TestParseRefusesMalformedRequests(t *testing.T) {
	long := strings.Repeat("a", MaxText+1)
	for _, raw := range []string{
		`not json`,
		`[]`,
		`{"verb":"snapshot"}`,                                    // no version
		`{"v":1,"verb":"snapshot"}`,                              // future version
		`{"v":"0","verb":"snapshot"}`,                            // version as string
		`{"v":0.0,"verb":"snapshot"}`,                            // version as float
		`{"v":0,"verb":"snapshot","script":"1"}`,                 // unknown argument
		`{"v":0,"verb":"click"}`,                                 // missing ref
		`{"v":0,"verb":"click","ref":"#login"}`,                  // a selector, not a ref
		`{"v":0,"verb":"click","ref":"e1 >> css=a"}`,             // selector smuggled after a ref
		`{"v":0,"verb":"click","ref":12}`,                        // wrong type
		`{"v":0,"verb":"type","ref":"e1","text":"x","submit":1}`, // submit not bool
		`{"v":0,"verb":"type","ref":"e1","text":"` + long + `"}`, // text too long
		`{"v":0,"verb":"navigate","url":"javascript:alert(1)"}`,
		`{"v":0,"verb":"navigate","url":"file:///etc/passwd"}`,
		`{"v":0,"verb":"navigate","url":"chrome://settings"}`,
		`{"v":0,"verb":"navigate","url":"https://user:pw@example.test/"}`,
		`{"v":0,"verb":"navigate","url":"https:///nohost"}`,
		`{"v":0,"verb":"select","ref":"e1","option":"a","ref2":"e2"}`,
		`{"v":0,"verb":"snapshot"} {"v":0,"verb":"evaluate"}`, // trailing value
	} {
		if _, err := Parse([]byte(raw)); !isProtocol(err) {
			t.Errorf("%s: want protocol error, got %v", raw, err)
		}
	}
}

// A request with a key twice is refused, so the gate and the driver can never
// read different values from one line (parser differential).
func TestParseRefusesDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"v":0,"verb":"snapshot","verb":"evaluate"}`,
		`{"v":0,"verb":"navigate","url":"https://a.test/","url":"https://b.test/"}`,
	} {
		if _, err := Parse([]byte(raw)); !isProtocol(err) {
			t.Errorf("%s: want protocol error, got %v", raw, err)
		}
	}
}

func TestEncodeIsCanonical(t *testing.T) {
	r, err := Parse([]byte(`{"verb":"type","text":"hi","ref":"e2","v":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(r.Encode()), `{"v":0,"verb":"type","ref":"e2","text":"hi","submit":false}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	r, _ = Parse([]byte(`{"v":0,"verb":"snapshot"}`))
	if got, want := string(r.Encode()), `{"v":0,"verb":"snapshot"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestOnDeclaredOrigin(t *testing.T) {
	o, err := NewOrigins([]string{"https://shop.example.test", "http://127.0.0.1:8080/x"})
	if err != nil {
		t.Fatal(err)
	}
	for url, want := range map[string]bool{
		"https://shop.example.test/cart":                true,
		"https://shop.example.test:443/":                true,
		"https://SHOP.example.test/":                    true,
		"http://127.0.0.1:8080/app.html":                true,
		"http://shop.example.test/":                     false, // scheme differs
		"https://shop.example.test.evil.test/":          false,
		"https://evil.test/?https://shop.example.test/": false,
		"http://127.0.0.1:8081/":                        false,
		"about:blank":                                   false,
		"javascript:alert(1)":                           false,
		"https://user@shop.example.test/":               false,
	} {
		if got := o.Declared(url); got != want {
			t.Errorf("%s: got %v, want %v", url, got, want)
		}
	}
	if _, err := NewOrigins(nil); err == nil {
		t.Error("an executor with no declared origin must not start")
	}
	if _, err := NewOrigins([]string{"file:///tmp"}); err == nil {
		t.Error("a non-http origin must be refused")
	}
}

func isProtocol(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe)
}
