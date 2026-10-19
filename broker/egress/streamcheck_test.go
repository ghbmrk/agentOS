package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// REQ: CRED-8
// SR3-mail-k18g: the body check walks the body instead of decoding it
// (K18g-1, K18g-2), a stalled reader's slots return within the write
// deadline (K18g-3), and no machine holds more than its share of the
// budget (K18g-4).

// decodedApply is BodyRule.apply as it was before SR3-mail-k18g: the whole
// body decoded into map[string]any and re-encoded. The differential tests
// hold the walk to its decisions. The one change: a Set stream_options map
// is copied, not written (the old code wrote the rule's own map).
func decodedApply(b *BodyRule, body []byte, public bool) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("body is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON body")
	}
	for _, k := range b.DenyKeys {
		if _, ok := obj[k]; ok {
			return nil, fmt.Errorf("body key %q not allowed", k)
		}
	}
	strict := !(public && b.PublicMayFetch)
	if strict {
		for _, k := range b.ServerToolKeys {
			if _, ok := obj[k]; ok {
				return nil, fmt.Errorf("body key %q needs a public machine", k)
			}
		}
		if err := decodedRemoteSource(obj, ""); err != nil {
			return nil, err
		}
	}
	if t, ok := obj["tools"]; ok {
		tools, ok := t.([]any)
		if !ok {
			return nil, errors.New("tools is not a list")
		}
		for _, e := range tools {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, errors.New("tool entry is not an object")
			}
			if typ, has := m["type"]; has && typ != "function" && typ != "custom" && strict {
				return nil, errors.New("provider-side tools need a public machine")
			}
		}
	}
	for k, v := range b.Set {
		obj[k] = v
	}
	if b.StreamUsage && obj["stream"] == true {
		so, _ := obj["stream_options"].(map[string]any)
		cp := map[string]any{}
		for k, v := range so {
			cp[k] = v
		}
		cp["include_usage"] = true
		obj["stream_options"] = cp
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func decodedRemoteSource(v any, key string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if k == "input_schema" || k == "parameters" || (k == "input" && t["type"] == "tool_use") {
				continue
			}
			if err := decodedRemoteSource(c, k); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range t {
			if err := decodedRemoteSource(c, key); err != nil {
				return err
			}
		}
	case string:
		if urlKeys[key] && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "data:") {
			return errors.New("remote content sources need a public machine; send content inline")
		}
	}
	return nil
}

// checkRules are the body rules the differential runs every body under:
// the two shipped ones and synthetic ones that reach every branch of Set
// and StreamUsage.
func checkRules(t testing.TB) map[string]*BodyRule {
	rules := map[string]*BodyRule{}
	for _, a := range []Adapter{OpenAI("k"), Anthropic("k")} {
		for _, op := range a.Operations {
			if op.Body != nil {
				rules[a.Name+" "+op.Name] = op.Body
			}
		}
	}
	if len(rules) != 2 {
		t.Fatalf("shipped rules: %d", len(rules))
	}
	rules["empty"] = &BodyRule{}
	rules["deny"] = &BodyRule{DenyKeys: []string{"tools", "url", "\u00e9"}, ServerToolKeys: []string{"type", "stream"}}
	rules["set stream"] = &BodyRule{StreamUsage: true, Set: map[string]any{"stream": true, "stream_options": map[string]any{"a": 1, "include_usage": "x"}}}
	rules["set nil options"] = &BodyRule{StreamUsage: true, Set: map[string]any{"stream_options": map[string]any(nil)}}
	rules["set string options"] = &BodyRule{StreamUsage: true, Set: map[string]any{"stream_options": "s", "n": json.Number("1.50")}}
	rules["set stream off"] = &BodyRule{StreamUsage: true, Set: map[string]any{"stream": false, "tools": []any{"x"}}}
	rules["set bad"] = &BodyRule{Set: map[string]any{"c": make(chan int)}}
	return rules
}

// sameDecision runs one body through the walk and the decoder under every
// rule, public and not, and reports any difference.
func sameDecision(t testing.TB, rules map[string]*BodyRule, body []byte) {
	t.Helper()
	for name, rule := range rules {
		for _, public := range []bool{false, true} {
			before := fmt.Sprint(rule.Set)
			want, werr := decodedApply(rule, body, public)
			got, gerr := rule.apply(body, public)
			if fmt.Sprint(rule.Set) != before {
				t.Fatalf("%s: apply wrote the rule's Set: %v", name, rule.Set)
			}
			if (werr == nil) != (gerr == nil) || (werr != nil && werr.Error() != gerr.Error()) {
				t.Fatalf("%s public=%v %q:\n decoder: %v\n walk:    %v", name, public, clip(body), werr, gerr)
			}
			if werr != nil {
				continue
			}
			if err := wellFormed(got); err != nil {
				t.Fatalf("%s public=%v %q: output %q: %v", name, public, clip(body), clip(got), err)
			}
			if w, g := decodeNum(t, want), decodeNum(t, got); !reflect.DeepEqual(w, g) {
				t.Fatalf("%s public=%v %q:\n decoder: %s\n walk:    %s", name, public, clip(body), clip(want), clip(got))
			}
		}
	}
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

func decodeNum(t testing.TB, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", clip(b), err)
	}
	return v
}

// wellFormed reports whether an output is valid JSON and UTF-8 with no
// object holding a key twice: what the provider parses is what was checked.
func wellFormed(b []byte) error {
	if !json.Valid(b) || !utf8.Valid(b) {
		return errors.New("not valid JSON and UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type level struct {
		obj  bool
		keys map[string]bool
		key  bool // the next token is a key
	}
	var stack []*level
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *level
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.key {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = true
				}
				continue
			}
			k := tok.(string)
			if top.keys[k] {
				return fmt.Errorf("key %q twice", k)
			}
			top.keys[k] = true
			top.key = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &level{obj: true, keys: map[string]bool{}, key: true})
			continue
		case json.Delim('['):
			stack = append(stack, &level{})
			continue
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].key = true
		}
	}
}

// harvestBodies are the JSON literals in this package's tests: the corpus
// the decoder was tested on.
func harvestBodies(t testing.TB) [][]byte {
	files, _ := filepath.Glob("*_test.go")
	var out [][]byte
	fset := token.NewFileSet()
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				if s, err := strconv.Unquote(l.Value); err == nil && len(s) > 0 && (s[0] == '{' || s[0] == '[') {
					out = append(out, []byte(s))
				}
			}
			return true
		})
	}
	if len(out) < 50 {
		t.Fatalf("corpus: %d bodies", len(out))
	}
	return out
}

// edgeBodies reach each rule of the decoder: syntax, duplicates at every
// level, escapes and invalid UTF-8 in keys, remote sources and their
// exclusions, tools entries and streaming.
var edgeBodies = []string{
	``, ` `, `{`, `}`, `{}`, ` {} `, "\t{}\r\n", `{} x`, `{}{}`, `{}[`, `{}]`, `{},`, `{}0`, `{}"`, "{}\x00", "\ufeff{}",
	`null`, `[]`, `[{}]`, `"x"`, `0`, `true`, `{"a"}`, `{"a":}`, `{"a":1,}`, `{,"a":1}`, `{"a":1 "b":2}`, `{"a" 1}`,
	`{"a":01}`, `{"a":-}`, `{"a":1.}`, `{"a":.5}`, `{"a":1e}`, `{"a":-0.0e+00}`, `{"a":1E-7}`, `{"a":+1}`, `{"a":0x1}`,
	`{"a":tru}`, `{"a":truex}`, `{"a":nul}`, `{"a":True}`, `{"a":[1,]}`, `{"a":[,1]}`, `{"a":[1 2]}`, `{"a":[}`, `{"a":{]}`,
	`{"a":"\x"}`, `{"a":"\u12"}`, `{"a":"\u12G4"}`, "{\"a\":\"\x01\"}", "{\"a\":\"\x1f\"}", "{\"a\":\"\x7f\"}", `{"a":"\""}`,
	`{"a":"\\"}`, `{"a":"\/\b\f\n\r\t"}`, `{"a":"\u0000\u001f\u007f"}`, `{"\u0000":1}`, `{"a\"b":1}`,
	`{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud83d\ude00"}`, `{"a":"\ud83d\u0041"}`, `{"a":"\ud83d\ud83d\ude00"}`,
	`{"a":"\ud83d"}`, `{"a":"\ud83d\"}`, `{"a":"\ud83d\u"}`, `{"a":"\ude00\ud83d"}`, `{"a":"\uFFFD\uffff"}`,
	"{\"a\":\"\xff\xfe\"}", "{\"\xff\":1,\"\xfe\":2}", "{\"\xff\":1,\"\\ufffd\":2}", "{\"\xed\xa0\x80\":1}", "{\"a\":\"\xc0\xaf\"}",
	"{\"a\":\"\xe2\x80\xa8\xe2\x80\xa9\"}", `{"a":"\u2028"}`, "{\"\xe6\xbc\xa2\":\"\xe6\xbc\xa2\"}", `{"a":"<>&"}`,
	`{"a":1,"a":2}`, `{"a":{"b":1},"a":{"c":2}}`, `{"a":{"b":1,"b":{"c":[1,{"d":1,"d":2}]}}}`, `{"\u0061":1,"a":2}`, `{"a":2,"\u0061":1}`,
	`{"store":true}`, `{"store":true,"store":null}`, `{"background":false}`, `{"background":1,"background":2}`, `{"\u0062ackground":1}`,
	`{"web_search_options":{}}`, `{"mcp_servers":[]}`, `{"container":null}`, `{"x":{"background":1}}`,
	`{"url":"http://x"}`, `{"url":"data:x"}`, `{"url":" DATA:x"}`, `{"url":"\u00a0data:x"}`, `{"url":"\u2028Data:"}`, `{"url":"data"}`,
	`{"url":"dat\u0061:"}`, `{"url":"\u0130data:"}`, `{"url":"Dâta:"}`, `{"url":""}`, `{"url":1}`, `{"url":null}`, `{"url":{"x":"http"}}`,
	`{"url":["data:", "http"]}`, `{"url":[["http"]]}`, `{"url":[{"url":"data:"}]}`, `{"url":[{"x":"http"}]}`, `{"URL":"http"}`,
	`{"\u0075rl":"http"}`, `{"image_url":{"url":"https://x"}}`, `{"image_url":"https://x"}`, `{"file_url":"h"}`, `{"document_url":"h"}`,
	`{"audio_url":"h"}`, `{"video_url":"h"}`, `{"server_url":"h"}`, `{"urls":"h"}`, `{"url":"http","url":"data:"}`, `{"url":"data:","url":"http"}`,
	`{"m":[{"type":"image","source":{"type":"url","url":"https://x"}}]}`, `{"input_schema":{"url":"h"}}`, `{"parameters":{"url":"h"}}`,
	`{"a":{"input_schema":{"url":"h"},"parameters":[{"url":"h"}]}}`, `{"input":{"url":"h"}}`, `{"type":"tool_use","input":{"url":"h"}}`,
	`{"m":[{"type":"tool_use","input":{"url":"h"}}]}`, `{"m":[{"type":"tool_use","type":"x","input":{"url":"h"}}]}`,
	`{"m":[{"type":"x","type":"tool_use","input":{"url":"h"}}]}`, `{"m":[{"input":{"url":"h"},"type":"tool_use"}]}`,
	`{"m":[{"type":"tool_use","input":{"url":"h"},"input":{}}]}`, `{"m":[{"type":"tool_use","input":{},"input":{"url":"h"}}]}`,
	`{"m":[{"type":"tool_\u0075se","input":{"url":"h"}}]}`, `{"m":[{"type":["tool_use"],"input":{"url":"h"}}]}`,
	`{"m":[{"type":"tool_use","url":"h"}]}`, `{"input_schema":1,"url":"h"}`, `{"url":{"url":"h"},"url":"data:"}`,
	`{"tools":[]}`, `{"tools":null}`, `{"tools":{}}`, `{"tools":"x"}`, `{"tools":[1]}`, `{"tools":[null]}`, `{"tools":[[]]}`,
	`{"tools":[{}]}`, `{"tools":[{"type":"function"}]}`, `{"tools":[{"type":"custom"}]}`, `{"tools":[{"type":"web_search"}]}`,
	`{"tools":[{"type":null}]}`, `{"tools":[{"type":1}]}`, `{"tools":[{"type":{}}]}`, `{"tools":[{"type":"function","type":"x"}]}`,
	`{"tools":[{"type":"x","type":"function"}]}`, `{"tools":[{"type":"x"},1]}`, `{"tools":[1,{"type":"x"}]}`, `{"tools":[{"type":"\u0066unction"}]}`,
	`{"tools":[{"type":"function"}],"tools":{}}`, `{"tools":{},"tools":[]}`, `{"tools":[{"function":{"parameters":{"url":"h"}}}]}`,
	`{"tools":[{"type":"function","url":"h"}]}`, `{"tools":[{"x":{"type":"web"}}]}`,
	`{"stream":true}`, `{"stream":false}`, `{"stream":"true"}`, `{"stream":1}`, `{"stream":true,"stream":false}`, `{"stream":false,"stream":true}`,
	`{"stream":true,"stream_options":{}}`, `{"stream":true,"stream_options":{"include_usage":false,"x":[1]}}`,
	`{"stream":true,"stream_options":{"include_usage":1,"include_usage":2,"a":1,"a":{"b":1,"b":2}}}`, `{"stream":true,"stream_options":null}`,
	`{"stream":true,"stream_options":[1]}`, `{"stream":true,"stream_options":"x"}`, `{"stream_options":{"a":1,"a":2}}`,
	`{"stream":true,"stream_options":{"a":1},"stream_options":{"b":2}}`, `{"stream":true,"stream_options":{"\u0069nclude_usage":0}}`,
	`{"n":12345678901234567890123,"f":1.0000000000000000001,"e":1e400,"z":-0}`, `{"a":[[[[[]]]]],"b":{"c":{"d":{}}}}`,
	` { "a" : [ 1 , { "b" : null } ] , "c" : "d" } `, "{\n\t\"a\":\r\n1}", `{"":1,"":{"":[]}}`, `{"c":1,"b":2,"a":3}`,
}

func TestBodyCheckMatchesDecoder(t *testing.T) {
	// K18g-2: the walk accepts and refuses exactly what the decoder did,
	// with the same reason, and forwards the same body, on the tests'
	// corpus, the edge cases above, generated bodies and their mutations.
	// REQ: K18g-2
	rules := checkRules(t)
	var bodies [][]byte
	bodies = append(bodies, harvestBodies(t)...)
	for _, s := range edgeBodies {
		bodies = append(bodies, []byte(s))
	}
	depth := 10000
	for _, d := range []int{depth - 1, depth, depth + 1} {
		bodies = append(bodies,
			[]byte(strings.Repeat(`{"a":`, d)+"0"+strings.Repeat("}", d)),
			[]byte(`{"a":`+strings.Repeat("[", d-1)+strings.Repeat("]", d-1)+"}"),
			[]byte(strings.Repeat(`{"url":[`, d/2)+`"h"`+strings.Repeat("]}", d/2)))
	}
	rng := rand.New(rand.NewSource(18))
	for i := 0; i < 4000; i++ {
		bodies = append(bodies, genBody(rng))
	}
	n := len(bodies)
	for i := 0; i < 6000; i++ {
		bodies = append(bodies, mutate(rng, bodies[rng.Intn(n)]))
	}
	for _, b := range bodies {
		sameDecision(t, rules, b)
	}
}

// genBody makes an object body from the keys and values the rules look at,
// with duplicates, escapes and invalid UTF-8.
func genBody(rng *rand.Rand) []byte {
	var b []byte
	b = genValue(rng, b, 0, true)
	return b
}

var genKeys = []string{
	`"url"`, `"image_url"`, `"\u0075rl"`, `"type"`, `"input"`, `"input_schema"`, `"parameters"`, `"tools"`, `"stream"`,
	`"stream_options"`, `"include_usage"`, `"background"`, `"store"`, `"mcp_servers"`, `"a"`, `"b"`, `""`, "\"\xff\"",
	`"\ufffd"`, `"\ud800"`, `"\u00e9"`, `"é"`, `"n"`, `"c"`,
}

var genStrings = []string{
	`"data:x"`, `"http://h"`, `" DaTa:"`, `"\u0020data:"`, `"function"`, `"custom"`, `"tool_use"`, `"web"`, `""`,
	"\"\xff\"", `"\ud83d\ude00"`, `"\u2028"`, `"a\"b"`, `"\\"`, `"\u0000"`, `"漢"`, `"\ud800x"`,
}

func genValue(rng *rand.Rand, b []byte, depth int, object bool) []byte {
	ws := func() {
		if rng.Intn(8) == 0 {
			b = append(b, " \t\n\r"[rng.Intn(4)])
		}
	}
	ws()
	k := rng.Intn(10)
	if object || (depth < 6 && k < 3) {
		b = append(b, '{')
		for i, n := 0, rng.Intn(5); i < n; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			ws()
			b = append(b, genKeys[rng.Intn(len(genKeys))]...)
			ws()
			b = append(b, ':')
			b = genValue(rng, b, depth+1, false)
		}
		ws()
		b = append(b, '}')
	} else if depth < 6 && k < 5 {
		b = append(b, '[')
		for i, n := 0, rng.Intn(4); i < n; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			b = genValue(rng, b, depth+1, false)
		}
		b = append(b, ']')
	} else {
		switch rng.Intn(6) {
		case 0, 1, 2:
			b = append(b, genStrings[rng.Intn(len(genStrings))]...)
		case 3:
			b = append(b, []string{"true", "false", "null"}[rng.Intn(3)]...)
		default:
			b = append(b, []string{"0", "-1.5e3", "12345678901234567890", "1.0"}[rng.Intn(4)]...)
		}
	}
	ws()
	return b
}

func mutate(rng *rand.Rand, b []byte) []byte {
	b = append([]byte(nil), b...)
	if len(b) == 0 {
		return []byte{byte(rng.Intn(256))}
	}
	i := rng.Intn(len(b))
	switch rng.Intn(4) {
	case 0:
		const c = `{}[]",:\ 0aeu`
		b[i] = c[rng.Intn(len(c))]
	case 1:
		b[i] = byte(rng.Intn(256))
	case 2:
		b = append(b[:i], b[i+1:]...)
	default:
		b = append(b[:i], append([]byte{`{}[]",:\`[rng.Intn(8)]}, b[i:]...)...)
	}
	return b
}

func TestBodyCheckMemoryPerByte(t *testing.T) {
	// K18g-1: on 8 MiB bodies of the shapes that cost the decoder most,
	// the check holds under three bytes per body byte, the body included,
	// plus two per invalid UTF-8 byte (forwarded as U+FFFD's three) and a
	// few dozen per level of nesting. Everything apply allocates counts.
	// REQ: K18g-1
	op, _ := OpenAI("openai-key").match("POST", "/v1/chat/completions")
	const size = DefaultMaxBody - 64
	array := func(elem string) []byte {
		var b strings.Builder
		b.WriteString(`{"model":"m","a":[`)
		for b.Len() < size-len(elem)-3 {
			b.WriteString(elem + ",")
		}
		b.WriteString(elem + "]}")
		return []byte(b.String())
	}
	var uniq strings.Builder
	uniq.WriteString(`{"model":"m"`)
	for i := 0; uniq.Len() < size-16; i++ {
		fmt.Fprintf(&uniq, `,"%x":0`, i)
	}
	uniq.WriteString("}")
	shapes := map[string][]byte{
		"unique keys":  []byte(uniq.String()),
		"nested":       []byte(strings.Repeat(`{"a":`, 9990) + "0" + strings.Repeat("}", 9990)),
		"deep mixed":   []byte(`{"model":"m","a":` + strings.Repeat(`[{"a":`, 4995) + "0" + strings.Repeat("}]", 4995) + "}"),
		"invalid utf8": array(`"` + strings.Repeat("\xff", 4096) + `"`),
		"u2028":        array(`"` + strings.Repeat("\u2028", 1365) + `"`),
		"cjk":          array(`"` + strings.Repeat("\u6f22", 1365) + `"`),
	}
	for _, e := range []string{`{}`, `[]`, `0`, `{"":0}`, `{"":{}}`, `[{}]`, `{"a":0,"b":0}`, `{"":0,"":0}`, `"\u0000"`} {
		shapes[e] = array(e)
	}
	for name, body := range shapes {
		_, invalid, deepest := bodyShape(body)
		peak := measureApply(t, op.Body, body)
		limit := 3*int64(len(body)) + 2*int64(invalid) + 64*int64(deepest) + 64<<10
		t.Logf("%-14.14s %8d bytes: %.2f per byte", name, len(body), float64(peak)/float64(len(body)))
		if peak > limit {
			t.Errorf("%s: %d bytes hold %d, over %d", name, len(body), peak, limit)
		}
		if c := bodyCost(body); peak > c {
			t.Errorf("%s: %d bytes hold %d, over bodyCost %d", name, len(body), peak, c)
		}
	}
}

// measureApply is the body plus everything apply allocates and the stack
// it grows, on a fresh goroutine.
func measureApply(t *testing.T, rule *BodyRule, body []byte) int64 {
	var heap, stack int64
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		out, e := rule.apply(body, false)
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(out)
		err = e
		heap = int64(after.TotalAlloc - before.TotalAlloc)
		stack = int64(after.StackInuse) - int64(before.StackInuse)
	}()
	<-done
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return int64(len(body)) + heap + max(stack, 0)
}

// streamRig is a proxy whose provider streams a reply far larger than any
// socket buffer, with a write deadline of d.
func streamRig(t *testing.T, d time.Duration) *inFlightRig {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := bytes.Repeat([]byte("data: x\n\n"), 4<<10)
		for i := 0; i < 4096; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("openai-key")}, Grants: map[string][]string{"m0": {"openai"}},
		Vault: r.vault, Audit: r.audit, Transport: r.transport, WriteTimeout: d,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &inFlightRig{p: p}
}

// stallClient sends a streamed chat over a raw connection and then never
// reads, so the server's writes block once the socket buffers fill.
func stallClient(t *testing.T, url string) net.Conn {
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetReadBuffer(4 << 10)
	}
	t.Cleanup(func() { c.Close() })
	body := `{"model":"m","stream":true,"messages":[]}`
	w := bufio.NewWriter(c)
	fmt.Fprintf(w, "POST /openai/v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
		"Authorization: Bearer placeholder\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	w.Flush()
	return c
}

func waitSlots(t *testing.T, ir *inFlightRig, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	held := false
	for time.Now().Before(deadline) {
		g, per := ir.slots()
		if g != 0 || len(per) != 0 {
			held = true
		} else if held {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	g, per := ir.slots()
	t.Fatalf("slots still held after %v (seen held %v): reserved %d, machines %v", within, held, g, per)
}

func TestStalledReaderReleasesSlot(t *testing.T) {
	// K18g-3: a guest that stops reading a streamed reply holds its slots
	// only until a write waits past the write deadline, whether the server
	// is the proxy's own handler or a handler that wraps it.
	// REQ: K18g-3
	const d = 200 * time.Millisecond
	t.Run("proxy", func(t *testing.T) {
		ir := streamRig(t, d)
		srv := httptest.NewServer(ir.p.Handler("m0"))
		t.Cleanup(srv.Close)
		stallClient(t, srv.URL)
		waitSlots(t, ir, 10*time.Second)
	})
	t.Run("wrapped", func(t *testing.T) {
		ir := streamRig(t, time.Hour)
		h := ir.p.Handler("m0")
		srv := httptest.NewServer(WithWriteDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}), d))
		t.Cleanup(srv.Close)
		stallClient(t, srv.URL)
		waitSlots(t, ir, 10*time.Second)
	})
	t.Run("reader keeps up", func(t *testing.T) {
		// The deadline is per write: a reply that takes longer than d in
		// all still arrives whole.
		ir := streamRig(t, d)
		srv := httptest.NewServer(ir.p.Handler("m0"))
		t.Cleanup(srv.Close)
		resp, err := http.Post(srv.URL+"/openai/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var n int64
		buf := make([]byte, 64<<10)
		start := time.Now()
		for {
			k, err := resp.Body.Read(buf)
			n += int64(k)
			if err != nil {
				break
			}
			if time.Since(start) < 4*d {
				time.Sleep(time.Millisecond)
			}
		}
		if want := int64(4096 * 9 * 4 << 10); n != want {
			t.Fatalf("read %d of %d bytes", n, want)
		}
	})
}

func TestDefaultWriteTimeout(t *testing.T) {
	// REQ: K18g-3
	ir := newInFlightRig(t, 0, 1, Cap{})
	if ir.p.writeTimeout != DefaultWriteTimeout || DefaultWriteTimeout <= 0 {
		t.Fatalf("write timeout %v, default %v", ir.p.writeTimeout, DefaultWriteTimeout)
	}
}

func TestMachineShareOfBudget(t *testing.T) {
	// K18g-4: no machine holds more than half the budget, so machines at
	// their share leave room for another.
	// REQ: K18g-4
	t.Run("admit", func(t *testing.T) {
		ir := newInFlightRig(t, 4*chatCost(t), 3, Cap{})
		done := make(chan int, 4)
		for i := 0; i < 2; i++ {
			go func() { done <- ir.do("m0").Code }()
			<-ir.entered
		}
		w := refusedSoon(t, ir, func() *httptest.ResponseRecorder { return ir.do("m0") })
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many requests in flight") {
			t.Fatalf("m0 over its share: %d %q", w.Code, w.Body)
		}
		if g, per := ir.slots(); g != 2*chatCost(t) || per["m0"] != 2 {
			t.Fatalf("after the refusal: reserved %d, machines %v", g, per)
		}
		// The rest of the budget is still there for the others.
		for _, m := range []string{"m1", "m2"} {
			go func() { done <- ir.do(m).Code }()
			<-ir.entered
		}
		close(ir.block)
		for i := 0; i < 4; i++ {
			if c := <-done; c != 200 {
				t.Fatalf("held request: %d", c)
			}
		}
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: reserved %d, machines %v", g, per)
		}
	})
	t.Run("check", func(t *testing.T) {
		// A body whose check would take m0 past its share waits, though
		// the budget has room.
		bad := []byte(`{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("\xff", 1<<20) + `"}]}`)
		ir := newInFlightRig(t, 2*(chatCost(t)+bodyCost(bad))-2, 2, Cap{})
		if readCost(int64(len(bad)))+chatCost(t) > ir.p.share {
			t.Fatal("rig: the read alone would not fit the share")
		}
		done := make(chan int, 2)
		go func() { done <- ir.do("m0").Code }()
		<-ir.entered
		w := refusedSoon(t, ir, func() *httptest.ResponseRecorder { return ir.post("m0", chatOf(bad)) })
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many requests in flight") {
			t.Fatalf("m0's costly body over its share: %d %q", w.Code, w.Body)
		}
		go func() { done <- ir.post("m1", chatOf(bad)).Code }()
		<-ir.entered
		close(ir.block)
		for i := 0; i < 2; i++ {
			if c := <-done; c != 200 {
				t.Fatalf("held request: %d", c)
			}
		}
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: reserved %d, machines %v", g, per)
		}
	})
}

// refusedSoon runs do, which the share cap should refuse at once; an
// admitted request would block on the rig, so it fails the test instead.
func refusedSoon(t *testing.T, ir *inFlightRig, do func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	got := make(chan *httptest.ResponseRecorder, 1)
	go func() { got <- do() }()
	select {
	case w := <-got:
		return w
	case <-ir.entered:
		close(ir.block)
		t.Fatal("admitted over the machine's share")
	case <-time.After(10 * time.Second):
		t.Fatal("no answer within 10s")
	}
	return nil
}
