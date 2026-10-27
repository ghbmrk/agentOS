package homekit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// Each case below is input that only the named check refuses: the input is
// otherwise well formed, so removing that one check makes the case pass and
// the test fail. All keys are generated per test; IDs sit in the RFC 7042
// documentation range.

// REQ: DEV-1, KRN-2
func TestTLV8Bounds(t *testing.T) {
	oversize := encodeTLV(tv(tlvPublicKey, bytes.Repeat([]byte{7}, maxTLVInput+1))) // fragments join into one item
	var many []byte
	for typ := byte(0x10); typ < 0x10+maxTLVItems+1; typ++ {
		many = append(many, typ, 1, typ)
	}
	for _, tc := range []struct {
		name  string
		check string
		in    []byte
	}{
		{"over 4 KiB of valid fragments", "tlv8.go size cap", oversize},
		{"17 distinct items", "tlv8.go item cap", many},
		{"same type after a short fragment", "tlv8.go join only after a full fragment", []byte{3, 1, 1, 3, 1, 2}},
		{"truncated value", "truncated value", []byte{6, 3, 1}},
		{"truncated header", "truncated header", []byte{6}},
		{"repeated type", "duplicate type", []byte{6, 1, 1, 7, 1, 1, 6, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeTLV(tc.in); !errors.Is(err, ErrProtocol) {
				t.Fatalf("%s: accepted (%v)", tc.check, err)
			}
		})
	}
	// The cases are not vacuous: just under each bound decodes.
	if _, err := decodeTLV(many[:3*maxTLVItems]); err != nil {
		t.Fatalf("16 items: %v", err)
	}
	if m, err := decodeTLV(encodeTLV(tv(tlvPublicKey, bytes.Repeat([]byte{7}, 4000)))); err != nil || len(m[tlvPublicKey]) != 4000 {
		t.Fatalf("4000-byte item: %v", err)
	}
}

// REQ: DEV-1, KRN-2
func TestResponseFramingBounds(t *testing.T) {
	ok := "HTTP/1.1 200 OK\r\n"
	headers := func(n int) string { return strings.Repeat("X-Canary: 1\r\n", n) }
	chunks := func(n int) string { return strings.Repeat("1\r\na\r\n", n) + "0\r\n\r\n" }
	bigBody := strings.Repeat("a", maxBody+1)
	for _, tc := range []struct {
		name, check, in string
	}{
		{"long header line", "http.go line cap", ok + "X-Canary: " + strings.Repeat("a", 2*maxLine) + "\r\nContent-Length: 0\r\n\r\n"},
		{"line over the buffer", "http.go line cap (buffer)", ok + "X-Canary: " + strings.Repeat("a", 2*readBufSize) + "\r\nContent-Length: 0\r\n\r\n"},
		{"too many headers", "http.go header cap", ok + headers(maxHeaders+2) + "Content-Length: 0\r\n\r\n"},
		{"content-length over the cap", "http.go content-length cap", ok + fmt.Sprintf("Content-Length: %d\r\n\r\n", maxBody+1) + bigBody},
		{"content-length twice", "http.go content-length repeat", ok + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}"},
		{"content-length too many digits", "http.go content-length digits", ok + "Content-Length: 00000002\r\n\r\n{}"},
		{"content-length negative", "http.go content-length sign", "HTTP/1.1 204 No Content\r\nContent-Length: -1\r\n\r\n"},
		{"content-length and chunked", "http.go length plus chunked", ok + "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"},
		{"chunked twice", "http.go transfer-encoding repeat", ok + "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"},
		{"body without a length", "http.go no body without a length", ok + "Content-Type: application/hap+json\r\n\r\n"},
		{"chunked body over the cap", "http.go chunked cap", ok + "Transfer-Encoding: chunked\r\n\r\n" + fmt.Sprintf("%x\r\n", maxBody+1) + bigBody + "\r\n0\r\n\r\n"},
		{"too many chunks", "http.go chunk-count cap", ok + "Transfer-Encoding: chunked\r\n\r\n" + chunks(maxChunks+2)},
		{"too many trailers", "http.go trailer cap", ok + "Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n" + headers(maxHeaders+2) + "\r\n"},
		{"status 600", "http.go status range", "HTTP/1.1 600 X\r\nContent-Length: 0\r\n\r\n"},
		{"bad status line", "http.go status line", "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := readResponse(bufio.NewReaderSize(strings.NewReader(tc.in), readBufSize))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("%s: response %v accepted (%v)", tc.check, r != nil, err)
			}
		})
	}
	// Just inside each bound is accepted, so the cases are not vacuous.
	for name, in := range map[string]string{
		"32 headers":     ok + headers(maxHeaders-1) + "Content-Length: 0\r\n\r\n",
		"1024 chunks":    ok + "Transfer-Encoding: chunked\r\n\r\n" + chunks(maxChunks),
		"max body":       ok + fmt.Sprintf("Content-Length: %d\r\n\r\n", maxBody) + bigBody[1:],
		"max chunked":    ok + "Transfer-Encoding: chunked\r\n\r\n" + fmt.Sprintf("%x\r\n", maxBody) + bigBody[1:] + "\r\n0\r\n\r\n",
		"no-body 204":    "HTTP/1.1 204 No Content\r\n\r\n",
		"1000-byte line": ok + "X-Canary: " + strings.Repeat("a", 1000-10) + "\r\nContent-Length: 0\r\n\r\n",
	} {
		if _, err := readResponse(bufio.NewReaderSize(strings.NewReader(in), readBufSize)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// sealFrame builds one session frame with any length field n over plain.
func sealFrame(t *testing.T, key []byte, counter uint64, n int, plain []byte) []byte {
	t.Helper()
	a, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{byte(n), byte(n >> 8)}
	nonce := make([]byte, 12)
	for i := 0; i < 8; i++ {
		nonce[4+i] = byte(counter >> (8 * i))
	}
	return a.Seal(hdr, nonce, plain, hdr)
}

// REQ: DEV-1, KRN-2
func TestFrameLengthBounds(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		// Authentic frames: only the 1..1024 length check refuses them.
		{"length 0", sealFrame(t, key, 0, 0, nil)},
		{"length 1025", sealFrame(t, key, 0, maxFrame+1, bytes.Repeat([]byte("x"), maxFrame+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _ := newFrameCipher(key)
			fr := &frameReader{r: bytes.NewReader(tc.frame), c: rc}
			if _, err := fr.Read(make([]byte, 2048)); !errors.Is(err, ErrProtocol) {
				t.Fatalf("frame accepted: %v", err)
			}
		})
	}
	rc, _ := newFrameCipher(key)
	fr := &frameReader{r: bytes.NewReader(sealFrame(t, key, 0, maxFrame, bytes.Repeat([]byte("x"), maxFrame))), c: rc}
	if out, err := io.ReadAll(fr); err != nil || len(out) != maxFrame {
		t.Fatalf("a full 1024-byte frame: %d bytes, %v", len(out), err)
	}
}

// hostileHolder is a key holder with a bad pairing ID or public key.
type hostileHolder struct {
	*MemoryKeyHolder
	id string
	pk ed25519.PublicKey
}

func (h hostileHolder) PairingID() string            { return h.id }
func (h hostileHolder) PublicKey() ed25519.PublicKey { return h.pk }

// REQ: DEV-3, A16
func TestPairSetupRefusesBadAccessoryProof(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name  string
		check string
		set   func(a *fakeAccessory)
		want  error
	}{
		{"M6 signed by another key", "pair.go accessory signature at M6", func(a *fakeAccessory) { a.m6SignKey = other }, ErrAuthentication},
		{"M6 identifier not printable", "pair.go pin.Valid", func(a *fakeAccessory) { a.m6ID = "00:00:5E:00:53:01\n" }, ErrProtocol},
		{"M6 identifier too long", "pair.go pin.Valid", func(a *fakeAccessory) { a.m6ID = strings.Repeat("A", 65) }, ErrProtocol},
		{"M6 key short", "pair.go pin.Valid", func(a *fakeAccessory) { a.m6LTPK = a.ltsk.Public().(ed25519.PublicKey)[:31] }, ErrProtocol},
		{"M2 with the wrong state", "pair.go state", func(a *fakeAccessory) { a.setupState = 4 }, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acc := newFakeAccessory(t)
			tc.set(acc)
			pin, err := PairSetup(acc.connect(t), host, testCode, newHolder(t), Options{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s: err %v, want %v", tc.check, err, tc.want)
			}
			if pin.AccessoryID != "" || pin.LTPK != nil || pin.Valid() {
				t.Fatalf("%s: a key was pinned", tc.check)
			}
		})
	}
	// Control: the unaltered accessory pairs.
	if _, err := PairSetup(newFakeAccessory(t).connect(t), host, testCode, newHolder(t), Options{}); err != nil {
		t.Fatal(err)
	}
}

// REQ: DEV-3, A16
func TestPairSetupRefusesBadKeyHolder(t *testing.T) {
	kh := newHolder(t)
	for name, h := range map[string]hostileHolder{
		"empty id":  {kh, "", kh.PublicKey()},
		"short key": {kh, kh.PairingID(), kh.PublicKey()[:31]},
	} {
		acc := newFakeAccessory(t)
		c := acc.connect(t)
		if _, err := PairSetup(c, host, testCode, h, Options{}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
		acc.mu.Lock()
		tries := acc.tries
		acc.mu.Unlock()
		if c.n() != 0 || tries != 0 {
			t.Errorf("%s: %d bytes reached the accessory", name, c.n())
		}
	}
}

// REQ: DEV-3, KRN-2
func TestPairVerifyRefusesBytesAfterM4(t *testing.T) {
	kh := newHolder(t)
	acc := newFakeAccessory(t)
	pin, err := PairSetup(acc.connect(t), host, testCode, kh, Options{})
	if err != nil {
		t.Fatal(err)
	}
	acc.mu.Lock()
	acc.afterVerify = []byte("HTTP/1.1 204 No Content\r\n\r\n") // plaintext a session would read as its first answer
	acc.mu.Unlock()
	if s, err := Verify(acc.connect(t), host, pin, kh, Options{}); !errors.Is(err, ErrProtocol) || s != nil {
		t.Fatalf("session %v err %v", s != nil, err)
	}
	acc.mu.Lock()
	acc.afterVerify = nil
	acc.mu.Unlock()
	s, err := Verify(acc.connect(t), host, pin, kh, Options{})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	s.Close()
}

// hostilePeer is the accessory end of a session that answers each request
// with the raw HTTP bytes answer returns (sealed into frames), so a test can
// send any framing a hostile accessory could.
func hostilePeer(t *testing.T, opt Options, answer func(req *http.Request, n int) string) (*Session, *tapConn) {
	t.Helper()
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	shared := make([]byte, 32)
	rand.Read(shared)
	tap := &tapConn{Conn: c}
	s, err := newSession(tap, host, shared, opt)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		rc, _ := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Write-Encryption-Key"))
		wc, _ := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Read-Encryption-Key"))
		br := bufio.NewReader(&frameReader{r: p, c: rc})
		fw := &frameWriter{w: p, c: wc}
		for n := 0; ; n++ {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			io.ReadAll(req.Body)
			out := hapResp(200, hostileAccessories)
			if req.URL.Path != "/accessories" {
				out = answer(req, n)
			}
			if _, err := fw.Write([]byte(out)); err != nil {
				return
			}
		}
	}()
	if err := s.Resolve(); err != nil {
		t.Fatal(err)
	}
	return s, tap
}

func hapResp(status int, body string) string {
	return fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Type: application/hap+json\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body)
}

func hapEvent(body string) string {
	return fmt.Sprintf("EVENT/1.0 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func valuesBody(ids ...ID) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(`{"aid":%d,"iid":%d,"value":1}`, id.AID, id.IID))
	}
	return `{"characteristics":[` + strings.Join(parts, ",") + `]}`
}

var (
	idEv      = ID{1, 2} // pr, ev
	idNoEv    = ID{1, 3} // pr only
	idNoPr    = ID{1, 4} // pw, ev: write-only
	idEnum    = ID{1, 5} // uint8 0..3, valid-values 0, 1, 2
	idInt     = ID{1, 6} // uint8, no range, step or values
	idUnknown = ID{9, 9}
)

const hostileAccessories = `{"accessories":[{"aid":1,"services":[{"type":"4A","characteristics":[` +
	`{"iid":2,"type":"11","perms":["pr","ev"],"format":"float"},` +
	`{"iid":3,"type":"F","perms":["pr"],"format":"uint8"},` +
	`{"iid":4,"type":"35","perms":["pw","ev"],"format":"float"},` +
	`{"iid":5,"type":"33","perms":["pr","pw"],"format":"uint8","minValue":0,"maxValue":3,"valid-values":[0,1,2]},` +
	`{"iid":6,"type":"ABCD","perms":["pw"],"format":"uint8"}]}]}]}`

// REQ: DEV-1, DEV-4, KRN-2
func TestSessionRefusesHostileResponses(t *testing.T) {
	t.Run("redirect", func(t *testing.T) { // session.go redirect refusal
		s, _ := hostilePeer(t, Options{}, func(req *http.Request, n int) string {
			if n == 1 {
				return "HTTP/1.1 302 Found\r\nLocation: /canary\r\nContent-Length: 0\r\n\r\n"
			}
			return hapResp(200, valuesBody(idEv))
		})
		if _, err := s.Read(idEv); !errors.Is(err, ErrProtocol) {
			t.Fatalf("redirect: %v", err)
		}
		if _, err := s.Read(idEv); !errors.Is(err, ErrClosed) {
			t.Fatalf("session continued after a redirect: %v", err)
		}
	})
	t.Run("redirect on write", func(t *testing.T) {
		s, _ := hostilePeer(t, Options{}, func(req *http.Request, n int) string {
			if n == 1 {
				return "HTTP/1.1 307 Temporary Redirect\r\nLocation: /canary\r\nContent-Length: 0\r\n\r\n"
			}
			return "HTTP/1.1 204 No Content\r\n\r\n"
		})
		if err := s.Write(idEnum, 1); !errors.Is(err, ErrProtocol) {
			t.Fatalf("redirect: %v", err)
		}
		if err := s.Write(idEnum, 1); !errors.Is(err, ErrClosed) {
			t.Fatalf("session continued after a redirect: %v", err)
		}
	})
	t.Run("event flood", func(t *testing.T) { // session.go events-before-a-response cap
		var mu sync.Mutex
		events := 0
		s, _ := hostilePeer(t, Options{OnEvent: func(v []Value) { mu.Lock(); events += len(v); mu.Unlock() }}, func(req *http.Request, n int) string {
			return strings.Repeat(hapEvent(valuesBody(idEv)), maxEventsWait) + hapResp(200, valuesBody(idEv))
		})
		if _, err := s.Read(idEv); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%d events before a response: %v", maxEventsWait, err)
		}
		if events != maxEventsWait {
			t.Fatalf("%d events delivered", events)
		}
	})
	t.Run("events under the cap", func(t *testing.T) {
		s, _ := hostilePeer(t, Options{}, func(req *http.Request, n int) string {
			return strings.Repeat(hapEvent(valuesBody(idEv)), maxEventsWait-1) + hapResp(200, valuesBody(idEv))
		})
		if _, err := s.Read(idEv); err != nil {
			t.Fatal(err)
		}
	})
}

// REQ: DEV-4
func TestSessionDropsUnaskedValues(t *testing.T) {
	var mu sync.Mutex
	var got []ID
	opt := Options{OnEvent: func(vs []Value) {
		mu.Lock()
		defer mu.Unlock()
		for _, v := range vs {
			got = append(got, v.ID)
		}
	}}
	s, c := hostilePeer(t, opt, func(req *http.Request, n int) string {
		// An event for a resolved ev characteristic, a resolved one
		// without ev and an unresolved one; then a read answer that adds
		// IDs nobody asked for.
		return hapEvent(valuesBody(idEv, idNoEv, idUnknown, idNoPr)) + hapResp(200, valuesBody(idEv, idNoEv, idUnknown))
	})
	vals, err := s.Read(idEv) // session.go unasked read IDs
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 || vals[0].ID != idEv {
		t.Fatalf("read returned %v, want only %v", vals, idEv)
	}
	mu.Lock()
	if len(got) != 2 || got[0] != idEv || got[1] != idNoPr { // session.go ev filter
		t.Fatalf("events delivered for %v, want %v and %v", got, idEv, idNoPr)
	}
	mu.Unlock()
	before := c.n()
	if _, err := s.Read(idNoPr); !errors.Is(err, ErrRefused) { // session.go pr
		t.Fatalf("read of a write-only characteristic: %v", err)
	}
	if err := s.Subscribe(idNoEv); !errors.Is(err, ErrRefused) {
		t.Fatalf("subscribe without ev: %v", err)
	}
	if c.n() != before {
		t.Fatalf("%d bytes written before the refusal", c.n()-before)
	}
}

// REQ: DEV-4
func TestWriteKeepsToDeclaredValuesAndFormat(t *testing.T) {
	s, c := hostilePeer(t, Options{}, func(req *http.Request, n int) string { return "HTTP/1.1 204 No Content\r\n\r\n" })
	for _, tc := range []struct {
		name, check string
		id          ID
		v           any
	}{
		{"3 inside 0..3 but not a valid value", "session.go valid-values", idEnum, 3},
		{"3.0 not a valid value", "session.go valid-values", idEnum, 3.0},
		{"fractional uint8 with no step", "session.go integer format", idInt, 1.5},
		{"uint8 over 255", "session.go integer format range", idInt, 256},
		{"uint8 negative", "session.go integer format range", idInt, -1},
		{"bool on uint8", "session.go bool format", idInt, true},
	} {
		before := c.n()
		if err := s.Write(tc.id, tc.v); !errors.Is(err, ErrRefused) {
			t.Errorf("%s (%s): %v", tc.name, tc.check, err)
		}
		if c.n() != before {
			t.Errorf("%s: %d bytes written before the refusal", tc.name, c.n()-before)
		}
	}
	for _, w := range []struct {
		id ID
		v  any
	}{{idEnum, 2}, {idInt, 255}, {idInt, 0.0}} {
		if err := s.Write(w.id, w.v); err != nil {
			t.Errorf("declared write %v=%v refused: %v", w.id, w.v, err)
		}
	}
}

// REQ: DEV-1, DEV-4, KRN-2
func TestAccessoriesJSONBounds(t *testing.T) {
	char := func(iid int) string {
		return fmt.Sprintf(`{"iid":%d,"type":"11","perms":["pr"],"format":"float"}`, iid)
	}
	svc := func(chars ...string) string {
		return `{"type":"4A","characteristics":[` + strings.Join(chars, ",") + `]}`
	}
	acc := func(aid int, svcs ...string) string {
		return fmt.Sprintf(`{"aid":%d,"services":[%s]}`, aid, strings.Join(svcs, ","))
	}
	doc := func(accs ...string) []byte { return []byte(`{"accessories":[` + strings.Join(accs, ",") + `]}`) }
	rep := func(n int, f func(i int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	for _, tc := range []struct {
		name, check string
		in          []byte
	}{
		{"duplicate characteristic across services", "session.go duplicate", doc(acc(1, svc(char(2)), svc(char(2))))},
		{"duplicate characteristic in a service", "session.go duplicate", doc(acc(1, svc(char(2), char(2))))},
		{"151 accessories", "session.go accessory cap", doc(rep(maxAccessories+1, func(i int) string { return acc(i+1, svc(char(2))) })...)},
		{"no accessories", "session.go accessory cap", doc()},
		{"65 services", "session.go service cap", doc(acc(1, rep(maxServices+1, func(i int) string { return svc(char(i + 2)) })...))},
		{"65 characteristics", "session.go characteristic cap", doc(acc(1, svc(rep(maxChars+1, func(i int) string { return char(i + 2) })...)))},
		{"9 perms", "session.go perms cap", doc(acc(1, svc(`{"iid":2,"type":"11","perms":["pr","pr","pr","pr","pr","pr","pr","pr","pr"],"format":"float"}`)))},
		{"long format", "session.go format cap", doc(acc(1, svc(`{"iid":2,"type":"11","perms":["pr"],"format":"`+strings.Repeat("f", 17)+`"}`)))},
		{"65 valid values", "session.go valid-values cap", doc(acc(1, svc(`{"iid":2,"type":"11","perms":["pr"],"format":"uint8","valid-values":[`+strings.TrimSuffix(strings.Repeat("1,", 65), ",")+`]}`)))},
		{"bad type", "session.go type", doc(acc(1, svc(`{"iid":2,"type":"XYZ","perms":["pr"],"format":"float"}`)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if m, err := parseAccessories(tc.in); !errors.Is(err, ErrProtocol) {
				t.Fatalf("%s: %d characteristics accepted (%v)", tc.check, len(m), err)
			}
		})
	}
	// Just inside each bound parses.
	for name, in := range map[string][]byte{
		"150 accessories":    doc(rep(maxAccessories, func(i int) string { return acc(i+1, svc(char(2))) })...),
		"64 services":        doc(acc(1, rep(maxServices, func(i int) string { return svc(char(i + 2)) })...)),
		"64 characteristics": doc(acc(1, svc(rep(maxChars, func(i int) string { return char(i + 2) })...))),
		"same iid, two aids": doc(acc(1, svc(char(2))), acc(2, svc(char(2)))),
	} {
		if _, err := parseAccessories(in); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// A 1xx interim reply is refused, ending the session, instead of being
// taken as the answer and knocking the stream out of step (#3325 item 7),
// whether or not it carries a body length.
// REQ: DEV-1, KRN-2
func TestInterimReplyIsRefused(t *testing.T) {
	for name, interim := range map[string]string{
		"bare":    "HTTP/1.1 100 Continue\r\n\r\n",
		"length":  "HTTP/1.1 100 Continue\r\nContent-Length: 2\r\n\r\n{}",
		"chunked": "HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := hostilePeer(t, Options{}, func(*http.Request, int) string {
				return interim + hapResp(200, valuesBody(idEv))
			})
			if _, err := s.Read(idEv); !errors.Is(err, ErrProtocol) {
				t.Fatalf("1xx reply: %v", err)
			}
			if _, err := s.Read(idEv); !errors.Is(err, ErrClosed) {
				t.Fatalf("session open after a 1xx reply: %v", err)
			}
		})
	}
}
