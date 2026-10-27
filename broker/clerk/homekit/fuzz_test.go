package homekit

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// REQ: DEV-1, KRN-2

func FuzzTLV8(f *testing.F) {
	f.Add(encodeTLV(tb(tlvState, 2), tv(tlvSalt, make([]byte, 16)), tv(tlvPublicKey, make([]byte, 384))))
	f.Add([]byte{6, 1, 4, 7, 1, 2})
	f.Add([]byte{3, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeTLV(b)
		if err != nil {
			return
		}
		total := 0
		for typ, v := range m {
			total += len(v)
			if _, err := decodeTLV(encodeTLV(tv(typ, v))); err != nil && len(v) <= maxTLVInput-32 {
				t.Fatalf("re-encoded item does not decode: %v", err)
			}
		}
		if total > len(b) || len(m) > maxTLVItems {
			t.Fatalf("decoded %d bytes in %d items from %d", total, len(m), len(b))
		}
	})
}

func FuzzSessionFrame(f *testing.F) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	var wire bytes.Buffer
	c, _ := newFrameCipher(key)
	(&frameWriter{w: &wire, c: c}).Write(bytes.Repeat([]byte("x"), 1500))
	f.Add(wire.Bytes())
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		rc, _ := newFrameCipher(key)
		fr := &frameReader{r: bytes.NewReader(b), c: rc}
		out, _ := io.ReadAll(io.LimitReader(fr, 1<<20))
		if len(out) > len(b) {
			t.Fatalf("%d plaintext bytes from %d", len(out), len(b))
		}
	})
}

func FuzzResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: 2\r\n\r\n{}"))
	f.Add([]byte("EVENT/1.0 200 OK\r\nContent-Length: 47\r\n\r\n{\"characteristics\":[{\"aid\":1,\"iid\":2,\"value\":1}]}"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 302 Found\r\nLocation: x\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n"))
	f.Add([]byte(thermostatJSON))
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(b), readBufSize)
		for i := 0; i < 4; i++ {
			r, err := readResponse(br)
			if err != nil {
				return
			}
			if len(r.body) > maxBody {
				t.Fatalf("body of %d bytes", len(r.body))
			}
			parseAccessories(r.body)
			parseValues(r.body)
		}
	})
}

func FuzzAccessoriesJSON(f *testing.F) {
	f.Add([]byte(thermostatJSON))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseAccessories(b)
		if err != nil {
			return
		}
		for _, c := range m {
			checkValue(c, 21.0)
			checkValue(c, true)
		}
	})
}

// FuzzSessionRoundTrip frames the fuzzed bytes as an accessory would, so
// every input passes AEAD and reaches the response parser through the frame
// reader (#3325 item 5).
func FuzzSessionRoundTrip(f *testing.F) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))
	f.Add([]byte("EVENT/1.0 200 OK\r\nContent-Length: 47\r\n\r\n{\"characteristics\":[{\"aid\":1,\"iid\":2,\"value\":1}]}HTTP/1.1 204 No Content\r\n\r\n"))
	f.Add(append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n"), bytes.Repeat([]byte("a"), 2000)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		var wire bytes.Buffer
		wc, _ := newFrameCipher(key)
		if _, err := (&frameWriter{w: &wire, c: wc}).Write(b); err != nil {
			t.Fatal(err)
		}
		rc, _ := newFrameCipher(key)
		br := bufio.NewReaderSize(&frameReader{r: &wire, c: rc}, readBufSize)
		for i := 0; i < 4; i++ {
			r, err := readResponse(br)
			if err != nil {
				return
			}
			if len(r.body) > maxBody || len(r.body) > len(b) {
				t.Fatalf("body of %d bytes from %d", len(r.body), len(b))
			}
			parseValues(r.body)
		}
	})
}
