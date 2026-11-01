package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// REQ: NET-2, DEV-2

func honest() map[Direction][]Msg {
	var h [HashLen]byte
	h[0] = 7
	return map[Direction][]Msg{
		ToEnforcer: {
			Hello{Role: RoleCore},
			Command{ID: 1, Device: "lamp", Verb: VerbOn},
			Command{ID: 2, Device: "lamp", Verb: VerbLevel, Level: MaxLevel},
			Command{ID: 3, Device: "drone-1", Verb: VerbReturnToDock},
			Tighten{ID: 4, Kind: RemoveDestination, Device: "tv", Host: "ads.example"},
			Tighten{ID: 5, Kind: CutVendorCloud, Device: "tv"},
			Tighten{ID: 6, Kind: RemovePair, A: "tv", B: "speaker"},
			Tighten{ID: 7, Kind: IsolateDevice, Device: "tv"},
			Tighten{ID: 8, Kind: RemoveDevice, Device: "tv"},
			Tighten{ID: 9, Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 10, ToMS: 20},
			Tighten{ID: 10, Kind: RevokeRule, Device: "lock", Rule: "plumber"},
			Read{ID: 11, What: ReadState, Device: "lamp"},
			Read{ID: 12, What: ReadExport},
			Read{ID: 13, What: ReadFingerprint, Device: "lock"},
			Read{ID: 14, What: ReadTraffic, Device: "tv"},
			Announce{ID: 15, Link: h},
			Head{ID: 16, Seq: 99, Hash: h},
			Entry{ID: 17, Body: []byte(`{"type":"key.revoked"}`)},
			Challenge{Answer: true, ID: 18, Data: []byte{1, 2, 3}},
			Challenge{Answer: true, ID: 19, Data: []byte{}},
		},
		ToCore: {
			Hello{Role: RoleEnforcer},
			Result{ID: 1, Code: NeedsOwner},
			ReadReply{ID: 2, Body: []byte("state")},
			ReadReply{ID: 3, Body: []byte{}},
			Challenge{ID: 4, Data: bytes.Repeat([]byte{9}, ChallengeData)},
			Alert{Kind: AlertText, Text: "The heater in the hall was turned off."},
		},
	}
}

// TestRoundTrip: every honest message encodes, crosses a stream and
// decodes to itself, on its own direction only.
func TestRoundTrip(t *testing.T) {
	for d, msgs := range honest() {
		other := ToCore
		if d == ToCore {
			other = ToEnforcer
		}
		for _, m := range msgs {
			f, err := Encode(d, m)
			if err != nil {
				t.Fatalf("%T %+v: %v", m, m, err)
			}
			var buf bytes.Buffer
			if err := WriteFrame(&buf, d, f); err != nil {
				t.Fatalf("%T: write: %v", m, err)
			}
			got, err := ReadFrame(&buf, d)
			if err != nil {
				t.Fatalf("%T: read: %v", m, err)
			}
			back, err := Decode(d, got)
			if err != nil {
				t.Fatalf("%T: decode: %v", m, err)
			}
			if !reflect.DeepEqual(back, m) {
				t.Errorf("%T: got %+v, want %+v", m, back, m)
			}
			if f.Type != THello {
				if _, err := Decode(other, got); !errors.Is(err, ErrType) {
					t.Errorf("%T decoded on the other side: %v", m, err)
				}
			}
		}
	}
}

// TestRefused: each near miss of an honest message is refused by Encode
// and by Decode. Revert mutant: dropping any one check in Decode passes its
// row.
func TestRefused(t *testing.T) {
	long := strings.Repeat("a", MaxName+1)
	rows := []struct {
		name string
		d    Direction
		m    Msg
	}{
		{"core hello claims the enforcer's role", ToEnforcer, Hello{Role: RoleEnforcer}},
		{"enforcer hello claims the core's role", ToCore, Hello{Role: RoleCore}},
		{"unknown verb", ToEnforcer, Command{ID: 1, Device: "lamp", Verb: 8}},
		{"zero verb", ToEnforcer, Command{ID: 1, Device: "lamp"}},
		{"level over 100", ToEnforcer, Command{ID: 1, Device: "lamp", Verb: VerbLevel, Level: 101}},
		{"level on a non-level verb", ToEnforcer, Command{ID: 1, Device: "lamp", Verb: VerbOn, Level: 1}},
		{"command names no device", ToEnforcer, Command{ID: 1, Verb: VerbOn}},
		{"device with a space", ToEnforcer, Command{ID: 1, Device: "front door", Verb: VerbLock}},
		{"device with a slash", ToEnforcer, Command{ID: 1, Device: "a/b", Verb: VerbLock}},
		{"device with a control character", ToEnforcer, Command{ID: 1, Device: "a\x00", Verb: VerbLock}},
		{"device not UTF-8", ToEnforcer, Command{ID: 1, Device: "\xff", Verb: VerbLock}},
		{"device too long", ToEnforcer, Command{ID: 1, Device: long, Verb: VerbLock}},
		{"unknown tightening", ToEnforcer, Tighten{ID: 1, Kind: 8, Device: "tv"}},
		{"remove-destination without a host", ToEnforcer, Tighten{ID: 1, Kind: RemoveDestination, Device: "tv"}},
		{"cut-vendor-cloud with a host", ToEnforcer, Tighten{ID: 1, Kind: CutVendorCloud, Device: "tv", Host: "x"}},
		{"remove-pair with a device", ToEnforcer, Tighten{ID: 1, Kind: RemovePair, Device: "tv", A: "a", B: "b"}},
		{"remove-pair to itself", ToEnforcer, Tighten{ID: 1, Kind: RemovePair, A: "a", B: "a"}},
		{"revoke-rule with a window", ToEnforcer, Tighten{ID: 1, Kind: RevokeRule, Device: "l", Rule: "r", ToMS: 5}},
		{"narrow-rule with an empty window", ToEnforcer, Tighten{ID: 1, Kind: NarrowRule, Device: "l", Rule: "r", FromMS: 5, ToMS: 5}},
		{"narrow-rule before the epoch", ToEnforcer, Tighten{ID: 1, Kind: NarrowRule, Device: "l", Rule: "r", FromMS: -5, ToMS: 5}},
		{"isolate with a rule", ToEnforcer, Tighten{ID: 1, Kind: IsolateDevice, Device: "tv", Rule: "r"}},
		{"unknown read", ToEnforcer, Read{ID: 1, What: 5, Device: "tv"}},
		{"export naming a device", ToEnforcer, Read{ID: 1, What: ReadExport, Device: "tv"}},
		{"state naming no device", ToEnforcer, Read{ID: 1, What: ReadState}},
		{"empty entry", ToEnforcer, Entry{ID: 1}},
		{"answer over the data area", ToEnforcer, Challenge{Answer: true, ID: 1, Data: make([]byte, ChallengeData+1)}},
		{"unknown result code", ToCore, Result{ID: 1, Code: Failed + 1}},
		{"alert of no kind", ToCore, Alert{Text: "x"}},
		{"empty alert", ToCore, Alert{Kind: AlertText}},
		{"alert with a newline", ToCore, Alert{Kind: AlertText, Text: "a\nb"}},
		{"alert with a C1 control", ToCore, Alert{Kind: AlertCall, Text: "a\u0085b"}},
		{"result sent by the core", ToEnforcer, Result{ID: 1}},
		{"command sent by the enforcer", ToCore, Command{ID: 1, Device: "lamp", Verb: VerbOn}},
		{"challenge sent by the core", ToEnforcer, Challenge{ID: 1}},
		{"answer sent by the enforcer", ToCore, Challenge{Answer: true, ID: 1}},
	}
	for _, r := range rows {
		if _, err := Encode(r.d, r.m); err == nil {
			t.Errorf("%s: encoded", r.name)
		}
		f := Frame{Type: r.m.Type(), Payload: r.m.put(nil)}
		if _, err := Decode(r.d, f); err == nil {
			t.Errorf("%s: decoded", r.name)
		}
	}
}

// TestRefusedBytes: frames no message encodes to are refused: trailing
// bytes, nonzero padding, a short payload, a lying or zero length, an
// unknown type and an unknown direction.
func TestRefusedBytes(t *testing.T) {
	cmd, _ := Encode(ToEnforcer, Command{ID: 1, Device: "lamp", Verb: VerbOn})
	ch, _ := Encode(ToCore, Challenge{ID: 1, Data: []byte{1}})
	pad := append([]byte{}, ch.Payload...)
	pad[len(pad)-1] = 1
	for name, f := range map[string]Frame{
		"trailing byte":    {TCommand, append(append([]byte{}, cmd.Payload...), 0)},
		"short":            {TCommand, cmd.Payload[:len(cmd.Payload)-1]},
		"nonzero padding":  {TChallenge, pad},
		"empty":            {TCommand, nil},
		"unknown type":     {0, cmd.Payload},
		"type 13":          {13, cmd.Payload},
		"overlong command": {TCommand, make([]byte, commandMax+1)},
	} {
		d := ToEnforcer
		if f.Type == TChallenge {
			d = ToCore
		}
		if _, err := Decode(d, f); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := Decode(3, cmd); !errors.Is(err, ErrDirection) {
		t.Errorf("unknown direction: %v", err)
	}
	var hdr [HeaderLen]byte
	hdr[0] = byte(TCommand)
	binary.BigEndian.PutUint32(hdr[1:], 1<<31)
	if _, err := ReadFrame(bytes.NewReader(hdr[:]), ToEnforcer); !errors.Is(err, ErrLength) {
		t.Errorf("lying length: %v", err)
	}
	binary.BigEndian.PutUint32(hdr[1:], 10)
	if _, err := ReadFrame(bytes.NewReader(hdr[:]), ToEnforcer); !errors.Is(err, ErrShort) {
		t.Errorf("truncated payload: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), ToEnforcer); err != io.EOF {
		t.Errorf("clean end: %v", err)
	}
}

// TestHello: a hello verifies only for its role, its connection's exporter
// and the pinned key.
func TestHello(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	exp := bytes.Repeat([]byte{1}, ExporterLen)
	h, err := SignHello(RoleCore, priv, exp)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(RoleCore, pub, exp); err != nil {
		t.Fatalf("honest hello: %v", err)
	}
	exp2 := bytes.Repeat([]byte{2}, ExporterLen)
	if h.Verify(RoleCore, pub, exp2) == nil {
		t.Error("hello verified on another connection")
	}
	if h.Verify(RoleEnforcer, pub, exp) == nil {
		t.Error("hello verified for the other role")
	}
	if h.Verify(RoleCore, other, exp) == nil {
		t.Error("hello verified under another pinned key")
	}
	h.Sig[0] ^= 1
	if h.Verify(RoleCore, pub, exp) == nil {
		t.Error("bent signature verified")
	}
	if _, err := SignHello(RoleCore, priv, exp[:31]); err == nil {
		t.Error("short exporter signed")
	}
}

// TestImportsStandardLibraryOnly: the package imports only the standard
// library and nothing that opens a socket, a file or a process, so both
// ends link the same small codec (brief code layout: "standard library
// only"; time only for SummaryInterval). Revert mutant: an "os" or "net"
// import in a non-test file.
func TestImportsStandardLibraryOnly(t *testing.T) {
	allowed := map[string]bool{
		"crypto/ed25519": true, "encoding/binary": true, "errors": true, "io": true, "strings": true, "time": true, "unicode": true, "unicode/utf8": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fs, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}
