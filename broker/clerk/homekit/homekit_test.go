package homekit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: DEV-1, DEV-3, DEV-4, DEV-5, DEV-10, CLK-1, A16

const host = "thermostat.local:51826"

func newHolder(t *testing.T) *MemoryKeyHolder {
	t.Helper()
	seed := make([]byte, 32)
	rand.Read(seed)
	kh, err := NewMemoryKeyHolder("5A1C0DE5-0000-4000-8000-00000000BEEF", seed)
	if err != nil {
		t.Fatal(err)
	}
	return kh
}

func pairAndVerify(t *testing.T, acc *fakeAccessory, kh KeyHolder, opt Options) (Pin, *Session, *tapConn) {
	t.Helper()
	pin, err := PairSetup(acc.connect(t), host, testCode, kh, opt)
	if err != nil {
		t.Fatalf("pair-setup: %v", err)
	}
	c := acc.connect(t)
	s, err := Verify(c, host, pin, kh, opt)
	if err != nil {
		t.Fatalf("pair-verify: %v", err)
	}
	if err := s.ConfigNumber(1); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return pin, s, c
}

func TestSRPVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/srp_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs struct {
		Vectors []map[string]string `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil || len(vs.Vectors) < 3 {
		t.Fatalf("vectors: %v", err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range vs.Vectors {
		t.Run(v["name"], func(t *testing.T) {
			a, _ := new(big.Int).SetString(v["a"], 16)
			b, _ := new(big.Int).SetString(v["b"], 16)
			salt := unhex(v["salt"])
			B, _ := srpServer(v["code"], salt, b)
			if !bytes.Equal(srpPad(B), unhex(v["B"])) {
				t.Fatal("server B differs from the vector")
			}
			r, err := srpClient(v["code"], salt, unhex(v["B"]), a)
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string][]byte{"A": r.A, "K": r.K, "M1": r.M1} {
				if !bytes.Equal(got, unhex(v[name])) {
					t.Errorf("%s differs from the vector", name)
				}
			}
			if !r.checkM2(unhex(v["M2"])) {
				t.Error("M2 differs from the vector")
			}
		})
	}
}

func TestSRPRejectsBadInput(t *testing.T) {
	salt := make([]byte, 16)
	a := big.NewInt(12345)
	for name, B := range map[string][]byte{
		"zero":     make([]byte, srpLen),
		"N":        srpPad(srpN),
		"2N":       new(big.Int).Lsh(srpN, 1).Bytes(),
		"empty":    nil,
		"too-long": make([]byte, srpLen+1),
		// Non-zero modulo N, so only the length check can refuse them.
		"too-long nonzero":      append([]byte{1}, srpPad(big.NewInt(7))...),
		"too-long leading zero": append([]byte{0}, srpPad(big.NewInt(7))...),
	} {
		if _, err := srpClient(testCode, salt, B, a); err == nil {
			t.Errorf("B %s accepted", name)
		}
	}
	if _, err := srpClient(testCode, salt[:15], srpPad(big.NewInt(7)), a); err == nil {
		t.Error("short salt accepted")
	}

	kh := newHolder(t)
	acc := newFakeAccessory(t)
	acc.badB = true
	if pin, err := PairSetup(acc.connect(t), host, testCode, kh, Options{}); err == nil || pin.Valid() {
		t.Fatalf("B mod N = 0: pin %v err %v", pin.Valid(), err)
	}
	acc = newFakeAccessory(t)
	acc.badM2 = true
	pin, err := PairSetup(acc.connect(t), host, testCode, kh, Options{})
	if !errors.Is(err, ErrAuthentication) || pin.Valid() {
		t.Fatalf("wrong server proof: pin %v err %v", pin.Valid(), err)
	}
	if len(acc.ctrls) != 0 {
		t.Fatal("controller key handed over after a wrong server proof")
	}
}

func TestPairSetupAndVerifyWithSyntheticAccessory(t *testing.T) {
	kh := newHolder(t)
	acc := newFakeAccessory(t)
	var mu sync.Mutex
	var events [][]Value
	opt := Options{OnEvent: func(v []Value) { mu.Lock(); events = append(events, v); mu.Unlock() }}
	pin, s, _ := pairAndVerify(t, acc, kh, opt)
	if pin.AccessoryID != acc.id || !bytes.Equal(pin.LTPK, acc.ltsk.Public().(ed25519.PublicKey)) {
		t.Fatal("pin is not the accessory's key")
	}
	if !bytes.Equal(acc.ctrls[kh.PairingID()], kh.PublicKey()) {
		t.Fatal("accessory did not receive the controller's public key")
	}
	cur, ok := s.Find(1, ServiceThermostat, CharCurrentTemperature)
	if !ok || cur.ID != (ID{1, 11}) {
		t.Fatalf("current temperature not resolved: %+v", cur)
	}
	if _, ok := s.Find(1, ServiceThermostat, CharCurrentHeatingCoolingState); !ok {
		t.Fatal("full-form type not normalized")
	}
	if err := s.Subscribe(cur.ID); err != nil {
		t.Fatal(err)
	}
	acc.mu.Lock()
	acc.eventsOn = true
	acc.mu.Unlock()
	vals, err := s.Read(cur.ID)
	if err != nil || len(vals) != 1 || vals[0].V != 20.5 {
		t.Fatalf("read: %v %v", vals, err)
	}
	if len(events) != 1 || events[0][0].ID != cur.ID {
		t.Fatalf("event not delivered: %v", events)
	}
	tgt, _ := s.Find(1, ServiceThermostat, CharTargetTemperature)
	if err := s.Write(tgt.ID, 21.5); err != nil {
		t.Fatal(err)
	}
	if acc.values[tgt.ID] != 21.5 {
		t.Fatalf("write not applied: %v", acc.values[tgt.ID])
	}
	// c# unchanged: no re-resolve; changed: one more /accessories.
	before := acc.accReqs
	s.ConfigNumber(1)
	s.ConfigNumber(2)
	if acc.accReqs != before+1 {
		t.Fatalf("c# change resolved %d times", acc.accReqs-before)
	}
	s.Close()
	// Reconnect: pair-verify again with the same pin.
	s2, err := Verify(acc.connect(t), host, pin, kh, Options{})
	if err != nil {
		t.Fatalf("second pair-verify: %v", err)
	}
	s2.Close()
}

func TestWrongHomeKitCodePinsNothing(t *testing.T) {
	kh := newHolder(t)
	acc := newFakeAccessory(t)
	acc.maxTries = 3
	for i := 0; i < 3; i++ {
		pin, err := PairSetup(acc.connect(t), host, "111-22-334", kh, Options{})
		if !errors.Is(err, ErrAuthentication) || pin.Valid() {
			t.Fatalf("try %d: pin %v err %v", i, pin.Valid(), err)
		}
	}
	pin, err := PairSetup(acc.connect(t), host, "111-22-334", kh, Options{})
	if !errors.Is(err, ErrMaxTries) || pin.Valid() {
		t.Fatalf("after max tries: pin %v err %v", pin.Valid(), err)
	}
	pin, err = PairSetup(acc.connect(t), host, testCode, kh, Options{})
	if !errors.Is(err, ErrMaxTries) || pin.Valid() {
		t.Fatalf("right code after max tries: pin %v err %v", pin.Valid(), err)
	}
	if acc.tries != 5 {
		t.Fatalf("accessory saw %d attempts for 5 calls: the controller retried", acc.tries)
	}
	if len(acc.ctrls) != 0 {
		t.Fatal("a controller was added")
	}
	if _, err := PairSetup(acc.connect(t), host, "1234", kh, Options{}); !errors.Is(err, ErrRefused) || acc.tries != 5 {
		t.Fatalf("malformed code reached the accessory: %v", err)
	}
}

func TestWrongAccessoryKeyIsRefused(t *testing.T) {
	kh := newHolder(t)
	acc := newFakeAccessory(t)
	pin, err := PairSetup(acc.connect(t), host, testCode, kh, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	// A slice, and every case sets both fields: "other key" proves a
	// different key under the pinned ID, so only the signature check can
	// refuse it, whatever ran before.
	for _, tc := range []struct {
		name string
		key  ed25519.PrivateKey
		id   string
	}{
		{"other key", other, acc.id},
		{"other id", acc.ltsk, "00:00:5E:00:53:99"},
		{"other key again", other, acc.id},
	} {
		name := tc.name
		acc.mu.Lock()
		acc.verifyKey, acc.verifyID = tc.key, tc.id
		acc.mu.Unlock()
		var logs []string
		s, err := Verify(acc.connect(t), host, pin, kh, Options{Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }})
		if !errors.Is(err, ErrIdentity) || s != nil {
			t.Fatalf("%s: session %v err %v", name, s, err)
		}
		if acc.sessReqs != 0 || len(acc.writes) != 0 {
			t.Fatalf("%s: %d requests reached the spoof", name, acc.sessReqs)
		}
		if len(logs) == 0 || !strings.Contains(logs[0], "does not match") {
			t.Fatalf("%s: refusal not logged: %v", name, logs)
		}
	}
}

func TestControllerKeyNeverLeaves(t *testing.T) {
	seed := []byte("homekit-canary-ctrl-key-00000000")
	kh, err := NewMemoryKeyHolder("CANARY-CTRL-0001", seed)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var out bytes.Buffer
	opt := Options{
		Logf:    func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) },
		OnEvent: func(v []Value) { fmt.Fprintf(&out, "%v %+v %#v\n", v, v, v) },
	}
	acc := newFakeAccessory(t)
	note := func(err error) {
		if err != nil {
			fmt.Fprintf(&out, "%v %+v %#v\n", err, err, err)
		}
	}
	_, err = PairSetup(acc.connect(t), host, "111-22-334", kh, opt)
	note(err)
	bad := acc.connect(t)
	_, err = PairSetup(bad, host, testCode, kh, opt)
	note(err)
	pin, s, c := pairAndVerify(t, acc, kh, opt)
	acc.eventsOn = true
	s.Subscribe(ID{1, 11})
	_, err = s.Read(ID{1, 11})
	note(err)
	note(s.Write(ID{1, 12}, 99.0))
	note(s.Write(ID{1, 12}, 22.0))
	acc.tamper = "flip"
	_, err = s.Read(ID{1, 12})
	note(err)
	acc.verifyKey, _ = func() (ed25519.PrivateKey, error) { _, k, e := ed25519.GenerateKey(rand.Reader); return k, e }()
	spoof := acc.connect(t)
	_, err = Verify(spoof, host, pin, kh, opt)
	note(err)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		fmt.Fprintf(&out, verb+"\n", kh)
		fmt.Fprintf(&out, verb+"\n", *kh)
	}
	j, _ := json.Marshal(kh)
	out.Write(j)
	out.Write(c.written.Bytes())
	out.Write(bad.written.Bytes())
	out.Write(spoof.written.Bytes())

	for _, secret := range [][]byte{seed, priv, priv[:32]} {
		for _, form := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(strings.ToUpper(hex.EncodeToString(secret))),
			[]byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)), []byte(fmt.Sprint(secret))} {
			if bytes.Contains(out.Bytes(), form) {
				t.Fatalf("controller key canary found in output")
			}
		}
	}
	if out.Len() < 1000 {
		t.Fatalf("too little output captured (%d bytes) for the check to mean anything", out.Len())
	}
}

func TestThermostatClasses(t *testing.T) {
	b := Bounds{Min: 16, Max: 26, Confirmed: true}
	for _, r := range ThermostatRows {
		if r.Read != key.Read {
			t.Errorf("%s read is %s", r.Name, r.Read)
		}
	}
	for _, c := range []string{CharTargetTemperature, CharCoolingThreshold, CharHeatingThreshold} {
		r := ClassFor(ServiceThermostat, c)
		if r.WriteVerb(21, b) != key.Actuate || r.Inverse != PriorValue {
			t.Errorf("%s in bounds: %s inverse %q", r.Name, r.WriteVerb(21, b), r.Inverse)
		}
		for _, v := range []float64{15.5, 26.5, 5, 38} {
			if r.WriteVerb(v, b) != key.ActuatePhysical {
				t.Errorf("%s %v outside bounds: %s", r.Name, v, r.WriteVerb(v, b))
			}
		}
		if r.WriteVerb(21, Bounds{Min: 16, Max: 26}) != key.ActuatePhysical {
			t.Errorf("%s with unconfirmed bounds is not actuate-physical", r.Name)
		}
	}
	// Every non-setpoint row is checked with each value both inside
	// confirmed bounds that contain it and outside them, so an in-bounds
	// verb on the row cannot pass unseen.
	mode := ClassFor(ServiceThermostat, CharTargetHeatingCoolingState)
	if mode.Inverse != NoInverse {
		t.Errorf("target heating/cooling state has inverse %q", mode.Inverse)
	}
	for v := 0.0; v <= 3; v++ { // off, heat, cool, auto
		for _, mb := range []Bounds{{Min: 0, Max: 3, Confirmed: true}, {Min: v, Max: v, Confirmed: true}, b} {
			if got := mode.WriteVerb(v, mb); got != key.ActuatePhysical {
				t.Errorf("target heating/cooling state %v under %+v: %s", v, mb, got)
			}
		}
	}
	units := ClassFor(ServiceThermostat, CharTemperatureDisplayUnits)
	for v := 0.0; v <= 1; v++ {
		for _, ub := range []Bounds{{Min: 0, Max: 1, Confirmed: true}, b} {
			if got := units.WriteVerb(v, ub); got != key.ChangeAccount {
				t.Errorf("display units %v under %+v: %s", v, ub, got)
			}
		}
	}
	for _, c := range []string{CharCurrentTemperature, CharCurrentHeatingCoolingState, "10", "ABCD"} {
		r := ClassFor(ServiceThermostat, c)
		for _, v := range []float64{21, 1, 40} {
			if r.Read != key.Read || r.WriteVerb(v, b) != key.ActuatePhysical ||
				r.WriteVerb(v, Bounds{Min: v, Max: v, Confirmed: true}) != key.ActuatePhysical {
				t.Errorf("%s %v: read %s write %s", c, v, r.Read, r.WriteVerb(v, b))
			}
		}
	}
	for _, v := range []float64{1, 21} {
		r := ClassFor("43", "25")
		if r.Read != key.Read || r.WriteVerb(v, b) != key.ActuatePhysical ||
			r.WriteVerb(v, Bounds{Min: v, Max: v, Confirmed: true}) != key.ActuatePhysical {
			t.Errorf("unmapped service is not conservative at %v", v)
		}
	}
	if AdminRows["remove-pairing"] != key.DeleteRemote || AdminRows["add-pairing"] != key.RevealOrCreateSecret {
		t.Error("admin rows")
	}
}

func TestOnlyDeclaredWrites(t *testing.T) {
	acc := newFakeAccessory(t)
	_, s, c := pairAndVerify(t, acc, newHolder(t), Options{})
	tgt, _ := s.Find(1, ServiceThermostat, CharTargetTemperature)
	mode, _ := s.Find(1, ServiceThermostat, CharTargetHeatingCoolingState)
	cur, _ := s.Find(1, ServiceThermostat, CharCurrentTemperature)
	for name, w := range map[string]struct {
		id ID
		v  any
	}{
		"undeclared iid":  {ID{1, 99}, 1.0},
		"undeclared aid":  {ID{2, 12}, 21.0},
		"read-only":       {cur.ID, 20.0},
		"name":            {ID{1, 2}, 1.0},
		"above max":       {tgt.ID, 38.5},
		"below min":       {tgt.ID, 9.5},
		"off step":        {tgt.ID, 21.25},
		"nan":             {tgt.ID, math.NaN()},
		"inf":             {tgt.ID, math.Inf(1)},
		"string":          {tgt.ID, "21"},
		"bool on float":   {tgt.ID, true},
		"mode 4":          {mode.ID, 4},
		"mode fractional": {mode.ID, 1.5},
		"mode negative":   {mode.ID, -1},
	} {
		before := c.n()
		if err := s.Write(w.id, w.v); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
		if c.n() != before {
			t.Errorf("%s: %d bytes written before the refusal", name, c.n()-before)
		}
	}
	if len(acc.writes) != 0 {
		t.Fatalf("accessory saw writes: %v", acc.writes)
	}
	if _, err := s.Read(ID{1, 99}); !errors.Is(err, ErrRefused) {
		t.Errorf("undeclared read: %v", err)
	}
	if err := s.Write(mode.ID, 2); err != nil {
		t.Fatalf("declared write refused: %v", err)
	}
	if len(acc.writes) != 1 || !strings.Contains(acc.writes[0], `"value":2`) {
		t.Fatalf("framed write: %v", acc.writes)
	}
}

func TestTamperedOrReplayedFrameIsRefused(t *testing.T) {
	for _, mode := range []string{"flip", "replay"} {
		t.Run(mode, func(t *testing.T) {
			acc := newFakeAccessory(t)
			_, s, _ := pairAndVerify(t, acc, newHolder(t), Options{})
			if _, err := s.Read(ID{1, 11}); err != nil {
				t.Fatal(err)
			}
			acc.mu.Lock()
			acc.tamper = mode
			acc.mu.Unlock()
			if _, err := s.Read(ID{1, 11}); !errors.Is(err, ErrProtocol) {
				t.Fatalf("tampered frame: %v", err)
			}
			if _, err := s.Read(ID{1, 11}); !errors.Is(err, ErrClosed) {
				t.Fatalf("session continued: %v", err)
			}
			if err := s.Write(ID{1, 12}, 21.0); !errors.Is(err, ErrClosed) {
				t.Fatalf("session accepted a write: %v", err)
			}
		})
	}
	// The same at the codec: a replayed frame fails at the next counter.
	key := make([]byte, 32)
	wc, _ := newFrameCipher(key)
	var wire bytes.Buffer
	(&frameWriter{w: &wire, c: wc}).Write([]byte("hello"))
	frame := append([]byte(nil), wire.Bytes()...)
	rc, _ := newFrameCipher(key)
	fr := &frameReader{r: bytes.NewReader(append(frame, frame...)), c: rc}
	buf := make([]byte, 16)
	if n, err := fr.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first frame: %q %v", buf[:n], err)
	}
	if _, err := fr.Read(buf); !errors.Is(err, ErrProtocol) {
		t.Fatalf("replayed frame: %v", err)
	}
	if _, err := fr.Read(buf); !errors.Is(err, ErrProtocol) {
		t.Fatal("frame reader recovered after a failure")
	}
}

// REQ: KRN-2
func TestCheckPathDoesNotLinkHomeKit(t *testing.T) {
	const pkg = "github.com/ghbmrk/agentos/broker/clerk/homekit"
	for _, p := range []string{"..", "../../kernel", "../../kernel/key"} {
		out, err := exec.Command("go", "list", "-deps", p).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", p, err, out)
		}
		if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/kernel/key") {
			t.Fatalf("go list %s returned no kernel deps; the check proves nothing", p)
		}
		for _, d := range strings.Fields(string(out)) {
			if strings.HasPrefix(d, pkg) {
				t.Errorf("%s links %s", p, d)
			}
		}
	}
}

func TestTLV8Fragments(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 600)
	enc := encodeTLV(tb(tlvState, 2), tv(tlvPublicKey, long), tv(tlvSalt, nil))
	m, err := decodeTLV(enc)
	if err != nil || !bytes.Equal(m[tlvPublicKey], long) || m[tlvState][0] != 2 || m[tlvSalt] == nil {
		t.Fatalf("round trip: %v", err)
	}
	for name, b := range map[string][]byte{
		"truncated": {6, 3, 1},
		"duplicate": {6, 1, 1, 7, 1, 1, 6, 1, 2},
		"huge":      make([]byte, maxTLVInput+1),
	} {
		if _, err := decodeTLV(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
