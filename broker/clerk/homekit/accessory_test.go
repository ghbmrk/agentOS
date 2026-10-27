package homekit

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// fakeAccessory is a minimal synthetic HAP accessory built on this package's
// own codec (TLV8, frames) and an SRP server written here. It serves a
// generic HomeKit thermostat profile. All keys are generated per
// test; the setup code is the canary 111-22-333 and the accessory ID sits
// in the RFC 7042 documentation range.
type fakeAccessory struct {
	mu        sync.Mutex
	code      string
	id        string
	ltsk      ed25519.PrivateKey // the key pair-setup hands over
	verifyKey ed25519.PrivateKey // the key pair-verify proves (a spoof when it differs)
	verifyID  string
	maxTries  int
	tries     int // pair-setup attempts (M1 received)
	failed    int
	ctrls     map[string]ed25519.PublicKey
	badB      bool
	badM2     bool
	tamper    string // "flip" or "replay": applied to the next session response
	eventsOn  bool   // send one EVENT before each characteristics response
	values    map[ID]any
	subs      map[ID]bool
	sessReqs  int
	accReqs   int
	writes    []string
	vs        verifyState
	// Hostile modes (all synthetic): the state of the pair-setup M2 reply,
	// the identifier, key and signing key of M6, and bytes sent after the
	// pair-verify M4 reply in the same write.
	setupState  byte
	m6ID        string
	m6LTPK      []byte
	m6SignKey   ed25519.PrivateKey
	afterVerify []byte
}

const testCode = "111-22-333"

func newFakeAccessory(t *testing.T) *fakeAccessory {
	t.Helper()
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAccessory{
		code: testCode, id: "00:00:5E:00:53:01", ltsk: sk, verifyKey: sk, verifyID: "00:00:5E:00:53:01",
		maxTries: 100, ctrls: map[string]ed25519.PublicKey{}, subs: map[ID]bool{},
		values: map[ID]any{
			{1, 9}: 1.0, {1, 10}: 1.0, {1, 11}: 20.5, {1, 12}: 21.0, {1, 13}: 0.0, {1, 14}: 25.0, {1, 15}: 18.0,
		},
	}
}

const thermostatJSON = `{"accessories":[{"aid":1,"services":[
 {"iid":1,"type":"0000003E-0000-1000-8000-0026BB765291","characteristics":[
  {"iid":2,"type":"23","perms":["pr"],"format":"string","value":"Thermostat"}]},
 {"iid":8,"type":"4A","characteristics":[
  {"iid":9,"type":"0000000F-0000-1000-8000-0026BB765291","perms":["pr","ev"],"format":"uint8","minValue":0,"maxValue":2},
  {"iid":10,"type":"33","perms":["pr","pw","ev"],"format":"uint8","minValue":0,"maxValue":3,"valid-values":[0,1,2,3]},
  {"iid":11,"type":"11","perms":["pr","ev"],"format":"float","minValue":0,"maxValue":100,"minStep":0.1},
  {"iid":12,"type":"35","perms":["pr","pw","ev"],"format":"float","minValue":10,"maxValue":38,"minStep":0.5},
  {"iid":13,"type":"36","perms":["pr","pw","ev"],"format":"uint8","minValue":0,"maxValue":1},
  {"iid":14,"type":"0D","perms":["pr","pw","ev"],"format":"float","minValue":10,"maxValue":35,"minStep":0.5},
  {"iid":15,"type":"12","perms":["pr","pw","ev"],"format":"float","minValue":0,"maxValue":25,"minStep":0.5}]}]}]}`

// connect starts a connection to the accessory; tap records what the
// controller writes.
func (a *fakeAccessory) connect(t *testing.T) *tapConn {
	c, s := net.Pipe()
	go a.serve(s)
	t.Cleanup(func() { c.Close(); s.Close() })
	return &tapConn{Conn: c}
}

type tapConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *tapConn) n() int { c.mu.Lock(); defer c.mu.Unlock(); return c.written.Len() }

func writeResp(w io.Writer, status int, ctype string, body []byte) error {
	var b bytes.Buffer
	if status == 204 {
		b.WriteString("HTTP/1.1 204 No Content\r\n\r\n")
	} else {
		fmt.Fprintf(&b, "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", status, ctype, len(body))
		b.Write(body)
	}
	_, err := w.Write(b.Bytes())
	return err
}

func tlvResp(w io.Writer, items ...tlvItem) error {
	return writeResp(w, 200, pairingTLV, encodeTLV(items...))
}

type srpServerState struct {
	salt []byte
	b, B *big.Int
	v    *big.Int
	K    []byte
}

// srpServer computes the accessory's B = k*v + g^b.
func srpServer(code string, salt []byte, b *big.Int) (B, v *big.Int) {
	x := new(big.Int).SetBytes(srpHash(salt, srpHash(srpUser, []byte(":"), []byte(code))))
	v = new(big.Int).Exp(srpG, x, srpN)
	B = new(big.Int).Mul(srpK, v)
	B.Add(B, new(big.Int).Exp(srpG, b, srpN)).Mod(B, srpN)
	return B, v
}

func (a *fakeAccessory) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	var srp srpServerState
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		m, err := decodeTLV(body)
		if err != nil {
			return
		}
		a.mu.Lock()
		var shared []byte
		switch req.URL.Path {
		case "/pair-setup":
			err = a.pairSetup(conn, m, &srp)
		case "/pair-verify":
			shared, err = a.pairVerify(conn, m)
		default:
			err = writeResp(conn, 470, "application/hap+json", []byte(`{"status":-70401}`))
		}
		a.mu.Unlock()
		if err != nil {
			return
		}
		if shared != nil {
			a.session(conn, shared)
			return
		}
	}
}

func (a *fakeAccessory) pairSetup(w io.Writer, m tlvMap, st *srpServerState) error {
	switch m[tlvState][0] {
	case 1:
		a.tries++
		if a.failed >= a.maxTries {
			return tlvResp(w, tb(tlvState, 2), tb(tlvError, 5))
		}
		st.salt = make([]byte, 16)
		rand.Read(st.salt)
		st.b = randScalar(32)
		st.B, st.v = srpServer(a.code, st.salt, st.b)
		bb := srpPad(st.B)
		if a.badB {
			bb = srpPad(srpN)
		}
		state := byte(2)
		if a.setupState != 0 {
			state = a.setupState
		}
		return tlvResp(w, tb(tlvState, state), tv(tlvSalt, st.salt), tv(tlvPublicKey, bb))
	case 3:
		A := new(big.Int).SetBytes(m[tlvPublicKey])
		pA, pB := srpPad(A), srpPad(st.B)
		u := new(big.Int).SetBytes(srpHash(pA, pB))
		S := new(big.Int).Exp(st.v, u, srpN)
		S.Mul(S, A).Mod(S, srpN).Exp(S, st.b, srpN)
		st.K = srpHash(srpPad(S))
		M1 := srpHash(srpHGroup, srpHash(srpUser), st.salt, pA, pB, st.K)
		if !bytes.Equal(M1, m[tlvProof]) {
			a.failed++
			return tlvResp(w, tb(tlvState, 4), tb(tlvError, 2))
		}
		M2 := srpHash(pA, M1, st.K)
		if a.badM2 {
			M2[0] ^= 1
		}
		return tlvResp(w, tb(tlvState, 4), tv(tlvProof, M2))
	case 5:
		encKey := hkdfKey(st.K, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
		plain, err := openMsg(encKey, "PS-Msg05", m[tlvEncryptedData])
		if err != nil {
			return tlvResp(w, tb(tlvState, 6), tb(tlvError, 2))
		}
		c, _ := decodeTLV(plain)
		cx := hkdfKey(st.K, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
		pk := ed25519.PublicKey(c[tlvPublicKey])
		if len(pk) != 32 || !ed25519.Verify(pk, catBytes(cx, c[tlvIdentifier], pk), c[tlvSignature]) {
			return tlvResp(w, tb(tlvState, 6), tb(tlvError, 2))
		}
		a.ctrls[string(c[tlvIdentifier])] = pk
		ax := hkdfKey(st.K, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
		id, ltpk, sk := a.id, []byte(a.ltsk.Public().(ed25519.PublicKey)), a.ltsk
		if a.m6ID != "" {
			id = a.m6ID
		}
		if a.m6LTPK != nil {
			ltpk = a.m6LTPK
		}
		if a.m6SignKey != nil {
			sk = a.m6SignKey
		}
		sig := ed25519.Sign(sk, catBytes(ax, []byte(id), ltpk))
		sub := encodeTLV(ts(tlvIdentifier, id), tv(tlvPublicKey, ltpk), tv(tlvSignature, sig))
		return tlvResp(w, tb(tlvState, 6), tv(tlvEncryptedData, sealMsg(encKey, "PS-Msg06", sub)))
	}
	return fmt.Errorf("bad state")
}

type verifyState struct {
	eph    *ecdh.PrivateKey
	ctrl   []byte
	shared []byte
}

func (a *fakeAccessory) pairVerify(w io.Writer, m tlvMap) ([]byte, error) {
	switch m[tlvState][0] {
	case 1:
		eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
		cpub, err := ecdh.X25519().NewPublicKey(m[tlvPublicKey])
		if err != nil {
			return nil, err
		}
		shared, _ := eph.ECDH(cpub)
		key := hkdfKey(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		ae := eph.PublicKey().Bytes()
		sig := ed25519.Sign(a.verifyKey, catBytes(ae, []byte(a.verifyID), m[tlvPublicKey]))
		sub := encodeTLV(ts(tlvIdentifier, a.verifyID), tv(tlvSignature, sig))
		a.vs = verifyState{eph, m[tlvPublicKey], shared}
		return nil, tlvResp(w, tb(tlvState, 2), tv(tlvPublicKey, ae), tv(tlvEncryptedData, sealMsg(key, "PV-Msg02", sub)))
	case 3:
		vs := a.vs
		key := hkdfKey(vs.shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		plain, err := openMsg(key, "PV-Msg03", m[tlvEncryptedData])
		if err != nil {
			return nil, tlvResp(w, tb(tlvState, 4), tb(tlvError, 2))
		}
		c, _ := decodeTLV(plain)
		pk := a.ctrls[string(c[tlvIdentifier])]
		if pk == nil || !ed25519.Verify(pk, catBytes(vs.ctrl, c[tlvIdentifier], vs.eph.PublicKey().Bytes()), c[tlvSignature]) {
			return nil, tlvResp(w, tb(tlvState, 4), tb(tlvError, 2))
		}
		var b bytes.Buffer
		tlvResp(&b, tb(tlvState, 4))
		b.Write(a.afterVerify) // one write, so the bytes arrive with M4
		_, err = w.Write(b.Bytes())
		return vs.shared, err
	}
	return nil, fmt.Errorf("bad state")
}

// tamperWriter alters the accessory's next encrypted response.
type tamperWriter struct {
	a    *fakeAccessory
	w    io.Writer
	last []byte
}

func (t *tamperWriter) Write(p []byte) (int, error) {
	q := append([]byte(nil), p...)
	switch t.a.tamper {
	case "flip":
		q[len(q)/2] ^= 0x40
		t.a.tamper = ""
	case "replay":
		if t.last != nil {
			q = t.last
			t.a.tamper = ""
		}
	}
	t.last = append([]byte(nil), p...)
	_, err := t.w.Write(q)
	return len(p), err
}

func (a *fakeAccessory) session(conn net.Conn, shared []byte) {
	rc, _ := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Write-Encryption-Key"))
	wc, _ := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Read-Encryption-Key"))
	br := bufio.NewReader(&frameReader{r: conn, c: rc})
	fw := &frameWriter{w: &tamperWriter{a: a, w: conn}, c: wc}
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		a.mu.Lock()
		a.sessReqs++
		err = a.handle(fw, req, body)
		a.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (a *fakeAccessory) valuesJSON(ids []ID) []byte {
	type cv struct {
		AID   uint64 `json:"aid"`
		IID   uint64 `json:"iid"`
		Value any    `json:"value"`
	}
	var out []cv
	for _, id := range ids {
		out = append(out, cv{id.AID, id.IID, a.values[id]})
	}
	b, _ := json.Marshal(map[string]any{"characteristics": out})
	return b
}

func (a *fakeAccessory) handle(w io.Writer, req *http.Request, body []byte) error {
	const hj = "application/hap+json"
	switch {
	case req.Method == "GET" && req.URL.Path == "/accessories":
		a.accReqs++
		return writeResp(w, 200, hj, []byte(thermostatJSON))
	case req.Method == "GET" && req.URL.Path == "/characteristics":
		var ids []ID
		for _, s := range strings.Split(req.URL.Query().Get("id"), ",") {
			var id ID
			fmt.Sscanf(s, "%d.%d", &id.AID, &id.IID)
			ids = append(ids, id)
		}
		if a.eventsOn {
			ev := a.valuesJSON([]ID{{1, 11}})
			if _, err := fmt.Fprintf(w, "EVENT/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", hj, len(ev), ev); err != nil {
				return err
			}
		}
		return writeResp(w, 200, hj, a.valuesJSON(ids))
	case req.Method == "PUT" && req.URL.Path == "/characteristics":
		a.writes = append(a.writes, string(body))
		var doc struct {
			C []struct {
				AID, IID uint64
				Value    any
				Ev       *bool
			} `json:"characteristics"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return writeResp(w, 400, hj, []byte(`{}`))
		}
		for _, c := range doc.C {
			if c.Ev != nil {
				a.subs[ID{c.AID, c.IID}] = *c.Ev
			} else {
				a.values[ID{c.AID, c.IID}] = c.Value
			}
		}
		return writeResp(w, 204, "", nil)
	}
	return writeResp(w, 404, hj, []byte(`{}`))
}
