package homekit

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const pairingTLV = "application/pairing+tlv8"

// Options are the session's hooks. Logf receives no key material: lines
// name the step and the accessory ID only. OnEvent runs after the session
// call that received the event has released the session. Timeout, when
// set and the connection takes deadlines, bounds each request's round trip.
type Options struct {
	Logf    func(format string, args ...any)
	OnEvent func([]Value)
	Timeout time.Duration
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

func checkHost(host string) error {
	if host == "" || len(host) > 255 || strings.ContainsAny(host, "\r\n \t/") {
		return fmt.Errorf("%w: bad host", ErrRefused)
	}
	return nil
}

// pairExchange posts one TLV8 message and returns the decoded answer after
// checking its state; an accessory error item becomes its error.
func pairExchange(w io.Writer, br *bufio.Reader, host, path string, wantState byte, items ...tlvItem) (tlvMap, error) {
	if err := writeRequest(w, "POST", path, host, pairingTLV, encodeTLV(items...)); err != nil {
		return nil, err
	}
	r, err := readResponse(br)
	if err != nil {
		return nil, err
	}
	if r.event || r.status != 200 {
		return nil, fmt.Errorf("%w: %s answered status %d", ErrProtocol, path, r.status)
	}
	if len(r.body) > maxTLVInput {
		return nil, fmt.Errorf("%w: pairing body of %d bytes", ErrProtocol, len(r.body))
	}
	m, err := decodeTLV(r.body)
	if err != nil {
		return nil, err
	}
	if st := m[tlvState]; len(st) != 1 || st[0] != wantState {
		return nil, fmt.Errorf("%w: %s expected state %d", ErrProtocol, path, wantState)
	}
	if e, ok := m[tlvError]; ok {
		return nil, accessoryError(e)
	}
	return m, nil
}

func randScalar(n int) *big.Int {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// PairSetup runs pair-setup (M1 to M6) over conn with the accessory's
// HomeKit code and returns the pin. It makes one attempt: on any failure it
// returns the zero Pin and never retries, so an accessory counting tries
// sees exactly the attempts the owner made.
func PairSetup(conn io.ReadWriter, host, code string, kh KeyHolder, opt Options) (Pin, error) {
	pin, err := pairSetup(conn, host, code, kh)
	if err != nil {
		opt.logf("homekit: pair-setup with %s failed: %v", host, err)
		return Pin{}, err
	}
	opt.logf("homekit: pair-setup with %s pinned accessory %s", host, pin.AccessoryID)
	return pin, nil
}

func pairSetup(conn io.ReadWriter, host, code string, kh KeyHolder) (Pin, error) {
	if err := checkHost(host); err != nil {
		return Pin{}, err
	}
	code, err := normalizeCode(code)
	if err != nil {
		return Pin{}, err
	}
	ctrlID, ctrlPK := kh.PairingID(), kh.PublicKey()
	if checkPairingID(ctrlID) != nil || len(ctrlPK) != ed25519.PublicKeySize {
		return Pin{}, fmt.Errorf("%w: key holder", ErrRefused)
	}
	br := bufio.NewReaderSize(conn, readBufSize)

	m2, err := pairExchange(conn, br, host, "/pair-setup", 2, tb(tlvState, 1), tb(tlvMethod, 0))
	if err != nil {
		return Pin{}, err
	}
	srp, err := srpClient(code, m2[tlvSalt], m2[tlvPublicKey], randScalar(32))
	if err != nil {
		return Pin{}, err
	}
	m4, err := pairExchange(conn, br, host, "/pair-setup", 4, tb(tlvState, 3), tv(tlvPublicKey, srp.A), tv(tlvProof, srp.M1))
	if err != nil {
		return Pin{}, err
	}
	if !srp.checkM2(m4[tlvProof]) {
		return Pin{}, fmt.Errorf("%w: accessory proof", ErrAuthentication)
	}

	encKey := hkdfKey(srp.K, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	ctrlX := hkdfKey(srp.K, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	sig, err := kh.Sign(catBytes(ctrlX, []byte(ctrlID), ctrlPK))
	if err != nil {
		return Pin{}, fmt.Errorf("%w: key holder could not sign", ErrRefused)
	}
	sub := encodeTLV(ts(tlvIdentifier, ctrlID), tv(tlvPublicKey, ctrlPK), tv(tlvSignature, sig))
	m6, err := pairExchange(conn, br, host, "/pair-setup", 6, tb(tlvState, 5), tv(tlvEncryptedData, sealMsg(encKey, "PS-Msg05", sub)))
	if err != nil {
		return Pin{}, err
	}
	plain, err := openMsg(encKey, "PS-Msg06", m6[tlvEncryptedData])
	if err != nil {
		return Pin{}, err
	}
	acc, err := decodeTLV(plain)
	if err != nil {
		return Pin{}, err
	}
	pin := Pin{AccessoryID: string(acc[tlvIdentifier]), LTPK: ed25519.PublicKey(acc[tlvPublicKey])}
	if !pin.Valid() {
		return Pin{}, fmt.Errorf("%w: accessory identity item", ErrProtocol)
	}
	accX := hkdfKey(srp.K, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	if !ed25519.Verify(pin.LTPK, catBytes(accX, []byte(pin.AccessoryID), pin.LTPK), acc[tlvSignature]) {
		return Pin{}, fmt.Errorf("%w: accessory signature at pair-setup", ErrAuthentication)
	}
	return pin, nil
}

// Verify runs pair-verify over conn against the pinned key and, when the
// accessory proves it, returns the encrypted session. A different key or
// ID is ErrIdentity; nothing is read or written on the accessory then.
func Verify(conn io.ReadWriter, host string, pin Pin, kh KeyHolder, opt Options) (*Session, error) {
	s, err := verify(conn, host, pin, kh, opt)
	if err != nil {
		opt.logf("homekit: pair-verify with %s for accessory %s failed: %v", host, pin.AccessoryID, err)
		if c, ok := conn.(io.Closer); ok {
			c.Close()
		}
		return nil, err
	}
	return s, nil
}

func verify(conn io.ReadWriter, host string, pin Pin, kh KeyHolder, opt Options) (*Session, error) {
	if err := checkHost(host); err != nil {
		return nil, err
	}
	if !pin.Valid() {
		return nil, fmt.Errorf("%w: no valid pin", ErrRefused)
	}
	ctrlID := kh.PairingID()
	if checkPairingID(ctrlID) != nil {
		return nil, fmt.Errorf("%w: key holder", ErrRefused)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	br := bufio.NewReaderSize(conn, readBufSize)

	m2, err := pairExchange(conn, br, host, "/pair-verify", 2, tb(tlvState, 1), tv(tlvPublicKey, ephPub))
	if err != nil {
		return nil, err
	}
	accEphB := m2[tlvPublicKey]
	accEph, err := ecdh.X25519().NewPublicKey(accEphB)
	if err != nil {
		return nil, fmt.Errorf("%w: accessory ephemeral key", ErrProtocol)
	}
	shared, err := eph.ECDH(accEph)
	if err != nil {
		return nil, fmt.Errorf("%w: accessory ephemeral key", ErrProtocol)
	}
	key := hkdfKey(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	plain, err := openMsg(key, "PV-Msg02", m2[tlvEncryptedData])
	if err != nil {
		return nil, err
	}
	acc, err := decodeTLV(plain)
	if err != nil {
		return nil, err
	}
	if string(acc[tlvIdentifier]) != pin.AccessoryID ||
		!ed25519.Verify(pin.LTPK, catBytes(accEphB, acc[tlvIdentifier], ephPub), acc[tlvSignature]) {
		return nil, ErrIdentity
	}
	sig, err := kh.Sign(catBytes(ephPub, []byte(ctrlID), accEphB))
	if err != nil {
		return nil, fmt.Errorf("%w: key holder could not sign", ErrRefused)
	}
	sub := encodeTLV(ts(tlvIdentifier, ctrlID), tv(tlvSignature, sig))
	if _, err := pairExchange(conn, br, host, "/pair-verify", 4, tb(tlvState, 3), tv(tlvEncryptedData, sealMsg(key, "PV-Msg03", sub))); err != nil {
		return nil, err
	}
	if br.Buffered() != 0 {
		return nil, fmt.Errorf("%w: bytes after pair-verify", ErrProtocol)
	}
	return newSession(conn, host, shared, opt)
}
