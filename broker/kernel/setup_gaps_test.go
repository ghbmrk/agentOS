package kernel_test

// REQ: KEY-4, LOG-2, D-146

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// sealFirst is a log's first frame as the log writes it: its length, then a
// nonce and the entry sealed under logKey with seq 1 as associated data.
func sealFirst(t *testing.T, logKey [32]byte, e kernel.Entry) []byte {
	t.Helper()
	b, err := aes.NewCipher(logKey[:])
	must(t, err)
	a, err := cipher.NewGCM(b)
	must(t, err)
	nonce := make([]byte, a.NonceSize())
	nonce[0] = 7
	fr := a.Seal(nonce, nonce, mustJSON(t, e), binary.BigEndian.AppendUint64(nil, 1))
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(fr))), fr...)
}

// Each hardware key signs the box's head key and every anchor, in order,
// each after its length, so a signature binds the whole set as the owner
// gave it. Fails if an anchor is left out of the signed message.
func TestSetupMsgBindsEveryAnchorInOrder(t *testing.T) {
	box, a, b := gen(3).pub, gen(1).pk, gen(12).pk
	want := append([]byte(kernel.DomainSetup), box...)
	for _, p := range []key.PublicKey{a, b} {
		e := p.Encode()
		want = append(binary.BigEndian.AppendUint16(want, uint16(len(e))), e...)
	}
	if got := kernel.SetupMsg(box, []key.PublicKey{a, b}); !bytes.Equal(got, want) {
		t.Fatalf("SetupMsg = %x, want %x", got, want)
	}
	if bytes.Equal(kernel.SetupMsg(box, []key.PublicKey{a, b}), kernel.SetupMsg(box, []key.PublicKey{b, a})) {
		t.Fatal("the anchors' order is not signed")
	}
}

// The first frame's length is read before anything opens: under four bytes
// there is no frame yet; a length below a sealed frame's least or above
// MaxSetupFrame is corrupt; a length the bytes do not yet hold is a torn
// frame, not a corrupt one. Fails if a bound moves by one.
func TestLoggedAnchorsReadsTheFirstFramesLengthExactly(t *testing.T) {
	box := gen(3).pub
	least := 12 + 16 // GCM's nonce and tag
	for name, c := range map[string]struct {
		raw     []byte
		corrupt bool
	}{
		"three bytes":         {[]byte{0, 0, 0}, false},
		"a zero length":       {[]byte{0, 0, 0, 0}, true},
		"one below the least": {binary.BigEndian.AppendUint32(nil, uint32(least-1)), true},
		"the least, torn":     {binary.BigEndian.AppendUint32(nil, uint32(least)), false},
		"MaxSetupFrame, torn": {binary.BigEndian.AppendUint32(nil, kernel.MaxSetupFrame), false},
		"past MaxSetupFrame":  {binary.BigEndian.AppendUint32(nil, kernel.MaxSetupFrame+1), true},
	} {
		raw := c.raw[:len(c.raw):len(c.raw)]
		a, ok, err := kernel.LoggedAnchors(raw, logKey, box)
		if ok || a != nil || errors.Is(err, kernel.ErrCorrupt) != c.corrupt || (!c.corrupt && err != nil) {
			t.Errorf("%s: %v, %v, %v; corrupt %v", name, a, ok, err, c.corrupt)
		}
	}
}

// A first frame that opens under the log key still gives no anchors unless
// it is the setup entry, first, with the owner's two keys each signing the
// set in its order. Fails if any of those checks is skipped.
func TestLoggedAnchorsReadsOnlyAWholeSetupEntry(t *testing.T) {
	box, owner, spare := gen(3).pub, gen(1), gen(12)
	f := kernel.SignSetup(box, owner.pass, spare.pass)
	entry := func(body []byte) kernel.Entry {
		return kernel.Entry{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: body}
	}
	good := sealFirst(t, logKey, entry(mustJSON(t, f)))
	if a, ok, err := kernel.LoggedAnchors(good, logKey, box); err != nil || !ok || len(a) != 2 || a[0] != owner.pk || a[1] != spare.pk {
		t.Fatalf("a sealed setup entry: %v, %v, %v", a, ok, err)
	}
	prev := entry(mustJSON(t, f))
	prev.Prev[0] = 1
	reordered := kernel.FirstAnchors{Anchors: []key.PublicKey{f.Anchors[1], f.Anchors[0]}, Sigs: [][]byte{f.Sigs[1], f.Sigs[0]}}
	for name, e := range map[string]kernel.Entry{
		"a previous hash":    prev,
		"one key":            entry(mustJSON(t, kernel.SignSetup(box, owner.pass))),
		"a second sig fewer": entry(mustJSON(t, kernel.FirstAnchors{Anchors: f.Anchors, Sigs: f.Sigs[:1]})),
		"keys reordered":     entry(mustJSON(t, reordered)),
		"sigs not a list":    entry(mustJSON(t, map[string]any{"anchors": f.Anchors, "sigs": "x"})),
	} {
		if a, ok, err := kernel.LoggedAnchors(sealFirst(t, logKey, e), logKey, box); ok || a != nil || !errors.Is(err, kernel.ErrCorrupt) {
			t.Errorf("%s: %v, %v, %v; want ErrCorrupt", name, a, ok, err)
		}
	}
}

// A setup entry whose body does not decode is corrupt, even where the part
// that did decode names two good keys. Fails if the fold takes the anchors
// a broken body left behind.
func TestASetupBodyThatDoesNotDecodeIsCorrupt(t *testing.T) {
	f := kernel.SignSetup(gen(3).pub, gen(1).pass, gen(12).pass)
	e := kernel.Entry{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: mustJSON(t, map[string]any{"anchors": f.Anchors, "sigs": "x"})}
	if st, err := kernel.Replay(nil, []kernel.Entry{e}); st != nil || !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("a setup body that does not decode: %v, %v; want ErrCorrupt", st, err)
	}
}
