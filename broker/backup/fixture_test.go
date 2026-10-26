package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Synthetic canaries only: none of these is a real key.
var (
	rk1          = []byte("canary-recovery-k-01") // 20 bytes, as on the card
	rk2          = []byte("canary-recovery-k-02")
	logKeyCanary = [32]byte{0x4c, 0x4f, 0x47, 0x4b, 0x45, 0x59, 0xca, 0x4e, 0xa7, 0x01, 0x4c, 0x4f, 0x47, 0x4b, 0x45, 0x59,
		0xca, 0x4e, 0xa7, 0x01, 0x4c, 0x4f, 0x47, 0x4b, 0x45, 0x59, 0xca, 0x4e, 0xa7, 0x01, 0x4c, 0x4f}
	holderKeyCanary = []byte("HOLDER-KEY-CANARY-7f3a9e1d")
)

var errDown = errors.New("down")

// flakyKeys is a key table whose Delete can be made to fail.
type flakyKeys struct {
	*kernel.MemKeys
	failDelete bool
}

func (f *flakyKeys) Delete(s string) error {
	if f.failDelete {
		return errDown
	}
	return f.MemKeys.Delete(s)
}

// rig is a real kernel on an in-memory log, key table and one content
// store, "mail".
type rig struct {
	t      *testing.T
	log    *kernel.MemStore
	anchor *kernel.MemAnchor
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	rnd    *rand.ChaCha8
	keys   *flakyKeys
	mail   *kernel.MemContent
	k      *kernel.Kernel
	// holder stands for a key the holder process keeps: it is in the
	// fixture and must never reach a backup.
	holder []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	priv := ed25519.NewKeyFromSeed(seed)
	r := &rig{t: t, log: &kernel.MemStore{}, anchor: &kernel.MemAnchor{}, pub: priv.Public().(ed25519.PublicKey), priv: priv,
		rnd: rand.NewChaCha8([32]byte{3}), keys: &flakyKeys{MemKeys: kernel.NewMemKeys()}, mail: kernel.NewMemContent(),
		holder: holderKeyCanary}
	r.boot(r.log, r.keys)
	return r
}

func (r *rig) boot(log *kernel.MemStore, keys kernel.Keys) kernel.ContentReport {
	r.t.Helper()
	l, err := kernel.Open(kernel.Config{Store: log, Anchor: r.anchor, Key: logKeyCanary, Pub: r.pub, Sign: r.priv, Rand: r.rnd})
	must(r.t, err)
	r.k, err = kernel.Boot(l, nil, nil, 0)
	must(r.t, err)
	rep, err := r.k.OpenContent(keys, map[string]kernel.ContentStore{"mail": r.mail}, 0)
	must(r.t, err)
	return rep
}

func (r *rig) open() string {
	r.t.Helper()
	s, err := r.k.OpenSubject(1)
	must(r.t, err)
	return s
}

func (r *rig) seal(sub, text string) kernel.Hash {
	r.t.Helper()
	h, err := r.k.Seal(2, sub, "mail", "body", []byte(text))
	must(r.t, err)
	return h
}

func (r *rig) erase(sub string) {
	r.t.Helper()
	if _, err := r.k.Erase(3, sub); err != nil && !r.keys.failDelete {
		r.t.Fatal(err)
	}
}

// input is a backup of the rig: its log and mail store as sections.
func (r *rig) input(rcp Recipient) Input {
	logBytes := bytes.Clone(r.log.B)
	var mail []byte
	for h, ct := range r.mail.M {
		mail = append(append(mail, h[:]...), ct...)
	}
	return Input{Recipient: rcp, Created: 1700000000, PageCA: []byte("page-ca-canary"), EdgeKey: []byte("edge-key-canary"),
		RevokedEdge: [][]byte{[]byte("revoked-fp-1"), []byte("revoked-fp-2")},
		Sections:    []Source{src("log", logBytes), src("content/mail", mail)},
		Keys:        r.keys, State: r.k.State()}
}

func (r *rig) backup(rcp Recipient, t Target) (Record, []byte) {
	r.t.Helper()
	var buf bytes.Buffer
	rec, err := Write(&buf, t, r.input(rcp))
	must(r.t, err)
	return rec, buf.Bytes()
}

func src(name string, b []byte) Source {
	return Source{Name: name, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }}
}

func recipient(t *testing.T, rk []byte) Recipient {
	t.Helper()
	r, err := RecipientFor(rk)
	must(t, err)
	return r
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// sealBytes seals body as one object of kind to r.
func sealBytes(t *testing.T, r Recipient, kind string, id [idLen]byte, gen uint64, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := sealTo(&buf, r, header{kind: kind, backupID: id, gen: gen})
	must(t, err)
	_, err = w.Write(body)
	must(t, err)
	must(t, w.Close())
	return buf.Bytes()
}

// openBytes opens obj fully, returning its body.
func openBytes(obj, rk []byte, kind string) ([]byte, error) {
	_, r, err := openFrom(bytes.NewReader(obj), rk, kind)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// tables lists t's generations of id.
func tables(t *testing.T, tg Target, id string) []uint64 {
	t.Helper()
	g, err := tg.Tables(id)
	must(t, err)
	return g
}

// unwrapped is the subjects a table object restores.
func unwrapped(t *testing.T, tg Target, rec Record, gen uint64, rk []byte) *kernel.MemKeys {
	t.Helper()
	b, err := tg.GetTable(rec.BackupID, gen)
	must(t, err)
	dst := kernel.NewMemKeys()
	_, err = UnwrapTable(bytes.NewReader(b), rk, rec.BackupID, dst)
	must(t, err)
	return dst
}

// forms is secret as raw bytes, hex and base64, for canary searches.
func forms(secret []byte) [][]byte {
	return [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret))}
}
