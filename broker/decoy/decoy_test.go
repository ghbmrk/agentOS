package decoy

// REQ: KRN-12

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// rangeAddrs stands in for the enforcer's decoy range (decision 4, DECOY-d).
var rangeAddrs = []netip.Addr{
	netip.MustParseAddr("192.168.10.250"),
	netip.MustParseAddr("192.168.20.250"),
	netip.MustParseAddr("192.168.30.250"),
}

// seeded is a deterministic byte source, so a failing sample can be rerun.
type seeded struct{ r *mrand.ChaCha8 }

func newSeeded(seed byte) *seeded {
	var s [32]byte
	s[0] = seed
	return &seeded{mrand.NewChaCha8(s)}
}

func (s *seeded) Read(p []byte) (int, error) { return s.r.Read(p) }

// validators: each kind's published format, written apart from gen.go.
var (
	reGitHub    = regexp.MustCompile(`^ghp_([0-9A-Za-z]{30})([0-9A-Za-z]{6})$`)
	reAWSKeyID  = regexp.MustCompile(`^AKIA[Q-Z2-7][A-Z2-7]{15}$`)
	reAWSSecret = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	// gitleaks' anthropic-api-key and openai-api-key rules.
	reAnthropic = regexp.MustCompile(`^sk-ant-api03-[a-zA-Z0-9_\-]{93}AA$`)
	reOpenAI    = regexp.MustCompile(`^sk-proj-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}$`)
	reRecovery  = regexp.MustCompile(`^[0-9a-f]{5}-[0-9a-f]{5}$`)
)

func valid(k Kind, v string) error {
	switch k {
	case KGitHub:
		m := reGitHub.FindStringSubmatch(v)
		if m == nil {
			return fmt.Errorf("not ghp_ shape")
		}
		const a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		var sum uint64
		for _, c := range m[2] {
			sum = sum*62 + uint64(strings.IndexRune(a, c))
		}
		if sum != uint64(crc32.ChecksumIEEE([]byte(m[1]))) {
			return fmt.Errorf("checksum")
		}
	case KAWSKeyID:
		if !reAWSKeyID.MatchString(v) {
			return fmt.Errorf("not an access key ID")
		}
	case KAWSSecret:
		if !reAWSSecret.MatchString(v) {
			return fmt.Errorf("not a secret key")
		}
	case KAnthropic:
		if !reAnthropic.MatchString(v) {
			return fmt.Errorf("not an anthropic key")
		}
	case KOpenAI:
		if !reOpenAI.MatchString(v) {
			return fmt.Errorf("not an openai key")
		}
	case KRecovery:
		if !reRecovery.MatchString(v) {
			return fmt.Errorf("not a recovery code")
		}
	case KSSH:
		return validSSH(v)
	default:
		return fmt.Errorf("no validator for %s", k)
	}
	return nil
}

// validSSH reads OpenSSH's PROTOCOL.key container: magic, no cipher, no
// KDF, one key, the public blob, then the private section, whose two check
// ints match, whose key is the public key's, and whose padding is 1, 2, 3...
func validSSH(v string) error {
	blk, rest := pem.Decode([]byte(v))
	if blk == nil || blk.Type != "OPENSSH PRIVATE KEY" || len(rest) != 0 || len(blk.Headers) != 0 {
		return fmt.Errorf("not an OpenSSH PEM block")
	}
	for _, line := range strings.Split(strings.TrimSpace(v), "\n")[1:] {
		if !strings.HasPrefix(line, "-----") && len(line) > 70 {
			return fmt.Errorf("line over 70")
		}
	}
	b := blk.Bytes
	str := func() []byte {
		if len(b) < 4 || int(binary.BigEndian.Uint32(b)) > len(b)-4 {
			b = nil
			return nil
		}
		n := binary.BigEndian.Uint32(b)
		s := b[4 : 4+n]
		b = b[4+n:]
		return s
	}
	if !bytes.HasPrefix(b, []byte("openssh-key-v1\x00")) {
		return fmt.Errorf("magic")
	}
	b = b[15:]
	if string(str()) != "none" || string(str()) != "none" || len(str()) != 0 || b == nil {
		return fmt.Errorf("cipher or kdf")
	}
	if len(b) < 4 || binary.BigEndian.Uint32(b) != 1 {
		return fmt.Errorf("key count")
	}
	b = b[4:]
	pubBlob := str()
	sec := str()
	if b == nil || len(b) != 0 || len(sec)%8 != 0 || len(sec) < 8 {
		return fmt.Errorf("framing")
	}
	if !bytes.Equal(sec[:4], sec[4:8]) {
		return fmt.Errorf("check ints differ")
	}
	b = sec[8:]
	typ, pub, priv, comment := str(), str(), str(), str()
	if b == nil || string(typ) != "ssh-ed25519" || len(pub) != 32 || len(priv) != 64 || comment == nil {
		return fmt.Errorf("private section")
	}
	for i, p := range b {
		if p != byte(i+1) {
			return fmt.Errorf("padding")
		}
	}
	want := append(binary.BigEndian.AppendUint32(nil, 11), "ssh-ed25519"...)
	want = append(binary.BigEndian.AppendUint32(want, 32), pub...)
	if !bytes.Equal(pubBlob, want) {
		return fmt.Errorf("public blob")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(priv[:32]).Public().(ed25519.PublicKey), pub) || !bytes.Equal(priv[32:], pub) {
		return fmt.Errorf("private key is not the public key's")
	}
	return nil
}

func loadCorpus(t *testing.T) map[Kind][]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var hexed map[Kind][]string
	if err := json.Unmarshal(raw, &hexed); err != nil {
		t.Fatal(err)
	}
	out := map[Kind][]string{}
	for k, vs := range hexed {
		for _, h := range vs {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			out[k] = append(out[k], string(b))
		}
	}
	return out
}

// features are what the two-sample test compares: length and the count of
// each character class.
var features = []struct {
	name string
	f    func(string) float64
}{
	{"length", func(s string) float64 { return float64(len(s)) }},
	{"upper", classCount(unicode.IsUpper)},
	{"lower", classCount(unicode.IsLower)},
	{"digit", classCount(unicode.IsDigit)},
	{"other", classCount(func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })},
}

func classCount(is func(rune) bool) func(string) float64 {
	return func(s string) float64 {
		n := 0
		for _, r := range s {
			if is(r) {
				n++
			}
		}
		return float64(n)
	}
}

// ks is the two-sample Kolmogorov-Smirnov statistic.
func ks(a, b []float64) float64 {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Float64s(a)
	sort.Float64s(b)
	var i, j int
	d := 0.0
	for i < len(a) && j < len(b) {
		x := math.Min(a[i], b[j])
		for i < len(a) && a[i] == x {
			i++
		}
		for j < len(b) && b[j] == x {
			j++
		}
		d = math.Max(d, math.Abs(float64(i)/float64(len(a))-float64(j)/float64(len(b))))
	}
	return d
}

// KRN-12: decoys of each kind pass an independent validator of the kind's
// published format, checksums included, and a two-sample test on length and
// character classes against a fixed corpus of synthetic, format-valid
// examples (testdata/corpus.py) finds no difference. Values only: a
// destination points into the enforcer's public range by design (SPEC
// KRN-12 Limit).
func TestDecoyIndistinguishable(t *testing.T) {
	corpus := loadCorpus(t)
	if len(corpus) != len(gens) {
		t.Fatalf("corpus has %d kinds, the generators %d", len(corpus), len(gens))
	}
	for k, gen := range gens {
		ref := corpus[k]
		for i, v := range ref {
			if err := valid(k, v); err != nil {
				t.Fatalf("%s corpus %d fails its own validator: %v", k, i, err)
			}
		}
		r := newSeeded(byte(len(k)))
		var got []string
		for range len(ref) {
			v, err := gen(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := valid(k, v); err != nil {
				t.Errorf("%s decoy is not format-valid: %v", k, err)
			}
			got = append(got, v)
		}
		// alpha = 0.001: c(alpha) = sqrt(-ln(alpha/2)/2).
		n, m := float64(len(got)), float64(len(ref))
		crit := math.Sqrt(-math.Log(0.0005)/2) * math.Sqrt((n+m)/(n*m))
		for _, f := range features {
			var a, b []float64
			for _, v := range got {
				a = append(a, f.f(v))
			}
			for _, v := range ref {
				b = append(b, f.f(v))
			}
			if d := ks(a, b); d > crit {
				t.Errorf("%s: %s differs from the corpus (D=%.3f > %.3f)", k, f.name, d, crit)
			}
		}
	}
	// The whole table: every value of a kind this package makes is valid,
	// and no two entries share a value.
	tab, err := Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range tab.Entries() {
		if e.Kind == KMetadata {
			continue
		}
		if err := valid(e.Kind, e.Value); err != nil {
			t.Errorf("%v: %v", e, err)
		}
		if seen[e.Value] {
			t.Errorf("%v repeats a value", e)
		}
		seen[e.Value] = true
	}
}

// The validators are not vacuous: a value one character long or short
// fails every kind, and one changed character fails the checksummed ones.
func TestValidatorsRefuseNearMisses(t *testing.T) {
	r := newSeeded(9)
	for k, gen := range gens {
		v, _ := gen(r)
		if k == KSSH {
			// One more base64 quad in the body breaks the framing.
			lines := strings.Split(v, "\n")
			lines[2] = "AAAA" + lines[2][4:] + "AAAA"
			v2 := strings.Join(lines, "\n")
			if valid(k, v2) == nil {
				t.Errorf("%s: a reframed key validates", k)
			}
			continue
		}
		if valid(k, v+"0") == nil || valid(k, v[:len(v)-1]) == nil {
			t.Errorf("%s: a value of the wrong length validates", k)
		}
	}
	gh, _ := gitHub(r)
	c := byte('0')
	if gh[10] == '0' {
		c = '1'
	}
	if valid(KGitHub, gh[:10]+string(c)+gh[11:]) == nil {
		t.Error("github: a token with a wrong checksum validates")
	}
	key, _ := sshKey(r)
	blk, _ := pem.Decode([]byte(key))
	raw := slices.Clone(blk.Bytes)
	raw[len(raw)-40] ^= 1 // inside the private key bytes
	bad := string(pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: raw}))
	if valid(KSSH, bad) == nil {
		t.Error("ssh: a key whose private half is not its public key's validates")
	}
}

// KRN-12: the table is readable only through the sealed store, and
// replaying its logged event gives the same table and the same trips.
func TestTableSealedAndReplayed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store")
	rk := make([]byte, seal.RecoveryLen)
	rand.Read(rk)
	st, err := seal.Create(path, seal.Recovery{Key: rk})
	if err != nil {
		t.Fatal(err)
	}
	// firstBoot is the kernel's first-boot step as store.go describes it.
	firstBoot := func(st *seal.Store, r io.Reader) (Table, error) {
		b, ok, err := st.Get(StoreEntry)
		if err != nil {
			return Table{}, err
		}
		if ok {
			return Load(b)
		}
		tab, err := Generate(r, rangeAddrs)
		if err != nil {
			return Table{}, err
		}
		if b, err = Stored(tab); err != nil {
			return Table{}, err
		}
		return tab, st.Put(StoreEntry, b)
	}
	tab, err := firstBoot(st, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.Entries(), []string{StoreEntry}) {
		t.Fatalf("the store holds %v, want only the table", st.Entries())
	}
	// A first boot cut short after the save makes no second table.
	again, err := firstBoot(st, newSeeded(1))
	if err != nil || !again.Equal(tab) {
		t.Fatalf("a second first boot changed the table (err %v)", err)
	}
	st.Close()

	// The store's file, the only place the table is written, shows no
	// value in any encoding the matcher knows; nothing else in the
	// directory was written.
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("the directory holds %d files, want the store only", len(files))
	}
	disk, _ := os.ReadFile(path)
	for _, e := range tab.Entries() {
		if e.Value == "" {
			continue
		}
		for _, enc := range []string{e.Value, hex.EncodeToString([]byte(e.Value)), base64.StdEncoding.EncodeToString([]byte(e.Value))} {
			if bytes.Contains(disk, []byte(enc)) {
				t.Fatalf("the store file shows %v", e)
			}
		}
	}
	// Printing a table or an entry shows no value.
	printed := fmt.Sprintf("%v %+v %#v %s %v %#v", tab, tab, tab, tab.Entries(), tab.Entries()[0], tab.Entries()[0])
	for _, e := range tab.Entries() {
		if e.Value != "" && strings.Contains(printed, e.Value) {
			t.Fatalf("printing shows %v's value", e)
		}
	}
	// Only the store key reads it back.
	if _, err := seal.Unlock(path, seal.Recovery{Key: make([]byte, seal.RecoveryLen)}); err == nil {
		t.Fatal("a wrong key opened the store")
	}
	st2, err := seal.Unlock(path, seal.Recovery{Key: rk})
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	stored, ok, err := st2.Get(StoreEntry)
	if err != nil || !ok {
		t.Fatalf("the store lost the table (ok %v, err %v)", ok, err)
	}
	back, err := Load(stored)
	if err != nil || !back.Equal(tab) {
		t.Fatalf("the table did not come back from the store (ok %v, err %v)", ok, err)
	}
	// No table is baked in: a second box gets a table of its own.
	other, err := Generate(rand.Reader, rangeAddrs)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range other.Entries() {
		if e.Value != "" && e.Value == tab.Entries()[i].Value {
			t.Fatalf("two boxes share %v", e)
		}
	}

	// Replay: the event rebuilds the same table, and the same outbound
	// bytes and destinations give the same trips.
	body, err := json.Marshal(Event(tab))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := FromEvent(EventVersion, body)
	if err != nil || !replayed.Equal(tab) || replayed.Digest() != tab.Digest() {
		t.Fatalf("the event did not rebuild the table (err %v)", err)
	}
	es := tab.Entries()
	traffic := [][]byte{
		[]byte("GET / HTTP/1.1\r\nAuthorization: Bearer " + es[0].Value + "\r\n\r\n"),
		[]byte(`{"q":"weather in Nairobi"}`),
		[]byte(base64.StdEncoding.EncodeToString([]byte(es[7].Value))),
		[]byte("x=" + es[12].Value),
	}
	m1, m2 := tab.Matcher(), replayed.Matcher()
	for _, b := range traffic {
		r1, r2 := m1.Scan(b), m2.Scan(b)
		if !slices.Equal(r1.Trips, r2.Trips) || r1.Pattern != r2.Pattern {
			t.Fatalf("replay trips %v, live %v", r2.Trips, r1.Trips)
		}
	}
	if got := m1.Scan(traffic[0]).Trips; !slices.Equal(got, []int{0}) {
		t.Fatalf("a sent decoy tripped %v, want [0]", got)
	}
	if got := m1.Scan(traffic[1]).Trips; len(got) != 0 {
		t.Fatalf("ordinary traffic tripped %v", got)
	}
	for _, a := range append(slices.Clone(rangeAddrs), Metadata) {
		i1, ok1 := m1.Dest(a)
		i2, ok2 := m2.Dest(a)
		if ok1 != ok2 || i1 != i2 {
			t.Fatalf("replay and live differ on %s", a)
		}
	}
	if _, ok := m1.Dest(Metadata); !ok {
		t.Fatal("the metadata address does not trip")
	}

	// A damaged or foreign event rebuilds nothing.
	if _, err := FromEvent(EventVersion+1, body); err == nil {
		t.Fatal("an unknown event version was read")
	}
	for _, bad := range []string{
		`[]`, `{}`, `[{"v":"x","k":"bogus","d":"192.168.10.250","p":"host.env"}]`,
		`[{"v":"x","k":"github","d":"192.168.10.250","p":"nowhere"}]`,
		`[{"k":"github","d":"192.168.10.250","p":"host.env"}]`,
		`[{"v":"x","k":"metadata","d":"169.254.169.254","p":"metadata"}]`,
		`[{"v":"x","k":"github","p":"host.env"}]`,
	} {
		if _, err := FromEvent(EventVersion, json.RawMessage(bad)); err == nil {
			t.Errorf("event %s was read", bad)
		}
	}
}

// Generate needs the range, points every credential into it, keeps the
// metadata entry valueless, and takes the box's own kinds only from the
// caller.
func TestGenerateRules(t *testing.T) {
	if _, err := Generate(rand.Reader, nil); err != ErrNoRange {
		t.Fatalf("no range: %v", err)
	}
	honey := func(r interface{ Read([]byte) (int, error) }) (string, error) {
		b := make([]byte, 24)
		_, err := r.Read(b)
		return "honey-" + hex.EncodeToString(b), err
	}
	tab, err := Generate(newSeeded(3), rangeAddrs, Own{KHoneyKey, PPlannerView, func(r io.Reader) (string, error) { return honey(r) }})
	if err != nil {
		t.Fatal(err)
	}
	same, _ := Generate(newSeeded(3), rangeAddrs, Own{KHoneyKey, PPlannerView, func(r io.Reader) (string, error) { return honey(r) }})
	if !same.Equal(tab) {
		t.Fatal("the same randomness gave a different table")
	}
	places := map[Place]bool{}
	for _, e := range tab.Entries() {
		places[e.Place] = true
		if e.Kind == KMetadata {
			if e.Value != "" || e.Dest != Metadata {
				t.Errorf("%v", e)
			}
			continue
		}
		if !slices.Contains(rangeAddrs, e.Dest) {
			t.Errorf("%v points outside the decoy range", e)
		}
	}
	for _, p := range []Place{PSandboxEnv, PHostEnv, PHostDotfile, PHostJackpot, PEdgeDotfile, PEdgeJackpot, PMetadata, PPlannerView} {
		if !places[p] {
			t.Errorf("nothing placed at %s", p)
		}
	}
	// More than one byte's worth of addresses still returns, and every
	// address can be picked (Security and L3 on 54307e7: a one-byte
	// rejection bound was empty past 256 and Generate never returned).
	for _, n := range []int{256, 257, 300, 1000} {
		var ds []netip.Addr
		for i := range n {
			ds = append(ds, netip.AddrFrom4([4]byte{10, 99, byte(i >> 8), byte(i)}))
		}
		if _, err := Generate(rand.Reader, ds); err != nil {
			t.Fatalf("%d addresses: %v", n, err)
		}
	}
	hits := make([]int, 300)
	r := newSeeded(4)
	for range 300 * 200 {
		i, err := uniform(r, 300)
		if err != nil {
			t.Fatal(err)
		}
		hits[i]++
	}
	for i, h := range hits {
		if h < 100 || h > 300 {
			t.Fatalf("index %d drawn %d times of a mean 200", i, h)
		}
	}
	if _, err := uniform(r, MaxRange+1); err != ErrTooMany {
		t.Fatalf("an oversized range: %v", err)
	}
	many := make([]netip.Addr, MaxRange+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	if _, err := Generate(rand.Reader, many); err != ErrTooMany {
		t.Fatalf("%d addresses: %v", len(many), err)
	}
	// A value short enough to occur in ordinary traffic is refused, from a
	// caller's generator and in a stored or logged table.
	short := Own{KHoneyKey, PPlannerView, func(io.Reader) (string, error) { return "a", nil }}
	if _, err := Generate(rand.Reader, rangeAddrs, short); err == nil {
		t.Fatal("a one-byte own value was accepted")
	}
	if _, err := Load([]byte(`[{"v":"abcdefghi","k":"github","d":"192.168.10.250","p":"host.env"}]`)); err == nil {
		t.Fatal("a nine-byte stored value was accepted")
	}
	if _, err := Generate(rand.Reader, rangeAddrs, Own{KGitHub, PHostEnv, gitHub}); err == nil {
		t.Fatal("a caller replaced a built-in generator")
	}
	// The table, with room for a handful of the box's own entries, fits
	// one sealed-store entry.
	var own []Own
	for range 4 {
		own = append(own, Own{KHoneyKey, PPlannerView, func(r io.Reader) (string, error) { return honey(r) }})
	}
	big, err := Generate(rand.Reader, rangeAddrs, own...)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := Stored(big); err != nil || len(b) > MaxStored || MaxStored > seal.MaxEntry {
		t.Fatalf("the table's stored form does not fit: %v", err)
	}
	t.Logf("stored form: %d bytes of %d", len(big.encode()), MaxStored)
}
