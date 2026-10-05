package update

// REQ: OSS-8, UPD-8, CHG-3, OSS-4

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/attest"
)

func securityFix(t *testing.T) (*fixture, *Verified) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	return f, res.Release
}

func newKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// floorPC is the HW-4 reference PC as the public attestation schema lists it.
var floorPC = attest.Hardware{Vendor: "geekom", Model: "air12_lite", Firmware: attest.Unlisted}

func pass(t *testing.T, k ed25519.PrivateKey, v *Verified) []byte {
	b, err := Attest(k, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Versions: map[string]string{"openclaw": "2026.9.8"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAttestationRoundTrip(t *testing.T) {
	_, v := securityFix(t)
	k := newKey(t)
	st, pub, err := ParseAttestation(pass(t, k, v))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k.Public()) || st.Release != "releases/2.json" || st.ManifestSHA256 != mustV(v.ManifestFile()).SHA256 ||
		st.Hardware != floorPC || st.Versions["openclaw"] != "2026.9.8" {
		t.Fatalf("%+v", st)
	}
}

func TestSecurityFixWaitsForOneIndependentAttestation(t *testing.T) {
	f, v := securityFix(t)
	own := newKey(t)
	if err := v.SecurityAutoStage(nil, own.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNeedsAttestation) {
		t.Fatalf("no attestations: %v", err)
	}
	g := newFixture(t) // a different release with the same version
	g.rootHash = "cd" + g.rootHash[2:]
	g.release(2, func(r *Manifest) { r.Security = true })
	g.publish(0, 1)
	gres, _ := g.check(Options{})
	other := gres.Release
	if mustV(other.ManifestFile()).SHA256 == mustV(v.ManifestFile()).SHA256 {
		t.Fatal("fixture: the two releases have the same bytes")
	}
	stable, _ := Attest(newKey(t), v, Statement{Result: ResultPass, Channel: ChannelStable, Hardware: floorPC})
	failed, _ := Attest(newKey(t), v, Statement{Result: ResultFail, Channel: ChannelFast, Hardware: floorPC})
	tampered := pass(t, newKey(t), v)
	var env map[string]any
	json.Unmarshal(tampered, &env)
	sigs := env["signatures"].([]any)
	s := sigs[0].(map[string]any)
	s["sig"] = "AAAA" + s["sig"].(string)[4:]
	tampered, _ = json.Marshal(env)
	notCounted := [][]byte{
		pass(t, own, v),          // this box itself
		pass(t, f.tgt[2], v),     // a maintainer key
		pass(t, f.ts, v),         // the online timestamp key
		pass(t, f.att[1], other), // another release's bytes
		pass(t, newKey(t), v),    // a key not on the allow-list
		stable, failed, tampered, []byte("{}"), []byte("not json"),
	}
	if err := v.SecurityAutoStage(notCounted, own.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNeedsAttestation) {
		t.Fatalf("only non-independent attestations: %v", err)
	}
	if n := v.IndependentPasses(notCounted, own.Public().(ed25519.PublicKey)); n != 0 {
		t.Fatalf("counted %d", n)
	}
	ok := pass(t, f.att[0], v)
	if err := v.SecurityAutoStage(append(notCounted, ok, ok), own.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if n := v.IndependentPasses([][]byte{ok, ok}, nil); n != 1 {
		t.Fatalf("one attestor counted %d times", n)
	}
}

func TestOnlySecurityFixesUseTheAttestationRule(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, _ := f.check(Options{})
	if err := res.Release.SecurityAutoStage([][]byte{pass(t, newKey(t), res.Release)}, nil); err == nil {
		t.Fatal("a non-security release auto-staged under the security rule")
	}
}

// A TUF-checked release is what the change pipeline takes (#34's seam):
// version, signed image digests, and Security only for a security fix
// with an independent attestation, never from the manifest flag alone.
func TestCheckedReleaseFeedsThePipeline(t *testing.T) {
	sf, v := securityFix(t)
	if !v.OK() || v.Version() != "2" || v.Security() {
		t.Fatalf("unattested: ok=%v version=%q security=%v", v.OK(), v.Version(), v.Security())
	}
	imgs := v.Images()
	if len(imgs) != 3 {
		t.Fatalf("images %v", imgs)
	}
	for _, f := range mustV(v.Files()) {
		if imgs[f.Path] != f.SHA256 {
			t.Fatalf("%s: %q, signed %q", f.Path, imgs[f.Path], f.SHA256)
		}
	}
	if v.WithAttestations(nil, nil).Security() {
		t.Fatal("security fix with no attestation marked security")
	}
	att := v.WithAttestations([][]byte{pass(t, sf.att[0], v)}, nil)
	if !att.Security() || v.Security() {
		t.Fatal("attested security fix not marked security, or the original changed")
	}
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, _ := f.check(Options{})
	if res.Release.WithAttestations([][]byte{pass(t, f.att[0], res.Release)}, nil).Security() {
		t.Fatal("an attested non-security release marked security")
	}
}

// Arbitrator ruling on D6: a maintainer-run attestor is evidence, labelled
// maintainer-operated, and never independent, whether the signed attestor
// list names its key or its statement marks itself.
func TestMaintainerOperatedAttestorNeverIndependent(t *testing.T) {
	f := newFixture(t)
	ci := newKey(t)
	f.must(f.repo.SetMaintainerAttestors([]ed25519.PublicKey{ci.Public().(ed25519.PublicKey)}))
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: f.attestors(ci)}) // even if allow-listed
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	listed := pass(t, ci, v)
	marked, err := Attest(f.att[1], v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: OperatorMaintainer})
	if err != nil {
		t.Fatal(err)
	}
	atts := [][]byte{listed, marked}
	if n := v.IndependentPasses(atts, nil); n != 0 {
		t.Fatalf("maintainer-operated counted as independent: %d", n)
	}
	if n := v.MaintainerPasses(atts, nil); n != 2 {
		t.Fatalf("maintainer evidence: %d", n)
	}
	if v.WithAttestations(atts, nil).Security() || !errors.Is(v.SecurityAutoStage(atts, nil), ErrNeedsAttestation) {
		t.Fatal("maintainer-operated attestations auto-staged a security fix")
	}
	if _, err := Attest(newKey(t), v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: "ci"}); err == nil {
		t.Fatal("unknown operator label")
	}
	ind := pass(t, f.att[0], v)
	if v.IndependentPasses(append(atts, ind), nil) != 1 || v.MaintainerPasses(append(atts, ind), nil) != 2 {
		t.Fatal("independent attestor miscounted")
	}
}

// A key any root this box accepted listed stays a maintainer key after a
// rotation drops it (Security R2).
func TestRotatedOutKeyStillNotIndependent(t *testing.T) {
	f := newFixture(t)
	if _, err := f.check(Options{}); err != nil {
		t.Fatal(err)
	}
	old := f.tgt[2]
	f.must(f.repo.Rotate("targets", nil, []ed25519.PublicKey{old.Public().(ed25519.PublicKey)}, 0))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: f.attestors(old)}) // even if allow-listed
	if err != nil || res.Release == nil || res.RootRotatedTo != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := res.Release.IndependentPasses([][]byte{pass(t, old, res.Release)}, nil); n != 0 {
		t.Fatal("a rotated-out targets key counted as independent")
	}
	// A box that sees no new root reports no rotation.
	if res, _ := f.check(Options{}); res.RootRotatedTo != 0 {
		t.Fatalf("RootRotatedTo %d without a rotation", res.RootRotatedTo)
	}
}

// envelopeOf signs body as a DSSE attestation without Attest's checks, so
// tests can sign statements Attest would never write.
func envelopeOf(k ed25519.PrivateKey, body string) []byte {
	id, _ := KeyID(k.Public())
	b, _ := json.Marshal(envelope{
		PayloadType: AttestationType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(body)),
		Signatures:  []envSignature{{KeyID: id, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k, pae(AttestationType, []byte(body))))}},
	})
	return b
}

// canonical is the canonical statement body Attest would sign for st.
func canonical(st Statement) string {
	b, _ := json.Marshal(st)
	return string(b)
}

// Attestations decode strictly: a signed statement with a duplicate or
// case-variant key is refused, not resolved last-wins (#34's guarantee).
func TestStrictAttestations(t *testing.T) {
	f, v := securityFix(t)
	k := f.att[0]
	m := mustV(v.ManifestFile())
	pub := base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	head := `{"release":"` + m.Path + `","manifest_sha256":"` + m.SHA256 + `","channel":"fast","hardware":{"vendor":"unlisted","model":"unlisted","firmware":"unlisted"},"attestor":"` + pub + `"`
	unknown := attest.Hardware{Vendor: attest.Unlisted, Model: attest.Unlisted, Firmware: attest.Unlisted}
	good := envelopeOf(k, canonical(Statement{Release: m.Path, ManifestSHA256: m.SHA256, Result: ResultPass, Channel: ChannelFast, Hardware: unknown, Attestor: pub}))
	if v.IndependentPasses([][]byte{good}, nil) != 1 {
		t.Fatal("fixture: the well-formed statement does not count")
	}
	for _, body := range []string{
		head + `,"result":"fail","result":"pass"}`,
		head + `,"result":"fail","Result":"pass"}`,
		head + `,"RESULT":"pass"}`,
		head + `,"result":"pass","operator":"maintainer","Operator":""}`,
		head + `,"result":"pass","extra":1}`,
		head + `,"result":"pass","versions":{"a":"1","a":"2"}}`,
		head + `,"result":"pass","hardware":{"vendor":"unlisted","model":"unlisted","firmware":"unlisted"}}`,
		head + `,"result":"pass"}{}`,
	} {
		b := envelopeOf(k, body)
		if _, _, err := ParseAttestation(b); err == nil {
			t.Fatalf("accepted %s", body)
		}
		if v.IndependentPasses([][]byte{b}, nil) != 0 {
			t.Fatalf("counted %s", body)
		}
	}
	s := string(good)
	for _, env := range []string{
		strings.Replace(s, `"payloadType"`, `"PayloadType"`, 1),
		strings.Replace(s, `"keyid"`, `"KeyID"`, 1),
		strings.Replace(s, `"sig":`, `"Sig":`, 1),
		strings.Replace(s, `{"payloadType"`, `{"payload":"e30=","payloadType"`, 1),
		s + `x`,
	} {
		if _, _, err := ParseAttestation([]byte(env)); err == nil {
			t.Fatalf("accepted envelope %s", env)
		}
	}
}

// D6 as corrected: only allow-listed attestors count, so a key a
// compromised signing quorum mints counts for nothing, and an empty list
// sends every security fix to the owner.
func TestOnlyAllowListedAttestorsCount(t *testing.T) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	minted := newKey(t)
	for _, c := range []struct {
		name  string
		allow []ed25519.PublicKey
		want  int
	}{
		{"empty list", []ed25519.PublicKey{}, 0},
		{"other keys listed", f.attestors(), 0},
		{"minted key listed", f.attestors(minted), 1},
		{"root key listed", []ed25519.PublicKey{f.root[0].Public().(ed25519.PublicKey)}, 0},
	} {
		res, err := f.check(Options{Attestors: c.allow})
		if err != nil || res.Release == nil {
			t.Fatal(c.name, err)
		}
		atts := [][]byte{pass(t, minted, res.Release), pass(t, f.root[0], res.Release)}
		if n := res.Release.IndependentPasses(atts, nil); n != c.want {
			t.Fatalf("%s: counted %d, want %d", c.name, n, c.want)
		}
		if got := res.Release.WithAttestations(atts, nil).Security(); got != (c.want == 1) {
			t.Fatalf("%s: Security() = %v", c.name, got)
		}
	}
	if _, err := f.check(Options{Attestors: []ed25519.PublicKey{ed25519.PublicKey("short")}}); err == nil {
		t.Fatal("malformed allow-list key accepted")
	}
}

// Mark, 2026-10-05 ("Project test box"): while the allow-list holds only
// maintainer-operated keys, the project's test box counts as the check;
// once an outside attestor is listed, it stops counting.
func TestProjectTestBoxIsInterimAttestor(t *testing.T) {
	f := newFixture(t)
	box := newKey(t)
	boxPub := box.Public().(ed25519.PublicKey)
	only := []ed25519.PublicKey{boxPub}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	// The image pins the test box; the signed maintainer list need not name
	// it, and it may carry the maintainer label.
	res, err := f.check(Options{Attestors: only, InterimAttestors: only})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	labelled, _ := Attest(box, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: OperatorMaintainer})
	if !v.InterimAttestation() || v.IndependentPasses([][]byte{labelled}, nil) != 1 || !v.WithAttestations([][]byte{labelled}, nil).Security() {
		t.Fatal("the project's test box did not count as the interim check")
	}
	if v.MaintainerPasses([][]byte{labelled}, nil) != 1 {
		t.Fatal("the test box's pass is not evidence for the digest")
	}
	// Pinned but not allow-listed, or allow-listed but not pinned: no.
	res, _ = f.check(Options{Attestors: []ed25519.PublicKey{}, InterimAttestors: only})
	if res.Release.InterimAttestation() || res.Release.IndependentPasses([][]byte{labelled}, nil) != 0 {
		t.Fatal("an empty allow-list counted the test box")
	}
	// A key that only claims the label does not ride the interim rule.
	stranger := newKey(t)
	claim, _ := Attest(stranger, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: OperatorMaintainer})
	if v.IndependentPasses([][]byte{claim}, nil) != 0 {
		t.Fatal("a self-labelled key counted")
	}
}

// The signed maintainer list never makes a key count: a compromised quorum
// that lists the outside attestor as maintainer-operated must not turn the
// interim rule back on (L3 round 3, B1).
func TestSignedListCannotReviveInterim(t *testing.T) {
	f := newFixture(t)
	box, outside := newKey(t), newKey(t)
	pinned := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	f.must(f.repo.SetMaintainerAttestors(allow))
	f.release(3, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: allow, InterimAttestors: pinned})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	atts := [][]byte{pass(t, box, v), pass(t, outside, v)}
	if v.InterimAttestation() || v.IndependentPasses(atts, nil) != 0 || v.WithAttestations(atts, nil).Security() {
		t.Fatal("the signed list revived the interim rule")
	}
	// Nor does it make an allow-listed, unpinned maintainer key count alone.
	solo := newFixture(t)
	mk := newKey(t)
	mkList := []ed25519.PublicKey{mk.Public().(ed25519.PublicKey)}
	solo.must(solo.repo.SetMaintainerAttestors(mkList))
	solo.release(2, func(r *Manifest) { r.Security = true })
	solo.publish(0, 1)
	res, _ = solo.check(Options{Attestors: mkList})
	if res.Release.InterimAttestation() || res.Release.IndependentPasses([][]byte{pass(t, mk, res.Release)}, nil) != 0 {
		t.Fatal("a signed maintainer key counted without the image pin")
	}
}

// Once an outside attestor is listed, the interim rule ends for good, even
// if that attestor is removed later or never seen by a check (B2).
func TestInterimEndsForGood(t *testing.T) {
	f := newFixture(t)
	box, outside := newKey(t), newKey(t)
	pinned := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, _ := f.check(Options{Attestors: allow, InterimAttestors: pinned})
	if v := res.Release; v.InterimAttestation() || v.IndependentPasses([][]byte{pass(t, box, v)}, nil) != 0 ||
		v.IndependentPasses([][]byte{pass(t, outside, v)}, nil) != 1 {
		t.Fatal("with an outside attestor listed, the test box counted or the outside one did not")
	}
	res, _ = f.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if v := res.Release; v.InterimAttestation() || v.IndependentPasses([][]byte{pass(t, box, v)}, nil) != 0 {
		t.Fatal("removing the outside attestor brought the interim rule back")
	}
	// Added and removed between checks: the owner's change is noted.
	g := newFixture(t)
	g.release(2, func(r *Manifest) { r.Security = true })
	g.publish(0, 1)
	g.must(g.store.NoteAttestors(allow, pinned))
	res, _ = g.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if res.Release.InterimAttestation() {
		t.Fatal("an outside attestor noted between checks did not end the interim rule")
	}
	// A check that fails still records the outside attestor.
	h := newFixture(t)
	h.release(2, func(r *Manifest) { r.Security = true })
	h.publish(0, 1)
	if _, err := h.store.Check(DirSource(t.TempDir()), Options{Attestors: allow, InterimAttestors: pinned}); err == nil {
		t.Fatal("an empty repository passed")
	}
	res, _ = h.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if res.Release.InterimAttestation() {
		t.Fatal("a failed check did not record the outside attestor")
	}
}

// The newest release supersedes a security fix: it auto-stages on an
// independent attestation of its own manifest, and only then (C2).
func TestNewestReleaseCarriesTheSecurityFix(t *testing.T) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.release(3, nil)
	f.publish(0, 1)
	res, err := f.check(Options{Channel: ChannelFast})
	if err != nil || res.Release == nil || res.SecurityFix != 2 {
		t.Fatal(res, err)
	}
	v := res.Release
	if v.SecurityAutoStage(nil, nil) != ErrNeedsAttestation {
		t.Fatal("the newest release staged without an attestation")
	}
	if !v.WithAttestations([][]byte{pass(t, f.att[0], v)}, nil).Security() {
		t.Fatal("the newest release did not carry the security fix")
	}
	// An attestation of the superseded fix is not one of the newest.
	old := newFixture(t)
	old.release(2, func(r *Manifest) { r.Security = true })
	old.publish(0, 1)
	r2, _ := old.check(Options{Channel: ChannelFast})
	if v.SecurityAutoStage([][]byte{pass(t, old.att[0], r2.Release)}, nil) == nil {
		t.Fatal("an attestation of another manifest counted")
	}
}

// TestOSS4AttestRefusesWhatTheSchemaDoesNotList: a box cannot sign a
// statement carrying hardware, versions, or a channel the public schema
// does not list, so free text, serial numbers and the like never leave it.
func TestOSS4AttestRefusesWhatTheSchemaDoesNotList(t *testing.T) {
	_, v := securityFix(t)
	k := newKey(t)
	ok := Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC}
	if _, err := Attest(k, v, ok); err != nil {
		t.Fatal(err)
	}
	unknown := attest.Hardware{Vendor: attest.Unlisted, Model: attest.Unlisted, Firmware: attest.Unlisted}
	if _, err := Attest(k, v, Statement{Result: ResultFail, Channel: ChannelStable, Hardware: unknown}); err != nil {
		t.Fatal("hardware the schema does not know yet:", err)
	}
	bad := map[string]func(*Statement){
		"no hardware":      func(s *Statement) { s.Hardware = attest.Hardware{} },
		"serial number":    func(s *Statement) { s.Hardware.Firmware = "SN-4C1A92F07" },
		"free-text model":  func(s *Statement) { s.Hardware.Model = "Mark's kitchen PC" },
		"unlisted version": func(s *Statement) { s.Versions = map[string]string{"openclaw": "2026.9.9"} },
		"free-text key":    func(s *Statement) { s.Versions = map[string]string{"my notes": "x"} },
		"channel":          func(s *Statement) { s.Channel = "nightly" },
		"result":           func(s *Statement) { s.Result = "pass with warnings" },
	}
	for name, f := range bad {
		st := ok
		f(&st)
		if _, err := Attest(k, v, st); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// TestOSS4ParseRefusesStatementsOutsideTheSchema: a statement signed
// elsewhere with fields no schema version could hold does not parse, so
// it never counts (D6) or reaches the owner's digest as evidence (OSS-9).
func TestOSS4ParseRefusesStatementsOutsideTheSchema(t *testing.T) {
	_, v := securityFix(t)
	k := newKey(t)
	pub := base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	sha := mustV(v.ManifestFile()).SHA256
	// stmt signs a canonical statement edited as a map, so the edit, not
	// key order, is what a refusal is about.
	stmt := func(edit func(m map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal([]byte(canonical(Statement{Release: "releases/2.json", ManifestSHA256: sha, Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Attestor: pub})), &m)
		if edit != nil {
			edit(m)
		}
		// Re-encode in Statement's field order when the keys still fit it.
		raw, _ := json.Marshal(m)
		var st Statement
		if err := decodeStrict(raw, &st, statementFields); err == nil {
			if c := canonical(st); len(c) > 0 {
				var back map[string]any
				json.Unmarshal([]byte(c), &back)
				if reflect.DeepEqual(back, m) {
					return envelopeOf(k, c)
				}
			}
		}
		return envelopeOf(k, string(raw))
	}
	if _, _, err := ParseAttestation(stmt(nil)); err != nil {
		t.Fatal(err)
	}
	if n := v.MaintainerPasses([][]byte{stmt(func(m map[string]any) { m["operator"] = "maintainer" })}, nil); n != 1 {
		t.Fatalf("fixture: a valid maintainer-labelled statement counts %d", n)
	}
	bad := map[string]func(m map[string]any){
		"timestamp":          func(m map[string]any) { m["time"] = "2026-10-05T04:00:00Z" },
		"notes":              func(m map[string]any) { m["notes"] = "ran on Mark's PC" },
		"serial":             func(m map[string]any) { m["serial"] = "SN-4C1A92F07" },
		"old hardware_class": func(m map[string]any) { m["hardware_class"] = "n95-8g" },
		"no hardware":        func(m map[string]any) { delete(m, "hardware") },
		"hardware as text":   func(m map[string]any) { m["hardware"] = "geekom air12_lite" },
		"hardware extra key": func(m map[string]any) {
			m["hardware"] = map[string]any{"vendor": "geekom", "model": "air12_lite", "firmware": "unlisted", "serial": "x"}
		},
		"hardware free text": func(m map[string]any) {
			m["hardware"] = map[string]any{"vendor": "geekom", "model": "Mark's kitchen PC", "firmware": "unlisted"}
		},
		"hardware under unlisted": func(m map[string]any) {
			m["hardware"] = map[string]any{"vendor": "unlisted", "model": "air12_lite", "firmware": "unlisted"}
		},
		"version unlisted": func(m map[string]any) { m["versions"] = map[string]any{"openclaw": "hello world"} },
		"channel":          func(m map[string]any) { m["channel"] = "nightly" },
		"result":           func(m map[string]any) { m["result"] = "maybe" },
		"operator":         func(m map[string]any) { m["operator"] = "Mark" },
		"release path":     func(m map[string]any) { m["release"] = "releases/2.json?note=hi" },
		"padded release":   func(m map[string]any) { m["release"] = "releases/02.json" },
		"release zero":     func(m map[string]any) { m["release"] = "releases/0.json" },
		"manifest hash":    func(m map[string]any) { m["manifest_sha256"] = "not a hash" },
	}
	for name, edit := range bad {
		b := stmt(edit)
		if _, _, err := ParseAttestation(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
		if n := v.MaintainerPasses([][]byte{stmt(func(m map[string]any) { m["operator"] = "maintainer"; edit(m) })}, nil); n != 0 {
			t.Errorf("%s: counted as evidence", name)
		}
	}
}

// TestOSS4NewerSchemaStatementStillCounts (potency PB1 on #73): an
// attestor already on release N+1 names N+1's hardware and versions,
// which this box's schema N does not list yet. The statement still counts
// for D6, and comes back with only what this box lists.
func TestOSS4NewerSchemaStatementStillCounts(t *testing.T) {
	f, v := securityFix(t)
	k := f.att[0]
	m := mustV(v.ManifestFile())
	body := canonical(Statement{
		Release: m.Path, ManifestSHA256: m.SHA256, Result: ResultPass, Channel: ChannelFast,
		Hardware: attest.Hardware{Vendor: "geekom", Model: "air12_lite", Firmware: "1.0.9"},
		Versions: map[string]string{"openclaw": "2026.11.2", "kernel": "6.12.48"},
		Attestor: base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)),
	})
	b := envelopeOf(k, body)
	st, _, err := ParseAttestation(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.Hardware != floorPC || len(st.Versions) != 1 || st.Versions["openclaw"] != attest.Unlisted {
		t.Fatalf("%+v", st)
	}
	if n := v.IndependentPasses([][]byte{b}, nil); n != 1 {
		t.Fatalf("independent passes %d", n)
	}
	if err := v.SecurityAutoStage([][]byte{b}, nil); err != nil {
		t.Fatal(err)
	}
	// Signing stays strict: this box cannot write what its schema does not list.
	if _, err := Attest(k, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: st.Hardware, Versions: map[string]string{"openclaw": "2026.11.2"}}); err == nil {
		t.Fatal("signed an unlisted version")
	}
}

// TestOSS4OnlyCanonicalAttestationsParse (security C1 on #73): an
// attestation parses only as the exact bytes Attest writes, so nothing
// outside the statement's fields (extra signatures, keyids, whitespace,
// key order, escapes, empty fields, base64 forms) can carry bits.
func TestOSS4OnlyCanonicalAttestationsParse(t *testing.T) {
	f, v := securityFix(t)
	k := f.att[0]
	good, err := Attest(k, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Versions: map[string]string{"openclaw": "2026.9.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseAttestation(good); err != nil || v.IndependentPasses([][]byte{good}, nil) != 1 {
		t.Fatal("fixture: Attest's own output does not parse and count", err)
	}
	var env envelope
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig := env.Signatures[0]
	reenc := func(e envelope) []byte { b, _ := json.Marshal(e); return b }
	resign := func(body string) []byte { return envelopeOf(k, body) }
	other := newKey(t)
	otherSig := base64.StdEncoding.EncodeToString(ed25519.Sign(other, pae(AttestationType, body)))
	otherID, _ := KeyID(other.Public())
	bs := string(body)
	pubB64 := base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	// A non-canonical encoding of the same key: flip the unused low bits
	// of the last base64 digit before the padding.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, pubB64[len(pubB64)-2])
	altKey := pubB64[:len(pubB64)-2] + string(alphabet[last^1]) + "="
	cases := map[string][]byte{
		"second signature":  reenc(envelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []envSignature{sig, {KeyID: otherID, Sig: otherSig}}}),
		"junk signature":    reenc(envelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []envSignature{sig, {KeyID: "x", Sig: "AAAA"}}}),
		"no signature":      reenc(envelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []envSignature{}}),
		"keyid free text":   reenc(envelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []envSignature{{KeyID: "hello", Sig: sig.Sig}}}),
		"envelope spaces":   []byte(strings.Replace(string(good), `,"payload"`, `, "payload"`, 1)),
		"envelope newline":  append(append([]byte{}, good...), '\n'),
		"base64 line break": []byte(strings.Replace(string(good), env.Payload, env.Payload[:8]+`\r\n`+env.Payload[8:], 1)),
		"body whitespace":   resign(strings.Replace(bs, `,"result"`, `, "result"`, 1)),
		"body key order":    resign(strings.Replace(bs, `"result":"pass","channel":"fast"`, `"channel":"fast","result":"pass"`, 1)),
		"body escape":       resign(strings.Replace(bs, `"pass"`, `"\u0070ass"`, 1)),
		"empty versions":    resign(strings.Replace(bs, `"versions":{"openclaw":"2026.9.8"}`, `"versions":{}`, 1)),
		"empty operator":    resign(strings.Replace(bs, `}`, `,"operator":""}`, 1)),
		"attestor bits":     resign(strings.Replace(bs, pubB64, altKey, 1)),
	}
	if string(reenc(env)) != string(good) {
		t.Fatal("fixture: re-encoding is not canonical")
	}
	if !strings.Contains(bs, `"result":"pass","channel":"fast"`) || altKey == pubB64 {
		t.Fatal("fixture: canonical body has an unexpected shape:", bs)
	}
	for name, b := range cases {
		if string(b) == string(good) {
			t.Errorf("%s: fixture did not change the attestation", name)
			continue
		}
		if _, _, err := ParseAttestation(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
		if v.IndependentPasses([][]byte{b}, nil) != 0 {
			t.Errorf("%s: counted", name)
		}
	}
}

// TestOSS4ParseCapsAttestationSize (review K-PB1b on #73): an attestation
// larger than MaxAttestationSize is refused before it is decoded.
func TestOSS4ParseCapsAttestationSize(t *testing.T) {
	_, v := securityFix(t)
	good := pass(t, newKey(t), v)
	if len(good) > MaxAttestationSize {
		t.Fatalf("a plain attestation is %d bytes", len(good))
	}
	big := append(append([]byte{}, good...), bytes.Repeat([]byte(" "), MaxAttestationSize)...)
	if _, _, err := ParseAttestation(big); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("oversize attestation: %v", err)
	}
}
