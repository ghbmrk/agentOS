package update

// REQ: OSS-8, UPD-8, CHG-3

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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

func pass(t *testing.T, k ed25519.PrivateKey, v *Verified) []byte {
	b, err := Attest(k, v, Statement{Result: ResultPass, Channel: ChannelFast, HardwareClass: "n95-8g", Versions: map[string]string{"openclaw": "1.2.3"}})
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
		st.HardwareClass != "n95-8g" || st.Versions["openclaw"] != "1.2.3" {
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
	stable, _ := Attest(newKey(t), v, Statement{Result: ResultPass, Channel: ChannelStable})
	failed, _ := Attest(newKey(t), v, Statement{Result: ResultFail, Channel: ChannelFast})
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
	marked, err := Attest(f.att[1], v, Statement{Result: ResultPass, Channel: ChannelFast, Operator: OperatorMaintainer})
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
	if _, err := Attest(newKey(t), v, Statement{Result: ResultPass, Channel: ChannelFast, Operator: "ci"}); err == nil {
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
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(k, pae(AttestationType, []byte(body))))
	return []byte(`{"payloadType":"` + AttestationType + `","payload":"` + base64.StdEncoding.EncodeToString([]byte(body)) +
		`","signatures":[{"keyid":"x","sig":"` + sig + `"}]}`)
}

// Attestations decode strictly: a signed statement with a duplicate or
// case-variant key is refused, not resolved last-wins (#34's guarantee).
func TestStrictAttestations(t *testing.T) {
	f, v := securityFix(t)
	k := f.att[0]
	m := mustV(v.ManifestFile())
	pub := base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	head := `{"release":"` + m.Path + `","manifest_sha256":"` + m.SHA256 + `","channel":"fast","hardware_class":"x","attestor":"` + pub + `"`
	good := envelopeOf(k, head+`,"result":"pass"}`)
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
	labelled, _ := Attest(box, v, Statement{Result: ResultPass, Channel: ChannelFast, Operator: OperatorMaintainer})
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
	claim, _ := Attest(stranger, v, Statement{Result: ResultPass, Channel: ChannelFast, Operator: OperatorMaintainer})
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
