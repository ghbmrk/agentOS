package update

// REQ: OSS-8, UPD-8, CHG-3

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

func securityFix(t *testing.T) (*fixture, *Checked) {
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

func pass(t *testing.T, k ed25519.PrivateKey, v *Checked) []byte {
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
	if !pub.Equal(k.Public()) || st.Release != "releases/2.json" || st.ManifestSHA256 != v.ManifestFile().SHA256 ||
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
	if other.ManifestFile().SHA256 == v.ManifestFile().SHA256 {
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
		pass(t, own, v),           // this box itself
		pass(t, f.tgt[2], v),      // a maintainer key
		pass(t, f.ts, v),          // the online timestamp key
		pass(t, newKey(t), other), // another release's bytes
		stable, failed, tampered, []byte("{}"), []byte("not json"),
	}
	if err := v.SecurityAutoStage(notCounted, own.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNeedsAttestation) {
		t.Fatalf("only non-independent attestations: %v", err)
	}
	if n := v.IndependentPasses(notCounted, own.Public().(ed25519.PublicKey)); n != 0 {
		t.Fatalf("counted %d", n)
	}
	ok := pass(t, newKey(t), v)
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

// A TUF-checked release reaches the change pipeline as the same Verified
// value #34's seam makes: version, signed image digests, and Security only
// with an independent attestation.
func TestCheckedReleaseBecomesPipelineVerified(t *testing.T) {
	_, c := securityFix(t)
	plain := c.Verified(nil, nil)
	if !plain.OK() || plain.Version() != "2" || plain.Security() {
		t.Fatalf("unattested: ok=%v version=%q security=%v", plain.OK(), plain.Version(), plain.Security())
	}
	imgs := plain.Images()
	if len(imgs) != 3 {
		t.Fatalf("images %v", imgs)
	}
	for _, f := range c.Files() {
		if imgs[f.Path] != f.SHA256 {
			t.Fatalf("%s: %q, signed %q", f.Path, imgs[f.Path], f.SHA256)
		}
	}
	if !c.Verified([][]byte{pass(t, newKey(t), c)}, nil).Security() {
		t.Fatal("attested security fix not marked security")
	}
}
