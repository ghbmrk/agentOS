package inbox

// REQ: VRB-2

import (
	"bytes"
	"strings"
	"testing"
)

// countBodyHashes swaps bodyHash for one that counts its calls, until the
// test ends.
func countBodyHashes(t *testing.T) *int {
	t.Helper()
	n, orig := new(int), bodyHash
	bodyHash = func(body []byte, limit int) [32]byte {
		*n++
		return orig(body, limit)
	}
	t.Cleanup(func() { bodyHash = orig })
	return n
}

// repeatSig is raw with its first line, the DKIM-Signature, written n times.
func repeatSig(raw []byte, n int) []byte {
	sig, rest, _ := bytes.Cut(raw, []byte("\r\n"))
	return []byte(strings.Repeat(string(sig)+"\r\n", n) + string(rest))
}

// #6422: the work VerifyDKIM does for one message is bounded by the message,
// not by its DKIM-Signature count. Signatures that share l= (the only
// canonicalization verified is relaxed/relaxed) hash the body once, and
// each still verifies.
func TestVerifyDKIMHashesTheBodyOncePerL(t *testing.T) {
	const tags = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sig.test; s=s1; h=from:subject"
	good, key := killSigned(t, tags)
	keys := map[string]string{"s1._domainkey.sig.test": key}
	n := countBodyHashes(t)
	sigs := VerifyDKIM(repeatSig(good, dkimSigMax), keys)
	if len(sigs) != dkimSigMax {
		t.Fatalf("VerifyDKIM gave %d results, want %d", len(sigs), dkimSigMax)
	}
	for i, s := range sigs {
		if !s.Pass {
			t.Errorf("signature %d of %d identical ones does not pass", i+1, dkimSigMax)
		}
	}
	if *n != 1 {
		t.Errorf("%d identical signatures hashed the body %d times, want 1", dkimSigMax, *n)
	}
	// A different l= is a different body hash: one more, then none for its copy.
	withL, _ := killSigned(t, tags+"; l=3")
	sig, _, _ := bytes.Cut(withL, []byte("\r\n"))
	*n = 0
	two := append([]byte(strings.Repeat(string(sig)+"\r\n", 2)), repeatSig(good, 2)...)
	if sigs := VerifyDKIM(two, keys); len(sigs) != 4 || !sigs[2].Pass || !sigs[3].Pass {
		t.Errorf("VerifyDKIM with two l= values = %+v, want 4 results, the last two passing", sigs)
	}
	if *n != 2 {
		t.Errorf("two l= values hashed the body %d times, want 2", *n)
	}
}

// More signatures than dkimSigMax fail closed: none is evaluated, so none
// passes and the body is never hashed, though each one alone verifies.
func TestVerifyDKIMPastTheBoundFailsClosed(t *testing.T) {
	good, key := killSigned(t, "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sig.test; s=s1; h=from:subject")
	keys := map[string]string{"s1._domainkey.sig.test": key}
	n := countBodyHashes(t)
	sigs := VerifyDKIM(repeatSig(good, dkimSigMax+1), keys)
	if len(sigs) != dkimSigMax+1 {
		t.Fatalf("VerifyDKIM gave %d results, want %d", len(sigs), dkimSigMax+1)
	}
	for i, s := range sigs {
		if s.Pass || s.D != "" || s.H != nil || s.L || s.T != -1 || s.X != -1 {
			t.Errorf("signature %d past the bound = %+v, want unevaluated", i+1, s)
		}
	}
	if *n != 0 {
		t.Errorf("past the bound the body was hashed %d times, want 0", *n)
	}
}
