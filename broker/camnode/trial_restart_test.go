package camnode

import (
	"crypto/sha256"
	"testing"
)

// REQ: NET-7

// TestRestartWithinTrialBoot (L3 on #3617, finding 2): a service restart
// within the trial boot, after the trial was marked good and the counter
// raised (systemd Restart=, a crash), starts again: the image is settled.
// Probe by the L3 review.
func TestRestartWithinTrialBoot(t *testing.T) {
	r := newRig(t, true)
	r.provision(5)
	img := testImage()
	r.manifest, r.image = r.signManifest(img, 1, r.owner, r.release), sha256.Sum256(img)
	r.trial = true
	if err := r.boot(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { c, _ := r.el.Image(); return c == 1 })
	// same boot, device-tree tryboot still 1: the service restarts
	if err := r.boot(false); err != nil {
		t.Fatalf("restart within the trial boot refused: %v", err)
	}
}
