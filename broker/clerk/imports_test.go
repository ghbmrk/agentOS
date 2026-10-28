package clerk_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: KRN-2

// The kernel, the key library and the clerk check path (check.Check,
// check.Verify) run in the trusted base, so none of them links a parser of
// mail, voice or photos: the IMAP client, the SIP and RTP stack, or the QR
// decoder. The inbox clerk's transport links IMAP in its own package, which
// the check path never imports (#2937).
func TestCheckPathLinksNoMailVoiceOrPhotoParser(t *testing.T) {
	banned := []string{
		"github.com/emersion/",
		"github.com/emiago/sipgo",
		"github.com/pion/",
		"github.com/makiuchi-d/gozxing",
		"github.com/ghbmrk/agentos/broker/clerk/inbox",
	}
	for _, pkg := range []string{".", "./check", "../kernel", "../kernel/key"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg, err, out)
		}
		for _, p := range strings.Fields(string(out)) {
			for _, b := range banned {
				if strings.HasPrefix(p, b) {
					t.Errorf("%s links %s", pkg, p)
				}
			}
		}
	}
}
