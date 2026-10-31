package thread

import (
	"slices"
	"testing"
)

// REQ: NET-2

// TestDaemonArgs (NET-2 Confined radio stacks): ot-daemon gets wpan0 and
// infra0, its state directory, and the radio URL last; a URL that could
// read as an option or carry another argument is refused.
func TestDaemonArgs(t *testing.T) {
	got, err := DaemonArgs("spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800", "/var/lib/agentos-thread", false)
	want := []string{"-I", "wpan0", "-B", "infra0", "--data-path", "/var/lib/agentos-thread", "spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%q %v, want %q", got, err, want)
	}
	for _, url := range []string{"", "-n", "--dry-run", "uart:///dev/ttyACM0", "spinel+hdlc+uart:///dev/x -n", "spinel+hdlc+uart:///dev/x\n"} {
		if _, err := DaemonArgs(url, "/s", false); err != ErrRadio {
			t.Errorf("%q: %v, want refused", url, err)
		}
	}
	if _, err := DaemonArgs("spinel+hdlc+uart:///dev/x", "state", false); err == nil {
		t.Error("a relative state directory was taken")
	}
}
