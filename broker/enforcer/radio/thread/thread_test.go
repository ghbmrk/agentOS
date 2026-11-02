package thread

import (
	"slices"
	"testing"
)

// REQ: NET-2

// TestDaemonArgs (NET-2 Confined radio stacks; #4616): ot-daemon gets
// wpan0 and infra0, its state directory, and last the spinel URL made from
// the radio's path, the one confine.Thread binds as a character device.
// A path that is not absolute and clean, or holds a character that could
// end the URL's path, start a query or another argument, is refused, so
// the URL can name no other file in the view (the state or run directory),
// where ot-daemon would fork a regular file; the view's refusal of a
// regular file at the radio's own path is confine.TestThreadRadioMustBeDevice.
func TestDaemonArgs(t *testing.T) {
	got, err := DaemonArgs("/dev/ttyACM0", 460800, "/var/lib/agentos-thread", false)
	want := []string{"-I", "wpan0", "-B", "infra0", "--data-path", "/var/lib/agentos-thread", "spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%q %v, want %q", got, err, want)
	}
	for _, radio := range []string{"", "-n", "dev/ttyACM0", "relative/path", "/dev/../var/lib/agentos-thread/settings", "/dev//ttyACM0", "/dev/ttyACM0/",
		"/dev/x -n", "/dev/x\n", "/dev/x?forkpty-arg=1", "/dev/x#y", "/dev/x&uart-baudrate=1", "/dev/%2e%2e/x", "/dev/x:y"} {
		if _, err := DaemonArgs(radio, 460800, "/s", false); err != ErrRadio {
			t.Errorf("%q: %v, want refused", radio, err)
		}
	}
	for _, baud := range []int{0, -1} {
		if _, err := DaemonArgs("/dev/x", baud, "/s", false); err != ErrRadio {
			t.Errorf("baud %d: %v, want refused", baud, err)
		}
	}
	if got, err := DaemonArgs("/dev/x", 1, "/s", true); err != nil || !slices.Contains(got, "-v") || got[len(got)-1] != "spinel+hdlc+uart:///dev/x?uart-baudrate=1" {
		t.Errorf("verbose, baud 1: %q %v", got, err)
	}
	if _, err := DaemonArgs("/dev/x", 460800, "state", false); err == nil {
		t.Error("a relative state directory was taken")
	}
}
