// Package thread runs the enforcer's Thread stack (NET-2 Confined radio
// stacks; briefs/ENF.md slice t, D-231): OpenThread's ot-daemon, built from
// the pinned source in tools/build-openthread.sh with border routing, the SRP server and
// advertising proxy and its own mDNS, confined by confine.Thread, and the
// adapter, a second confined process that is the stack's end of the radio
// host's interface. The adapter sends ot-daemon only the commands on its
// closed list (Commands) and serves only radio.Declared[radio.StackThread].
//
// ot-daemon and the Matter controller share one network namespace holding
// lo, wpan0 and a dummy infra0 (spikes/ENF-radio, consequence 1), so the
// controller resolves SRP-registered Thread devices over mDNS on infra0
// with no LAN interface. The enforcer creates that namespace's user
// namespace as root (confine, NetAdmin), never the stack.
package thread

import (
	"errors"
	"path"
	"strconv"
	"strings"
)

// Network is the device name of the Thread network itself: the one device
// the Thread stack serves. Thread devices are commanded through Matter.
const Network = "thread-network"

// Netif and Infra are the Thread interface ot-daemon creates and the
// dummy infrastructure link confine.Thread gives it.
const (
	Netif = "wpan0"
	Infra = "infra0"
)

// Socket is ot-daemon's command socket, relative to its run directory:
// tools/build-openthread.sh sets the daemon's socket base name to a relative path, and
// both processes run in that directory, the only one the adapter's view
// shows it (confine.ThreadAdapter), so it never sees the state directory.
const Socket = "openthread-" + Netif + ".sock"

// AdapterArg is the argument the enforcer's main (or a test's TestMain),
// after confine.Trampoline, hands to Adapter.
const AdapterArg = "agentos-thread-adapter"

var ErrRadio = errors.New("thread: radio path refused")

// DaemonArgs are ot-daemon's arguments for the radio (the nRF52840 RCP's
// serial device, owned by the Thread user; decision 11) at baud, and its
// state directory (owned by the Thread user, mode 0700: the network's
// dataset and keys); verbose also logs to stderr. radio must be the path
// confine.Thread binds: DaemonArgs makes the spinel URL from it, so the
// URL names no other path.
//
// The daemon (slice l) starts the stack in this order: ot-daemon under
// confine.Thread with that state directory, a run directory (owned by the
// Thread user, mode 0700) as Dir, where it makes its command socket, and
// the RCP's device; then the adapter, the enforcer's own binary with
// AdapterArg, under confine.ThreadAdapter with the same user and the run
// directory as Dir, whose interface it attaches as radio.StackThread;
// then the Matter controller under confine.Matter with its storage
// directory and Spec.Net set to ot-daemon's process. This package does not start them itself, so that
// only confine links os/exec (arc2).
func DaemonArgs(radio string, baud int, state string, verbose bool) ([]string, error) {
	// The URL is the last argument: it must not read as an option, and it
	// is the RCP's serial scheme with radio as its whole path. ot-daemon
	// forks the radio as its own child when that path is a regular file
	// (forkpty); confine.Thread's view binds radio only as a character
	// device and fails the start otherwise, with the filter's fork refusal
	// behind it (ENF-k-12). So radio is absolute, clean, and plain: no
	// character that would end the path or start a query in the URL.
	if !strings.HasPrefix(radio, "/") || path.Clean(radio) != radio || strings.Trim(radio, pathChars) != "" || baud <= 0 {
		return nil, ErrRadio
	}
	if !strings.HasPrefix(state, "/") {
		return nil, errors.New("thread: state directory must be absolute")
	}
	args := []string{"-I", Netif, "-B", Infra, "--data-path", state}
	if verbose {
		args = append(args, "-v")
	}
	return append(args, "spinel+hdlc+uart://"+radio+"?uart-baudrate="+strconv.Itoa(baud)), nil
}

// pathChars are the characters a radio path may hold.
const pathChars = "/._-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
