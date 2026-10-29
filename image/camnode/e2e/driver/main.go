// Command camnode-e2e is the camera node image's end-to-end test (CAM-node part c, #3513;
// briefs/CAM-node.md, "Part (c)" acceptance tests and the lifecycle matrix rows marked c). It
// boots the QEMU board's image (image/camnode/build.sh qemu) under QEMU aarch64, plays the
// Raspberry Pi bootloader's A/B part (vm.go), the home network (net.go), and the core and the
// enforcer with synthetic keys (node.go), and runs the tests in order on one node, as a camera
// lives: first boot, provisioning with the button, settings, restart, an update and a failed
// update. The altered-root test boots its own copy of the disk.
//
//	camnode-e2e keygen BASE
//	camnode-e2e run -out OUT [-work DIR] [-run REGEXP]
//
// run needs root in a network namespace of its own (`ip netns exec`), dnsmasq, and OUT from a
// qemu build: camnode-qemu.disk.img, .slot.img, .slot.json, e2e/release.key and br/host/bin.
//
// It is built inside the broker's module from these files (image/camnode/build.sh), as
// image/drivercheck is, so it links this checkout's camwire and camnode.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "camnode-e2e: "+format+"\n", a...)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: camnode-e2e keygen BASE | run -out OUT [-work DIR] [-run REGEXP]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: camnode-e2e keygen BASE")
			os.Exit(2)
		}
		if err := keygen(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "camnode-e2e:", err)
			os.Exit(1)
		}
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		out := fs.String("out", "", "the qemu build's output directory")
		work := fs.String("work", "", "a scratch directory (default: OUT/e2e-run)")
		only := fs.String("run", "", "run only the tests whose names match")
		fs.Parse(os.Args[2:])
		if *out == "" {
			fmt.Fprintln(os.Stderr, "run: -out is required")
			os.Exit(2)
		}
		if *work == "" {
			*work = filepath.Join(*out, "e2e-run")
		}
		if !runAll(*out, *work, *only) {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "camnode-e2e: unknown command", os.Args[1])
		os.Exit(2)
	}
}

// slotInfo is post-image.sh's camnode-qemu.slot.json.
type slotInfo struct {
	Size       uint64 `json:"size"`
	SHA256     string `json:"sha256"`
	RootOffset int64  `json:"root_offset"`
	RootLength int64  `json:"root_length"`
	Version    uint64 `json:"version"`
}

// e2e is one run's state: the node under test and the parties around it.
type e2e struct {
	out, work string
	slot      slotInfo
	keys      keys
	board     *board
	vm        *vm
	lan       *lan
	node      [camwire.PointLen]byte // the node's device key, learnt at provisioning
	fp        [32]byte
	counter   uint64 // the settings counter the node should hold
}

func (e *e2e) addr() string { return fmt.Sprintf("%s:%d", guestIP, port) }

type test struct {
	name string
	fn   func(*e2e) error
}

// The tests, in the order a camera lives through them. Each leaves the node powered and
// provisioned for the next, except where it says.
var tests = []test{
	{"test_no_shell", testNoShell},
	{"test_altered_root_does_not_boot", testAlteredRoot},
	{"test_only_stream_port", testOnlyStreamPort},
	{"test_first_bundle_needs_button", testFirstBundle},
	{"test_unsigned_settings_refused", testUnsignedSettings},
	{"test_streams_without_internet", testWithoutInternet},
	{"test_restart_keeps_state", testRestart},
	{"test_update_rollback", testUpdateRollback},
}

func runAll(out, work, only string) bool {
	rx := regexp.MustCompile(only)
	if err := os.MkdirAll(work, 0o755); err != nil {
		logf("%v", err)
		return false
	}
	e := &e2e{out: out, work: work}
	if err := e.setup(); err != nil {
		logf("setup: %v", err)
		return false
	}
	defer e.teardown()
	ok := true
	for _, t := range tests {
		if !rx.MatchString(t.name) {
			continue
		}
		start := time.Now()
		logf("=== RUN   %s", t.name)
		if err := t.fn(e); err != nil {
			ok = false
			logf("--- FAIL: %s (%v): %v", t.name, time.Since(start).Round(time.Second), err)
			if e.vm != nil {
				logf("kernel console tail (%s):\n%s", e.vm.console, tail(e.vm.kernel(), 40))
				logf("journal tail (%s):\n%s", e.vm.journal, tail(e.vm.journalLog(), 30))
			}
			// The later tests build on the node this one left; stop here.
			break
		}
		logf("--- PASS: %s (%v)", t.name, time.Since(start).Round(time.Second))
	}
	if ok {
		logf("PASS")
	} else {
		logf("FAIL")
	}
	return ok
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (e *e2e) setup() error {
	b, err := os.ReadFile(filepath.Join(e.out, "camnode-qemu.slot.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &e.slot); err != nil {
		return err
	}
	if e.keys.release, err = loadRelease(filepath.Join(e.out, "e2e", "release")); err != nil {
		return err
	}
	e.keys.owner = passkey{newKey()}
	e.keys.core, e.keys.enforcer = newKey(), newKey()
	disk := filepath.Join(e.work, "disk.img")
	if err := copyFile(filepath.Join(e.out, "camnode-qemu.disk.img"), disk); err != nil {
		return err
	}
	element := filepath.Join(e.work, "element.raw")
	if err := os.WriteFile(element, make([]byte, 1<<20), 0o600); err != nil {
		return err
	}
	e.board = newBoard(filepath.Join(e.out, "br", "host", "bin"), e.work, disk, element, tapName)
	e.lan, err = setupLAN(e.work, e.board.mac)
	return err
}

func (e *e2e) teardown() {
	if e.vm != nil {
		e.vm.cut()
	}
	if e.lan != nil {
		e.lan.close()
	}
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// up powers the node (after a power cut if it is running) and waits for its port.
func (e *e2e) up(button bool) error {
	if e.vm != nil {
		e.vm.cut()
	}
	v, err := e.board.power(button)
	if err != nil {
		return err
	}
	e.vm = v
	return e.ready()
}

// ready waits for the node's service and its port on the current boot.
func (e *e2e) ready() error {
	if err := e.vm.wait(`camnode-init: slot \d+ root [0-9a-f]{64} verified, mounted read-only \(erofs\)`, 3*time.Minute); err != nil {
		return err
	}
	if err := e.vm.wait(`Started agentos-camnode\.service|Started agentOS camera node`, 3*time.Minute); err != nil {
		return err
	}
	return waitPort(2 * time.Minute)
}

// enforcer opens the settings channel and reads the status the node sends first.
func (e *e2e) enforcer() (*conn, camwire.Status, error) {
	c, _, err := dial(e.addr(), e.keys.enforcer, &e.node)
	if err != nil {
		return nil, camwire.Status{}, err
	}
	st, err := c.status(30 * time.Second)
	if err != nil {
		c.close()
		return nil, st, fmt.Errorf("no status on the settings channel: %w", err)
	}
	return c, st, nil
}

func (e *e2e) bundle(counter uint64) camwire.Bundle {
	return camwire.Bundle{
		Node: e.fp, Counter: counter, Owner: e.keys.owner.owner(),
		Core: pointOf(&e.keys.core.PublicKey), Enforcer: pointOf(&e.keys.enforcer.PublicKey),
		Settings: camwire.Settings{Width: 1280, Height: 720, FPS: 15, BitrateKbps: 2000, IR: camwire.IROff, Stream: true},
	}
}

// frames reads video frames on the core's stream for d and returns how many arrived.
func (e *e2e) frames(d time.Duration) (int, error) {
	c, _, err := dial(e.addr(), e.keys.core, &e.node)
	if err != nil {
		return 0, err
	}
	defer c.close()
	n := 0
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		f, err := c.readFrame(camwire.ToCore, 10*time.Second)
		if err != nil {
			return n, err
		}
		if f.Type == camwire.TypeVideo {
			n++
		}
	}
	return n, nil
}

// testNoShell reads the shipped root out of the slot image: no shell, getty, sshd or console
// login, and the root is erofs, which Linux mounts read-only only.
func testNoShell(e *e2e) error {
	slot, err := os.Open(filepath.Join(e.out, "camnode-qemu.slot.img"))
	if err != nil {
		return err
	}
	defer slot.Close()
	root := make([]byte, e.slot.RootLength)
	if _, err := slot.ReadAt(root, e.slot.RootOffset); err != nil {
		return err
	}
	// erofs: the superblock's magic 0xE0F5E1E2 at byte 1024.
	if len(root) < 1028 || !bytes.Equal(root[1024:1028], []byte{0xE2, 0xE1, 0xF5, 0xE0}) {
		return errors.New("the slot's root is not erofs")
	}
	img := filepath.Join(e.work, "root.erofs")
	if err := os.WriteFile(img, root, 0o600); err != nil {
		return err
	}
	tree := filepath.Join(e.work, "root")
	os.RemoveAll(tree)
	if out, err := exec.Command(e.board.tool("fsck.erofs"), "--extract="+tree, "--no-preserve", img).CombinedOutput(); err != nil {
		return fmt.Errorf("fsck.erofs: %v: %s", err, out)
	}
	barred := map[string]bool{}
	for _, n := range strings.Fields("sh bash dash ash zsh ksh busybox toybox sshd ssh dropbear telnetd login agetty getty sulogin su sudo nc socat systemd-sulogin-shell getty@.service serial-getty@.service console-getty.service debug-shell.service") {
		barred[n] = true
	}
	var found []string
	filepath.Walk(tree, func(p string, fi os.FileInfo, err error) error {
		if err == nil && barred[fi.Name()] {
			found = append(found, strings.TrimPrefix(p, tree))
		}
		return nil
	})
	if len(found) > 0 {
		return fmt.Errorf("the root holds %v", found)
	}
	for _, need := range []string{"usr/bin/agentos-camnode", "etc/camnode/firewall.nft", "usr/share/agentos/camnode-release.pub"} {
		if _, err := os.Stat(filepath.Join(tree, need)); err != nil {
			return fmt.Errorf("the root lacks %s", need)
		}
	}
	return nil
}

// testAlteredRoot flips one byte in slot A's root on a copy of the disk: the board restarts
// before systemd, and never serves.
func testAlteredRoot(e *e2e) error {
	disk := filepath.Join(e.work, "altered.img")
	if err := copyFile(e.board.disk, disk); err != nil {
		return err
	}
	parts, err := partitions(disk)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(disk, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	at := parts[1].off + e.slot.RootOffset + e.slot.RootLength/2
	var b [1]byte
	f.ReadAt(b[:], at)
	b[0] ^= 0x01
	f.WriteAt(b[:], at)
	f.Close()
	el := filepath.Join(e.work, "altered-element.raw")
	if err := os.WriteFile(el, make([]byte, 1<<20), 0o600); err != nil {
		return err
	}
	ab := newBoard(e.board.tools, filepath.Join(e.work, "altered"), disk, el, tapName)
	ab.mac = e.board.mac
	v, err := ab.power(false)
	if err != nil {
		return err
	}
	e.vm = v
	cmd, err := v.stopped(ab, 4*time.Minute)
	if err != nil {
		return err
	}
	log := v.log()
	if strings.Contains(log, "verified, mounted read-only") || strings.Contains(log, "systemd[1]") {
		return errors.New("the altered root started")
	}
	// dm-verity's own report of the flipped block, not any other early failure.
	if !regexp.MustCompile(`device-mapper: verity: [^\n]*data block \d+ is corrupted`).MatchString(log) {
		return errors.New("the board restarted, but not on a verity failure")
	}
	logf("altered root: restarted (%q) before systemd", cmd)
	e.vm = nil
	return nil
}

// testOnlyStreamPort is the first boot: no bundle, the button not held. A TCP and UDP scan
// from the home network finds the stream port only, and the port refuses every client.
func testOnlyStreamPort(e *e2e) error {
	if err := e.up(false); err != nil {
		return err
	}
	if !refused(e.addr(), newKey()) {
		return errors.New("an unprovisioned node admitted an unknown key")
	}
	capt, err := startCapture(e.board.mac)
	if err != nil {
		return err
	}
	open := scanTCP()
	if err := scanUDP(); err != nil {
		capt.stop()
		return err
	}
	time.Sleep(3 * time.Second)
	odd, _ := capt.stop()
	if len(open) != 1 || open[0] != port {
		return fmt.Errorf("open TCP ports %s, want %d only", joinPorts(open), port)
	}
	if len(odd) > 0 {
		return fmt.Errorf("the node answered the scan or sent other traffic: %v", odd)
	}
	logf("scan: TCP %s open; no UDP or ICMP answer", joinPorts(open))
	return nil
}

// testFirstBundle: with the button held at power-on the first bundle is taken once, from
// whoever presents it as its enforcer; without the button it is not.
func testFirstBundle(e *e2e) error {
	// Without the button: nothing is admitted.
	if !refused(e.addr(), e.keys.enforcer) {
		return errors.New("an unprovisioned node admitted the enforcer without the button")
	}
	if err := e.up(true); err != nil {
		return err
	}
	c, node, err := dial(e.addr(), e.keys.enforcer, nil)
	if err != nil {
		return fmt.Errorf("handshake in the first-bundle window: %w", err)
	}
	e.node, e.fp = node, camwire.Fingerprint(node)
	e.counter = 1
	if err := c.send(camwire.TypeBundle, e.keys.owner.signBundle(e.bundle(e.counter))); err != nil {
		c.close()
		return err
	}
	st, err := c.status(30 * time.Second)
	c.close()
	if err != nil {
		return fmt.Errorf("no status after the first bundle: %w", err)
	}
	if st.Settings != e.counter {
		return fmt.Errorf("settings counter %d after the first bundle, want %d", st.Settings, e.counter)
	}
	// The window closed: a second first-bundle from another key is refused.
	if !refused(e.addr(), newKey()) {
		return errors.New("a second key was admitted after the first bundle")
	}
	// Normal start: power-cycled without the button, the core gets the stream.
	if err := e.up(false); err != nil {
		return err
	}
	n, err := e.frames(10 * time.Second)
	if err != nil || n < 10 {
		return fmt.Errorf("%d video frames in 10 s after provisioning (%v)", n, err)
	}
	logf("provisioned node %x; %d frames in 10 s", e.fp[:8], n)
	return nil
}

// testUnsignedSettings: a bundle without the owner's valid assertion, or with an old counter,
// is refused and the settings stay; a valid one is the control.
func testUnsignedSettings(e *e2e) error {
	try := func(p []byte) (camwire.Status, error) {
		c, _, err := e.enforcer()
		if err != nil {
			return camwire.Status{}, err
		}
		defer c.close()
		if err := c.send(camwire.TypeBundle, p); err != nil {
			return camwire.Status{}, err
		}
		return c.status(15 * time.Second)
	}
	stranger := passkey{newKey()}
	// Another passkey's assertion over a bundle naming the pinned owner.
	if st, err := try(stranger.signBundle(e.bundle(e.counter + 1))); err == nil {
		return fmt.Errorf("a bundle signed by another passkey was applied (counter %d)", st.Settings)
	}
	// The owner's assertion over a different bundle.
	good := e.keys.owner.signBundle(e.bundle(e.counter + 1))
	sb, _, err := camwire.ParseSignedBundle(good)
	if err != nil {
		return err
	}
	other, _ := e.bundle(e.counter + 2).Encode()
	forged, err := camwire.SignedBundle{Bundle: other, Assertion: sb.Assertion}.Encode()
	if err != nil {
		return err
	}
	if _, err := try(forged); err == nil {
		return errors.New("a bundle carrying another bundle's assertion was applied")
	}
	// The owner's bundle at the counter the node holds (a replay).
	if _, err := try(e.keys.owner.signBundle(e.bundle(e.counter))); err == nil {
		return errors.New("a bundle at the node's own counter was applied")
	}
	c, st, err := e.enforcer()
	if err != nil {
		return err
	}
	c.close()
	if st.Settings != e.counter {
		return fmt.Errorf("refused bundles moved the counter to %d", st.Settings)
	}
	// Control: the owner's next bundle is applied.
	st, err = try(good)
	if err != nil {
		return fmt.Errorf("the owner's valid bundle was refused: %w", err)
	}
	e.counter++
	if st.Settings != e.counter {
		return fmt.Errorf("counter %d after a valid bundle, want %d", st.Settings, e.counter)
	}
	return nil
}

// testWithoutInternet: the namespace has no route beyond the host, and the node's lease names
// the host as its router, so any packet towards the internet would show on the tap. While the
// core streams for 30 s the node sends only the stream's segments, ARP and DHCP.
func testWithoutInternet(e *e2e) error {
	capt, err := startCapture(e.board.mac)
	if err != nil {
		return err
	}
	n, ferr := e.frames(30 * time.Second)
	odd, segs := capt.stop()
	if ferr != nil || n < 30 {
		return fmt.Errorf("%d video frames in 30 s with no internet (%v)", n, ferr)
	}
	if len(odd) > 0 {
		return fmt.Errorf("the node sent traffic other than the stream, ARP and DHCP: %v", odd)
	}
	logf("no internet: %d frames, %d stream segments, nothing else sent", n, segs)
	return nil
}

// testRestart: after a power cut the node has the same key, bundle and counter, and streams.
func testRestart(e *e2e) error {
	if err := e.up(false); err != nil {
		return err
	}
	c, st, err := e.enforcer() // pinned to the key learnt at provisioning
	if err != nil {
		return err
	}
	c.close()
	if st.Settings != e.counter {
		return fmt.Errorf("counter %d after restart, want %d", st.Settings, e.counter)
	}
	if n, err := e.frames(10 * time.Second); err != nil || n < 10 {
		return fmt.Errorf("%d frames after restart (%v)", n, err)
	}
	return nil
}

// testUpdateRollback: an approved update is written to the inactive slot, tried once, marked
// good and kept; an approved update whose root does not verify is tried once and the board
// returns to the slot before; an update at the node's own image counter is refused.
func testUpdateRollback(e *e2e) error {
	good, err := os.ReadFile(filepath.Join(e.out, "camnode-qemu.slot.img"))
	if err != nil {
		return err
	}
	goodSum := sha256.Sum256(good)
	from := e.vm.part
	if err := e.update(good, 1); err != nil {
		return err
	}
	// The trial boot of the other slot.
	if err := e.reboot(); err != nil {
		return err
	}
	if !e.vm.trial || e.vm.part == from {
		return fmt.Errorf("after the update the board booted partition %d (trial %v), want the other slot on trial", e.vm.part, e.vm.trial)
	}
	if err := e.ready(); err != nil {
		return err
	}
	if err := e.vm.wait(`update kept|image marked good|marked good`, time.Minute); err != nil {
		logf("note: no mark-good line on the console: %v", err)
	}
	c, st, err := e.enforcer()
	if err != nil {
		return err
	}
	c.close()
	if st.Image != goodSum {
		return fmt.Errorf("running image %x after the update, want %x", st.Image[:8], goodSum[:8])
	}
	// Kept: the next power-on boots the new slot by default.
	newSlot := e.vm.part
	if err := e.up(false); err != nil {
		return err
	}
	if e.vm.part != newSlot || e.vm.trial {
		return fmt.Errorf("the kept update is not the default: booted %d (trial %v), want %d", e.vm.part, e.vm.trial, newSlot)
	}
	if n, err := e.frames(5 * time.Second); err != nil || n < 5 {
		return fmt.Errorf("%d frames on the updated slot (%v)", n, err)
	}

	// An update whose root does not verify: tried once, then the slot before.
	bad := append([]byte(nil), good...)
	bad[e.slot.RootOffset+e.slot.RootLength/3] ^= 0x01
	if err := e.update(bad, 2); err != nil {
		return err
	}
	if err := e.reboot(); err != nil {
		return err
	}
	if !e.vm.trial || e.vm.part == newSlot {
		return fmt.Errorf("the bad update booted partition %d (trial %v), want the other slot on trial", e.vm.part, e.vm.trial)
	}
	cmd, err := e.vm.stopped(e.board, 4*time.Minute)
	if err != nil {
		return fmt.Errorf("the bad update's trial did not restart: %w", err)
	}
	if e.board.tryboot {
		return fmt.Errorf("the bad update's trial restarted asking for tryboot (%q)", cmd)
	}
	v, err := e.board.power(false)
	if err != nil {
		return err
	}
	e.vm = v
	if e.vm.part != newSlot || e.vm.trial {
		return fmt.Errorf("after the failed trial the board booted %d (trial %v), want %d", e.vm.part, e.vm.trial, newSlot)
	}
	if err := e.ready(); err != nil {
		return err
	}
	c, st, err = e.enforcer()
	if err != nil {
		return err
	}
	c.close()
	if st.Image != goodSum {
		return fmt.Errorf("running image %x after the failed trial, want %x", st.Image[:8], goodSum[:8])
	}

	// An update at the node's own image counter (1, the kept one's) is refused: no restart.
	if err := e.update(good, 1); err == nil {
		if _, err := e.vm.stopped(e.board, 30*time.Second); err == nil {
			return errors.New("an update at the node's own image counter restarted the board")
		}
		return errors.New("an update at the node's own image counter was staged")
	}
	if err := waitPort(30 * time.Second); err != nil {
		return err
	}
	return nil
}

// update sends a manifest for img at counter, approved by the owner, then img, and returns nil
// once the node reports the update staged (the status it sends before restarting).
func (e *e2e) update(img []byte, counter uint64) error {
	sum := sha256.Sum256(img)
	m := camwire.Manifest{Image: sum, Size: uint64(len(img)), Version: e.slot.Version + counter, Counter: counter, Nodes: [][32]byte{e.fp}}
	c, _, err := e.enforcer()
	if err != nil {
		return err
	}
	defer c.close()
	if err := c.send(camwire.TypeManifest, e.keys.signManifest(m, e.keys.owner)); err != nil {
		return err
	}
	for off := 0; off < len(img); off += camwire.MaxImage {
		end := min(off+camwire.MaxImage, len(img))
		if err := c.send(camwire.TypeImage, img[off:end]); err != nil {
			return fmt.Errorf("image refused at byte %d: %w", off, err)
		}
	}
	if _, err := c.status(2 * time.Minute); err != nil {
		return fmt.Errorf("no status after the image: %w", err)
	}
	return nil
}

// reboot waits for the node's own restart and powers the board as the bootloader would.
func (e *e2e) reboot() error {
	cmd, err := e.vm.stopped(e.board, 2*time.Minute)
	if err != nil {
		return err
	}
	logf("node restarted (%q), tryboot %v", cmd, e.board.tryboot)
	v, err := e.board.power(false)
	if err != nil {
		return err
	}
	e.vm = v
	return nil
}
