package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// board is the QEMU board with the Raspberry Pi bootloader's part played by the harness: at each
// power-on it reads autoboot.txt from the disk's first partition, picks the [all] partition, or
// the [tryboot] one when the last restart asked for it, takes boot.img from that partition and
// the kernel, command line and initramfs from boot.img, and starts the kernel with a device tree
// whose /chosen/bootloader node names the partition and the tryboot flag, as the Pi firmware's
// does (camnode ASSUMPTIONS CAM-bin-2). It does not check boot.sig: signed boot is part d's, on
// the board.
//
// The restart reaches the harness as it reaches the Pi firmware, not through the console: QEMU
// reports the reset itself on QMP, and the restart command is a word the kernel's reboot-mode
// notifier writes into a firmware page before any device shuts down (mailbox), as the Pi's
// firmware driver passes tryboot to the firmware from its reboot notifier. The console's
// "reboot: Restarting system" line is not a signal: with two CPUs Linux loses it whenever another
// CPU owns the console at that moment (#6407).
type board struct {
	tools   string // Buildroot's host/bin: qemu-system-aarch64, mcopy, fdtput
	work    string
	disk    string // the node's disk (vda)
	element string // the element stand-in's store (vdb)
	tap     string
	mac     string
	tryboot bool // the last restart asked for the one-shot partition
	boots   int
	append  string // added to the kernel command line (test_panic_is_reported)
}

// vm is one power-on of the board.
type vm struct {
	cmd     *exec.Cmd
	dir     string
	console string // the kernel's serial console (ttyAMA0)
	journal string // the journal's console (hvc0), kept off the kernel's
	part    int
	trial   bool
	done    chan error // qemu's exit
	qmp     *qmp
}

// The firmware page: the last page of the board's 1 GiB, reserved no-map in the device tree (QEMU
// rewrites /memory itself, so the page stays in it) and given to the syscon-reboot-mode driver as
// one 32-bit register. The kernel's
// reboot notifier writes the word for a restart command it knows, before device_shutdown; the
// guest's RAM starts zeroed at every power-on, so the word is 0 unless this boot asked.
const (
	ramBase, ramSize = 0x40000000, 1 << 30
	mailbox          = ramBase + ramSize - 0x1000
)

// restartCmds are the restart commands the mailbox carries, by word: agentos-camnode's reboot
// ("0 tryboot", sys_linux.go; vm_test.go reads it there) and dm-verity's restart_on_corruption.
// A restart with any other command, or none, leaves 0. Device-tree names cannot hold a space; the
// kernel matches "mode-0-tryboot" to "0 tryboot".
var restartCmds = map[uint32]string{1: "0 tryboot", 2: "dm-verity device corrupted"}

// errPanic is a kernel panic. A panic restarts the board (panic=5) through emergency_restart,
// which skips the reboot notifiers, so the mailbox reads 0 as for a plain restart; the pvpanic
// device tells it apart instead: the kernel's panic notifier writes to it, and QEMU pauses the
// board and sends GUEST_PANICKED before the panic's restart.
var errPanic = errors.New("the kernel panicked")

func newBoard(tools, work, disk, element, tap string) *board {
	return &board{tools: tools, work: work, disk: disk, element: element, tap: tap, mac: "52:54:00:ca:4e:01"}
}

func (b *board) tool(name string) string { return filepath.Join(b.tools, name) }

// partition is one MBR entry: its byte offset and length.
type partition struct{ off, len int64 }

func partitions(disk string) ([]partition, error) {
	f, err := os.Open(disk)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var mbr [512]byte
	if _, err := f.ReadAt(mbr[:], 0); err != nil {
		return nil, err
	}
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil, errors.New("no MBR")
	}
	var out []partition
	for i := range 4 {
		e := mbr[446+16*i:]
		out = append(out, partition{
			off: int64(binary.LittleEndian.Uint32(e[8:])) * 512,
			len: int64(binary.LittleEndian.Uint32(e[12:])) * 512,
		})
	}
	return out, nil
}

// fatRead reads one file from the FAT image at img (or the FAT at offset inside it).
func (b *board) fatRead(img string, off int64, name string) ([]byte, error) {
	spec := img
	if off > 0 {
		spec = fmt.Sprintf("%s@@%d", img, off)
	}
	cmd := exec.Command(b.tool("mcopy"), "-n", "-i", spec, "::"+name, "-")
	cmd.Env = append(os.Environ(), "MTOOLS_SKIP_CHECK=1")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mcopy %s from %s: %v: %s", name, spec, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// autoboot parses autoboot.txt as the bootloader does for tryboot_a_b: boot_partition under
// [all] and under [tryboot].
func autoboot(p []byte) (def, try int, err error) {
	section := "all"
	for _, line := range strings.Split(string(p), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k != "boot_partition" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, err
		}
		switch section {
		case "all":
			def = n
		case "tryboot":
			try = n
		}
	}
	if def == 0 {
		return 0, 0, errors.New("autoboot.txt names no default partition")
	}
	return def, try, nil
}

func (b *board) qemuArgs(button bool) []string {
	flag := "0"
	if button {
		flag = "1"
	}
	return []string{
		"-machine", "virt", "-cpu", "cortex-a72", "-smp", "2", "-m", strconv.Itoa(ramSize >> 20),
		"-nodefaults", "-display", "none", "-no-reboot",
		"-drive", "if=none,id=disk,format=raw,file=" + b.disk,
		"-device", "virtio-blk-pci,drive=disk,addr=0x4",
		"-drive", "if=none,id=element,format=raw,file=" + b.element,
		"-device", "virtio-blk-pci,drive=element,addr=0x5",
		"-netdev", "tap,id=net,ifname=" + b.tap + ",script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=net,mac=" + b.mac + ",addr=0x6",
		"-fw_cfg", "name=opt/camnode/button,string=" + flag,
		"-device", "pvpanic-pci,addr=0x8",
	}
}

// inMemory checks that the mailbox page lies inside the RAM that the /memory node's reg (two
// address cells, two size cells, as fdtget prints them in hex) describes: the page the kernel
// writes and the page pmemsave reads must be guest RAM, not a hole.
func inMemory(reg string) error {
	f := strings.Fields(reg)
	if len(f) == 0 || len(f)%4 != 0 {
		return fmt.Errorf("/memory reg %q", reg)
	}
	for i := 0; i < len(f); i += 4 {
		var c [4]uint64
		for j := range c {
			n, err := strconv.ParseUint(f[i+j], 16, 32)
			if err != nil {
				return fmt.Errorf("/memory reg %q: %v", reg, err)
			}
			c[j] = n
		}
		base, size := c[0]<<32|c[1], c[2]<<32|c[3]
		if base <= mailbox && mailbox+0x1000 <= base+size {
			return nil
		}
	}
	return fmt.Errorf("the mailbox page %#x is outside /memory (reg %q)", mailbox, reg)
}

// power starts the board, as the bootloader would after power-on or a restart.
func (b *board) power(button bool) (*vm, error) {
	parts, err := partitions(b.disk)
	if err != nil {
		return nil, err
	}
	sel, err := b.fatRead(b.disk, parts[0].off, "autoboot.txt")
	if err != nil {
		return nil, err
	}
	def, try, err := autoboot(sel)
	if err != nil {
		return nil, err
	}
	part, trial := def, false
	if b.tryboot && try != 0 {
		part, trial = try, true
	}
	b.tryboot = false // the flag is one-shot
	if part < 1 || part > 4 {
		return nil, fmt.Errorf("boot partition %d", part)
	}
	b.boots++
	dir := filepath.Join(b.work, fmt.Sprintf("boot%02d", b.boots))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	bootimg, err := b.fatRead(b.disk, parts[part-1].off, "boot.img")
	if err != nil {
		if trial {
			// The Pi bootloader returns to the default partition when the one-shot has no
			// boot image; so does this one.
			b.tryboot = false
			return b.power(button)
		}
		return nil, err
	}
	bi := filepath.Join(dir, "boot.img")
	if err := os.WriteFile(bi, bootimg, 0o644); err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, n := range []string{"Image", "cmdline.txt", "camnode-initramfs.cpio"} {
		p, err := b.fatRead(bi, 0, n)
		if err != nil {
			return nil, err
		}
		files[n] = filepath.Join(dir, n)
		if err := os.WriteFile(files[n], p, 0o644); err != nil {
			return nil, err
		}
	}
	cmdline, err := os.ReadFile(files["cmdline.txt"])
	if err != nil {
		return nil, err
	}
	dtb := filepath.Join(dir, "board.dtb")
	args := b.qemuArgs(button)
	dump := exec.Command(b.tool("qemu-system-aarch64"), append(append([]string{}, args...),
		"-machine", "virt,dumpdtb="+dtb)...)
	if out, err := dump.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("dumpdtb: %v: %s", err, out)
	}
	reg, err := exec.Command(b.tool("fdtget"), "-t", "x", dtb, fmt.Sprintf("/memory@%x", ramBase), "reg").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fdtget /memory: %v: %s", err, reg)
	}
	if err := inMemory(string(reg)); err != nil {
		return nil, err
	}
	tb := "0"
	if trial {
		tb = "1"
	}
	hex := func(v uint64) string { return strconv.FormatUint(v, 16) }
	box := fmt.Sprintf("/camnode-firmware@%x", mailbox)
	set := [][]string{
		{"-c", dtb, "/chosen/bootloader"},
		{"-t", "x", dtb, "/chosen/bootloader", "partition", strconv.FormatInt(int64(part), 16)},
		{"-t", "x", dtb, "/chosen/bootloader", "tryboot", tb},
		{"-p", "-c", dtb, fmt.Sprintf("/reserved-memory/camnode-firmware@%x", mailbox)},
		{"-t", "x", dtb, "/reserved-memory", "#address-cells", "2"},
		{"-t", "x", dtb, "/reserved-memory", "#size-cells", "2"},
		{"-t", "x", dtb, "/reserved-memory", "ranges"},
		{"-t", "x", dtb, fmt.Sprintf("/reserved-memory/camnode-firmware@%x", mailbox), "reg", "0", hex(mailbox), "0", "1000"},
		{"-t", "x", dtb, fmt.Sprintf("/reserved-memory/camnode-firmware@%x", mailbox), "no-map"},
		{"-p", "-c", dtb, box + "/reboot-mode"},
		{"-t", "s", dtb, box, "compatible", "syscon", "simple-mfd"},
		{"-t", "x", dtb, box, "reg", "0", hex(mailbox), "0", "1000"},
		{"-t", "s", dtb, box + "/reboot-mode", "compatible", "syscon-reboot-mode"},
		{"-t", "x", dtb, box + "/reboot-mode", "offset", "0"},
	}
	for w, c := range restartCmds {
		set = append(set, []string{"-t", "x", dtb, box + "/reboot-mode", "mode-" + strings.ReplaceAll(c, " ", "-"), hex(uint64(w))})
	}
	for _, a := range set {
		if out, err := exec.Command(b.tool("fdtput"), a...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("fdtput %v: %v: %s", a, err, out)
		}
	}
	console, journal := filepath.Join(dir, "console.log"), filepath.Join(dir, "journal.log")
	ln, err := qmpListen(dir)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	sock := ln.Addr().String()
	// -no-reboot with shutdown=pause: a guest reset stops the board and QEMU says why on QMP,
	// keeping its memory for the mailbox; panic=pause: a panic the pvpanic device reports stops
	// it too, with the GUEST_PANICKED event (with shutdown=pause QEMU pauses on a panic whatever
	// the panic action, and sends no SHUTDOWN). -S: the board starts only once QMP is listening.
	args = append(args,
		"-kernel", files["Image"], "-initrd", files["camnode-initramfs.cpio"],
		"-append", strings.TrimSpace(strings.TrimSpace(string(cmdline))+" "+b.append), "-dtb", dtb,
		"-serial", "file:"+console, "-monitor", "none",
		"-device", "virtio-serial-pci,addr=0x7", "-chardev", "file,id=journal,path="+journal,
		"-device", "virtconsole,chardev=journal",
		"-action", "shutdown=pause", "-action", "panic=pause", "-S",
		"-chardev", "socket,id=qmp,path="+sock, "-mon", "chardev=qmp,mode=control")
	cmd := exec.Command(b.tool("qemu-system-aarch64"), args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	v := &vm{cmd: cmd, dir: dir, console: console, journal: journal, part: part, trial: trial, done: make(chan error, 1)}
	go func() { v.done <- cmd.Wait() }()
	ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.AcceptUnix()
	if err == nil {
		v.qmp, err = newQMP(conn)
	}
	if err == nil {
		err = v.qmp.run("cont", nil)
	}
	if err != nil {
		v.cut()
		return nil, fmt.Errorf("qmp: %w", err)
	}
	logf("boot %d: partition %d, tryboot %v, console %s", b.boots, part, trial, console)
	return v, nil
}

// qmpListen listens for QEMU's QMP connection on a socket in a new directory under dir that
// only the harness's user can enter (MkdirTemp: 0700), so no other user's process on the runner can reach
// the socket and drive the board. Closing the listener removes the socket.
func qmpListen(dir string) (*net.UnixListener, error) {
	private, err := os.MkdirTemp(dir, "qmp")
	if err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(private, "qmp.sock"), Net: "unix"})
}

// qmp is QEMU's machine protocol on one connection: the reader keeps the SHUTDOWN event's reason
// (or guest-panic for GUEST_PANICKED) and passes command replies on.
type qmp struct {
	conn    net.Conn
	replies chan map[string]json.RawMessage
	halted  chan struct{} // closed on the guest's SHUTDOWN or GUEST_PANICKED, or when QEMU closes the connection
	reason  string        // the SHUTDOWN's reason (guest-reset, guest-shutdown, ...), or guest-panic for GUEST_PANICKED
}

func newQMP(conn net.Conn) (*qmp, error) {
	q := &qmp{conn: conn, replies: make(chan map[string]json.RawMessage, 4), halted: make(chan struct{})}
	dec := json.NewDecoder(bufio.NewReader(conn))
	var greeting map[string]json.RawMessage
	if err := dec.Decode(&greeting); err != nil || greeting["QMP"] == nil {
		conn.Close()
		return nil, fmt.Errorf("no greeting (%v)", err)
	}
	go func() {
		once := false
		halt := func() {
			if !once {
				once = true
				close(q.halted)
			}
		}
		defer close(q.replies)
		defer halt()
		for {
			var m map[string]json.RawMessage
			if dec.Decode(&m) != nil {
				return
			}
			if ev, ok := m["event"]; ok {
				switch {
				case once:
				case string(ev) == `"SHUTDOWN"`:
					var d struct{ Reason string }
					json.Unmarshal(m["data"], &d)
					q.reason = d.Reason
					halt()
				case string(ev) == `"GUEST_PANICKED"`:
					// The pvpanic device's report: QEMU has paused the board and sends no SHUTDOWN.
					q.reason = "guest-panic"
					halt()
				}
				continue
			}
			q.replies <- m
		}
	}()
	return q, q.run("qmp_capabilities", nil)
}

// run sends one command and waits for its reply.
func (q *qmp) run(execute string, args any) error {
	c := map[string]any{"execute": execute}
	if args != nil {
		c["arguments"] = args
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := q.conn.Write(b); err != nil {
		return err
	}
	select {
	case m, ok := <-q.replies:
		if !ok {
			return fmt.Errorf("%s: qemu closed the connection", execute)
		}
		if e, bad := m["error"]; bad {
			return fmt.Errorf("%s: %s", execute, e)
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("%s: no reply", execute)
	}
}

// log is the kernel's console then the journal.
func (v *vm) log() string {
	return v.kernel() + v.journalLog()
}

func (v *vm) kernel() string {
	b, _ := os.ReadFile(v.console)
	return string(b)
}

func (v *vm) journalLog() string {
	b, _ := os.ReadFile(v.journal)
	return string(b)
}

// wait waits for re to match the console, failing early if the board stops.
func (v *vm) wait(re string, timeout time.Duration) error {
	rx := regexp.MustCompile(re)
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if rx.MatchString(v.log()) {
			return nil
		}
		select {
		case <-v.qmp.halted:
			if rx.MatchString(v.log()) {
				return nil
			}
			if v.qmp.reason == "guest-panic" {
				return fmt.Errorf("%w before %q", errPanic, re)
			}
			return fmt.Errorf("board stopped (%q) before %q", v.qmp.reason, re)
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("no %q on the console within %v", re, timeout)
}

// stopped waits for the board to restart by itself and returns the restart command the mailbox
// names ("" for one it does not know, or none), recording whether it asked for tryboot, as the
// Pi firmware reads the reboot argument. QEMU's SHUTDOWN reason tells a restart (guest-reset)
// from a kernel panic (errPanic), a power-off or anything else. Every handle the run holds is
// released on every path: QEMU is told to quit, or killed, and the QMP connection is closed.
func (v *vm) stopped(b *board, timeout time.Duration) (restart string, err error) {
	select {
	case <-v.qmp.halted:
	case <-time.After(timeout):
		v.cut()
		return "", fmt.Errorf("board did not restart within %v", timeout)
	}
	// The guest has stopped: QEMU is told to quit, as it would have exited at the reset, and
	// whatever is left (the process if quit failed, the connection always) goes with cut.
	defer func() {
		if v.qmp.run("quit", nil) == nil {
			select {
			case err := <-v.done:
				v.done <- err
			case <-time.After(10 * time.Second):
			}
		}
		v.cut()
	}()
	switch v.qmp.reason {
	case "guest-reset":
	case "guest-panic":
		return "", errPanic
	default:
		return "", fmt.Errorf("board stopped without restarting (qemu: %q)", v.qmp.reason)
	}
	word := filepath.Join(v.dir, "mailbox")
	if err := v.qmp.run("pmemsave", map[string]any{"val": mailbox, "size": 4, "filename": word}); err != nil {
		return "", err
	}
	p, err := os.ReadFile(word)
	if err != nil || len(p) != 4 {
		return "", fmt.Errorf("mailbox: %v", err)
	}
	w := binary.LittleEndian.Uint32(p)
	restart, known := restartCmds[w]
	if w != 0 && !known {
		return "", fmt.Errorf("mailbox word %#x", w)
	}
	b.tryboot = restart == "0 tryboot"
	return restart, nil
}

// cut is a power cut: the process is killed, the disk keeps what was written.
func (v *vm) cut() {
	if v.cmd.Process != nil {
		v.cmd.Process.Kill()
	}
	select {
	case err := <-v.done:
		v.done <- err
	case <-time.After(10 * time.Second):
	}
	if v.qmp != nil {
		v.qmp.conn.Close()
	}
}
