package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
type board struct {
	tools   string // Buildroot's host/bin: qemu-system-aarch64, mcopy, fdtput
	work    string
	disk    string // the node's disk (vda)
	element string // the element stand-in's store (vdb)
	tap     string
	mac     string
	tryboot bool // the last restart asked for the one-shot partition
	boots   int
}

// vm is one power-on of the board.
type vm struct {
	cmd     *exec.Cmd
	console string // the kernel's serial console (ttyAMA0)
	journal string // the journal's console (hvc0), kept off the kernel's (see stopped)
	part    int
	trial   bool
	done    chan error
}

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
		"-machine", "virt", "-cpu", "cortex-a72", "-smp", "2", "-m", "1024",
		"-nodefaults", "-display", "none", "-no-reboot",
		"-drive", "if=none,id=disk,format=raw,file=" + b.disk,
		"-device", "virtio-blk-pci,drive=disk,addr=0x4",
		"-drive", "if=none,id=element,format=raw,file=" + b.element,
		"-device", "virtio-blk-pci,drive=element,addr=0x5",
		"-netdev", "tap,id=net,ifname=" + b.tap + ",script=no,downscript=no",
		"-device", "virtio-net-pci,netdev=net,mac=" + b.mac + ",addr=0x6",
		"-fw_cfg", "name=opt/camnode/button,string=" + flag,
	}
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
	tb := "0"
	if trial {
		tb = "1"
	}
	for _, a := range [][]string{
		{"-c", dtb, "/chosen/bootloader"},
		{"-t", "x", dtb, "/chosen/bootloader", "partition", strconv.FormatInt(int64(part), 16)},
		{"-t", "x", dtb, "/chosen/bootloader", "tryboot", tb},
	} {
		if out, err := exec.Command(b.tool("fdtput"), a...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("fdtput %v: %v: %s", a, err, out)
		}
	}
	console, journal := filepath.Join(dir, "console.log"), filepath.Join(dir, "journal.log")
	args = append(args,
		"-kernel", files["Image"], "-initrd", files["camnode-initramfs.cpio"],
		"-append", strings.TrimSpace(string(cmdline)), "-dtb", dtb,
		"-serial", "file:"+console, "-monitor", "none",
		"-device", "virtio-serial-pci,addr=0x7", "-chardev", "file,id=journal,path="+journal,
		"-device", "virtconsole,chardev=journal")
	cmd := exec.Command(b.tool("qemu-system-aarch64"), args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	v := &vm{cmd: cmd, console: console, journal: journal, part: part, trial: trial, done: make(chan error, 1)}
	go func() { v.done <- cmd.Wait() }()
	logf("boot %d: partition %d, tryboot %v, console %s", b.boots, part, trial, console)
	return v, nil
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
		case err := <-v.done:
			v.done <- err
			if rx.MatchString(v.log()) {
				return nil
			}
			return fmt.Errorf("board stopped before %q", re)
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("no %q on the console within %v", re, timeout)
}

var restartRe = regexp.MustCompile(`reboot: Restarting system(?: with command '([^']*)')?`)

// stopped waits for the board to restart or power off by itself and records whether the
// restart asked for tryboot, as the Pi firmware reads the reboot argument.
func (v *vm) stopped(b *board, timeout time.Duration) (restart string, err error) {
	select {
	case <-v.done:
	case <-time.After(timeout):
		v.cut()
		return "", fmt.Errorf("board did not restart within %v", timeout)
	}
	// The kernel's console carries kernel messages only: with the journal on it too, a journal
	// write holding the console when the node calls reboot could leave the restart line unprinted
	// when the other CPU is stopped (seen in CI).
	m := restartRe.FindStringSubmatch(v.kernel())
	if m == nil {
		return "", fmt.Errorf("board stopped without restarting (qemu: %v)", v.cmd.ProcessState)
	}
	b.tryboot = strings.Contains(m[1], "tryboot")
	return m[1], nil
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
}
