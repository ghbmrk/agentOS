package at

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// REQ: HW-2

// openPTY returns a pseudo-terminal pair: a stand-in for a USB serial port.
func openPTY(t *testing.T) (master *os.File, slave string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skip("unlockpt:", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Skip("ptsname:", e)
	}
	t.Cleanup(func() { m.Close() })
	return m, "/dev/pts/" + strconv.Itoa(int(n))
}

func TestOpenSerialIsRawSoCRAndCtrlZPassUnchanged(t *testing.T) {
	master, slave := openPTY(t)
	port, err := OpenSerial(slave)
	if err != nil {
		t.Fatal(err)
	}
	defer port.Close()
	// A cooked tty would echo, turn CR into LF, and treat Ctrl-Z as
	// suspend; the AT protocol needs all of them as plain bytes.
	if _, err := port.Write([]byte("AT+CMGS=22\r0001\x1a")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = master.SetReadDeadline(time.Now().Add(time.Second))
	n, err := master.Read(buf)
	if err != nil || string(buf[:n]) != "AT+CMGS=22\r0001\x1a" {
		t.Fatalf("modem side read %q %v", buf[:n], err)
	}
	if _, err := master.Write([]byte("\r\nOK\r\n> ")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, 8)
	for len(got) < 8 {
		n, err := port.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "\r\nOK\r\n> " {
		t.Fatalf("host side read %q", got)
	}
}
