// Command e2e-button stands in for the provisioning button on the QEMU board (CAM-node part c's
// end-to-end test only). It makes a uinput key device named camnode-button with BTN_0, the key
// agentos-camnode reads with EVIOCGKEY (camnode ASSUMPTIONS CAM-bin-3), and holds the key down
// when the fw_cfg file it is given reads "1", which the test harness sets with QEMU's -fw_cfg
// for a boot with the button held at power-on. It keeps the device open until it is stopped.
//
// It is built inside the broker's module as one file (image/camnode/build.sh) and imports only
// the standard library.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	uiSetEvBit  = 0x40045564 // _IOW('U', 100, int)
	uiSetKeyBit = 0x40045565 // _IOW('U', 101, int)
	uiDevSetup  = 0x405c5503 // _IOW('U', 3, struct uinput_setup)
	uiDevCreate = 0x5501     // _IO('U', 1)
	evSyn       = 0
	evKey       = 1
	btn0        = 0x100
)

func ioctl(fd uintptr, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); e != 0 {
		return e
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: e2e-button FW_CFG_FILE")
		os.Exit(2)
	}
	held := false
	if b, err := os.ReadFile(os.Args[1]); err == nil {
		held = bytes.Equal(bytes.TrimSpace(b), []byte("1"))
	}
	f, err := os.OpenFile("/dev/uinput", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fail(err)
	}
	fd := f.Fd()
	if err := ioctl(fd, uiSetEvBit, evKey); err != nil {
		fail(err)
	}
	if err := ioctl(fd, uiSetKeyBit, btn0); err != nil {
		fail(err)
	}
	// struct uinput_setup: struct input_id (bustype, vendor, product, version), name[80],
	// ff_effects_max.
	var setup [92]byte
	binary.LittleEndian.PutUint16(setup[0:], 0x06) // BUS_VIRTUAL
	copy(setup[8:88], "camnode-button")
	if err := ioctl(fd, uiDevSetup, uintptr(unsafe.Pointer(&setup[0]))); err != nil {
		fail(err)
	}
	if err := ioctl(fd, uiDevCreate, 0); err != nil {
		fail(err)
	}
	if held {
		emit(f, evKey, btn0, 1)
		emit(f, evSyn, 0, 0)
	}
	fmt.Fprintf(os.Stderr, "e2e-button: camnode-button created, held=%v\n", held)
	notify()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
}

// emit writes one struct input_event: a zero timeval (the kernel stamps it), type, code, value.
func emit(f *os.File, typ, code uint16, value int32) {
	var ev [24]byte
	binary.LittleEndian.PutUint16(ev[16:], typ)
	binary.LittleEndian.PutUint16(ev[18:], code)
	binary.LittleEndian.PutUint32(ev[20:], uint32(value))
	if _, err := f.Write(ev[:]); err != nil {
		fail(err)
	}
}

// notify tells systemd the device exists (Type=notify).
func notify() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		fail(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("READY=1")); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "e2e-button:", err)
	os.Exit(1)
}
