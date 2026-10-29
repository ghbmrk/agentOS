// Command e2e-element stands in for the Infineon OPTIGA Trust M on the QEMU board, which has no
// I2C bus (CAM-node part c's end-to-end test only; it ships in no CM4 image). It serves
// /dev/i2c-1 over CUSE and answers the element's I2C protocol as broker/camnode/se drives it:
// the state and data registers, the link layer's frames (CRC-16/KERMIT, frame and ack numbers)
// and the commands the driver sends (OpenApplication, GetDataObject, SetDataObject write and
// count, CalcSign). So the end-to-end test runs the node binary and its element driver
// unchanged; only the chip is software.
//
// Its state, the chip's non-volatile memory, is a fixed record on the block device it is given
// (QEMU's second virtio disk): the device key, the public point, the bundle record and the two
// counters. A fresh device is a fresh chip: the stand-in makes the device key at its first
// start, as provisioning would (part d). The counters only count up, as the chip's do. The key
// never leaves the process except as the public point.
//
// It is built inside the broker's module as one file (image/camnode/build.sh) and imports only
// the standard library.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"syscall"
)

// The element's registers and link layer (OPTIGA Trust M I2C protocol; broker/camnode/se).
const (
	regData      = 0x80
	regState     = 0x82
	regSoftReset = 0x88
	stateReady   = 0x40
	fctrControl  = 0x80
	pctrPresence = 0x08
	maxPacket    = 0x115 - 5
)

// Commands and objects.
const (
	cmdGetData  = 0x81
	cmdSetData  = 0x82
	cmdCalcSign = 0xB1
	cmdOpenApp  = 0xF0
	paramWrite  = 0x00
	paramCount  = 0x02
	paramECDSA  = 0x11
	staOK       = 0x00
	staErr      = 0x07

	oidDeviceKey = 0xE0F1
	oidSettings  = 0xE120
	oidImage     = 0xE121
	oidBundle    = 0xF1D0
	oidPublic    = 0xF1D1
	threshold    = 1<<32 - 1
)

// chip is the element's non-volatile state, kept in a 512-byte record on the store device.
type chip struct {
	store    *os.File
	key      *ecdsa.PrivateKey
	public   [65]byte
	bundle   []byte // nil until written; then 32 bytes
	counters map[uint16]uint32
}

const magic = "CAMSIM1\x00"

func (c *chip) save() error {
	var rec [512]byte
	copy(rec[0:8], magic)
	d := c.key.D.FillBytes(make([]byte, 32))
	copy(rec[8:40], d)
	copy(rec[40:105], c.public[:])
	if c.bundle != nil {
		rec[105] = 32
		copy(rec[106:138], c.bundle)
	}
	binary.BigEndian.PutUint32(rec[138:], c.counters[oidSettings])
	binary.BigEndian.PutUint32(rec[142:], c.counters[oidImage])
	if _, err := c.store.WriteAt(rec[:], 0); err != nil {
		return err
	}
	return c.store.Sync()
}

func load(path string) (*chip, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_DSYNC, 0)
	if err != nil {
		return nil, err
	}
	c := &chip{store: f, counters: map[uint16]uint32{}}
	var rec [512]byte
	if _, err := f.ReadAt(rec[:], 0); err != nil {
		return nil, err
	}
	if string(rec[0:8]) != magic {
		// A fresh chip: make the device key, as provisioning does (se.Optiga.Generate).
		if c.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
		pub, err := c.key.PublicKey.Bytes()
		if err != nil {
			return nil, err
		}
		copy(c.public[:], pub)
		return c, c.save()
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), rec[8:40])
	if err != nil {
		return nil, err
	}
	c.key = k
	copy(c.public[:], rec[40:105])
	if rec[105] == 32 {
		c.bundle = append([]byte(nil), rec[106:138]...)
	}
	c.counters[oidSettings] = binary.BigEndian.Uint32(rec[138:])
	c.counters[oidImage] = binary.BigEndian.Uint32(rec[142:])
	return c, nil
}

// apdu runs one command and returns the response APDU: status, an undefined byte, the length,
// the data.
func (c *chip) apdu(a []byte) []byte {
	resp := func(sta byte, data []byte) []byte {
		out := []byte{sta, 0}
		out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
		return append(out, data...)
	}
	if len(a) < 4 || int(binary.BigEndian.Uint16(a[2:4])) != len(a)-4 {
		return resp(staErr, nil)
	}
	cmd, param, p := a[0], a[1], a[4:]
	switch cmd {
	case cmdOpenApp:
		return resp(staOK, nil)
	case cmdGetData:
		if len(p) != 6 || binary.BigEndian.Uint16(p[2:4]) != 0 {
			return resp(staErr, nil)
		}
		oid, n := binary.BigEndian.Uint16(p[0:2]), int(binary.BigEndian.Uint16(p[4:6]))
		var obj []byte
		switch oid {
		case oidSettings, oidImage:
			obj = binary.BigEndian.AppendUint32(nil, c.counters[oid])
			obj = binary.BigEndian.AppendUint32(obj, threshold)
		case oidBundle:
			obj = c.bundle
		case oidPublic:
			obj = c.public[:]
		default:
			return resp(staErr, nil)
		}
		return resp(staOK, obj[:min(n, len(obj))])
	case cmdSetData:
		if len(p) < 4 || binary.BigEndian.Uint16(p[2:4]) != 0 {
			return resp(staErr, nil)
		}
		oid, data := binary.BigEndian.Uint16(p[0:2]), p[4:]
		switch {
		case param == paramWrite && oid == oidBundle && len(data) == 32:
			c.bundle = append([]byte(nil), data...)
		case param == paramCount && (oid == oidSettings || oid == oidImage) && len(data) == 1:
			next := uint64(c.counters[oid]) + uint64(data[0])
			if next > threshold {
				return resp(staErr, nil)
			}
			c.counters[oid] = uint32(next)
		default:
			// The key slot and the public point are locked after provisioning.
			return resp(staErr, nil)
		}
		if err := c.save(); err != nil {
			return resp(staErr, nil)
		}
		return resp(staOK, nil)
	case cmdCalcSign:
		want := append([]byte{0x01, 0, 32}, make([]byte, 32)...)
		want = append(want, 0x03, 0, 2, oidDeviceKey>>8, oidDeviceKey&0xFF)
		if param != paramECDSA || len(p) != len(want) || !bytes.Equal(p[:3], want[:3]) || !bytes.Equal(p[35:], want[35:]) {
			return resp(staErr, nil)
		}
		r, s, err := ecdsa.Sign(rand.Reader, c.key, p[3:35])
		if err != nil {
			return resp(staErr, nil)
		}
		return resp(staOK, append(derInt(r), derInt(s)...))
	}
	return resp(staErr, nil)
}

// derInt is a minimal DER INTEGER, as the chip returns r and s.
func derInt(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return append([]byte{0x02, byte(len(b))}, b...)
}

func crc16(p []byte) uint16 {
	var c uint16
	for _, b := range p {
		c ^= uint16(b)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0x8408
			} else {
				c >>= 1
			}
		}
	}
	return c
}

// link is the element's side of the I2C link layer.
type link struct {
	chip    *chip
	reg     byte
	pending []byte // the frame the host reads next from the data register
	next    uint8  // the element's next frame number
}

// write is one I2C write transaction from the host.
func (l *link) write(p []byte) {
	if len(p) == 0 {
		return
	}
	l.reg = p[0]
	switch {
	case p[0] == regSoftReset:
		l.pending, l.next = nil, 0
	case p[0] == regData && len(p) > 1:
		l.frame(p[1:])
	}
}

// read is one I2C read transaction of n bytes.
func (l *link) read(n int) []byte {
	switch l.reg {
	case regState:
		st := []byte{stateReady, 0}
		return binary.BigEndian.AppendUint16(st, uint16(len(l.pending)))[:min(n, 4)]
	case regData:
		out := l.pending
		l.pending = nil
		return out[:min(n, len(out))]
	}
	return nil
}

// frame takes one frame from the host: an acknowledgement is consumed; a data frame carrying a
// command is answered with a data frame carrying the response, acknowledging the host's frame.
func (l *link) frame(f []byte) {
	if len(f) < 5 || int(binary.BigEndian.Uint16(f[1:3])) != len(f)-5 ||
		binary.BigEndian.Uint16(f[len(f)-2:]) != crc16(f[:len(f)-2]) {
		return // a corrupt frame is dropped; the host times out
	}
	if f[0]&fctrControl != 0 {
		return
	}
	hostFrame := (f[0] >> 2) & 3
	pkt := f[3 : len(f)-2]
	if len(pkt) < 1 || pkt[0] != pctrPresence {
		return
	}
	body := append([]byte{pctrPresence}, l.chip.apdu(pkt[1:])...)
	if len(body) > maxPacket {
		return
	}
	out := []byte{(l.next&3)<<2 | hostFrame&3}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)
	out = binary.BigEndian.AppendUint16(out, crc16(out))
	l.pending = out
	l.next = (l.next + 1) & 3
}

// CUSE: the FUSE protocol's character-device form (include/uapi/linux/fuse.h).
const (
	fuseOpen      = 14
	fuseRead      = 15
	fuseWrite     = 16
	fuseRelease   = 18
	fuseFlush     = 25
	fuseInterrupt = 36
	fuseIoctl     = 39
	cuseInit      = 4096
	inHeader      = 40
	outHeader     = 16
	i2cSlave      = 0x0703
	devName       = "i2c-1"
)

func reply(dev *os.File, unique uint64, errno int32, body []byte) error {
	out := make([]byte, outHeader, outHeader+len(body))
	binary.LittleEndian.PutUint32(out[0:], uint32(outHeader+len(body)))
	binary.LittleEndian.PutUint32(out[4:], uint32(errno))
	binary.LittleEndian.PutUint64(out[8:], unique)
	_, err := dev.Write(append(out, body...))
	return err
}

func serve(dev *os.File, l *link) error {
	buf := make([]byte, 1<<17)
	for {
		n, err := dev.Read(buf)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n < inHeader {
			return errors.New("short CUSE request")
		}
		req := buf[:n]
		op := binary.LittleEndian.Uint32(req[4:])
		unique := binary.LittleEndian.Uint64(req[8:])
		arg := req[inHeader:]
		switch op {
		case cuseInit:
			if len(arg) < 16 {
				return errors.New("short CUSE_INIT")
			}
			major, minor := binary.LittleEndian.Uint32(arg[0:]), binary.LittleEndian.Uint32(arg[4:])
			if major != 7 || minor < 11 {
				return fmt.Errorf("CUSE protocol %d.%d unsupported", major, minor)
			}
			out := make([]byte, 72)
			binary.LittleEndian.PutUint32(out[0:], 7)
			binary.LittleEndian.PutUint32(out[4:], minor)
			binary.LittleEndian.PutUint32(out[16:], 4096) // max_read
			binary.LittleEndian.PutUint32(out[20:], 4096) // max_write
			out = append(out, "DEVNAME="+devName+"\x00"...)
			if err := reply(dev, unique, 0, out); err != nil {
				return err
			}
			notify()
		case fuseOpen:
			out := make([]byte, 16)
			binary.LittleEndian.PutUint32(out[8:], 1) // FOPEN_DIRECT_IO
			err = reply(dev, unique, 0, out)
		case fuseRead:
			size := int(binary.LittleEndian.Uint32(arg[16:]))
			err = reply(dev, unique, 0, l.read(size))
		case fuseWrite:
			size := int(binary.LittleEndian.Uint32(arg[16:]))
			if 40+size > len(arg) {
				return errors.New("short CUSE write")
			}
			l.write(append([]byte(nil), arg[40:40+size]...))
			out := binary.LittleEndian.AppendUint32(nil, uint32(size))
			err = reply(dev, unique, 0, append(out, 0, 0, 0, 0))
		case fuseIoctl:
			cmd := binary.LittleEndian.Uint32(arg[12:])
			if cmd != i2cSlave {
				err = reply(dev, unique, -int32(syscall.ENOTTY), nil)
				break
			}
			err = reply(dev, unique, 0, make([]byte, 16))
		case fuseRelease, fuseFlush:
			err = reply(dev, unique, 0, nil)
		case fuseInterrupt:
		default:
			err = reply(dev, unique, -int32(syscall.ENOSYS), nil)
		}
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
	}
}

// notify tells systemd the device is being created (Type=notify).
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
		return
	}
	defer c.Close()
	c.Write([]byte("READY=1"))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: e2e-element STORE-DEVICE")
		os.Exit(2)
	}
	c, err := load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-element:", err)
		os.Exit(1)
	}
	dev, err := os.OpenFile("/dev/cuse", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-element:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "e2e-element: settings counter %d, image counter %d\n",
		c.counters[oidSettings], c.counters[oidImage])
	if err := serve(dev, &link{chip: c}); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-element:", err)
		os.Exit(1)
	}
}
