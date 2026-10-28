// Command agentos-camnode is the camera node's one service (CAM-node part
// b2, #3513; SPEC DEV-3, NET-2 Cameras, NET-4, NET-7, A16): it opens the
// secure element, the capture and the board's A/B slots, and serves the
// node's one TLS port. The image (part c) runs it as a static binary under
// its own uid with the camera, secure-element, SPI and input devices only,
// and fixes every flag in its unit.
//
// The listener is the only socket it has: systemd's socket activation
// hands it as fd 3, or -listen opens it. It dials nothing
// (TestNoOutboundDial).
//
//	agentos-camnode -release PATH -store DIR -slots DIR -autoboot PATH \
//	    -slot-a DEV -slot-b DEV -part-a N -part-b N -encoder PATH \
//	    -resolutions WxH,... [-listen ADDR] [-element DEV] [-button DEV] [-ir PATH] [-thermal DEV -thermal-core lepton2|lepton3]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/camnode"
	"github.com/ghbmrk/agentos/broker/camnode/capture"
	"github.com/ghbmrk/agentos/broker/camnode/se"
	"github.com/ghbmrk/agentos/broker/camwire"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentos-camnode:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("agentos-camnode", flag.ContinueOnError)
	listen := fs.String("listen", ":8443", "the stream port, when no socket is passed as fd 3")
	element := fs.String("element", "/dev/i2c-1", "the secure element's i2c-dev node")
	elementAddr := fs.Uint("element-addr", se.DefaultAddress, "the secure element's 7-bit I2C address")
	releasePath := fs.String("release", "", "the release signer's Ed25519 public key, base64, in a file on the read-only root")
	store := fs.String("store", "", "the bundle directory on the data partition")
	slotsDir := fs.String("slots", "", "the slot manifest directory on the data partition")
	autoboot := fs.String("autoboot", "", "autoboot.txt on the boot partition")
	slotA := fs.String("slot-a", "", "slot A's root device")
	slotB := fs.String("slot-b", "", "slot B's root device")
	partA := fs.Int("part-a", 2, "slot A's boot partition number")
	partB := fs.Int("part-b", 3, "slot B's boot partition number")
	bootDT := fs.String("bootloader-dt", "/proc/device-tree/chosen/bootloader", "the bootloader's device-tree node")
	button := fs.String("button", "", "the provisioning button's input event device")
	buttonKey := fs.Uint("button-key", 0x100, "the button's key code (BTN_0 by default)")
	encoder := fs.String("encoder", "/usr/bin/rpicam-vid", "the encoder")
	irPath := fs.String("ir", "", "the IR illuminator's brightness file; empty: none fitted")
	thermalDev := fs.String("thermal", "", "the thermal core's spidev node; empty: none fitted")
	thermalCore := fs.String("thermal-core", "lepton3", "the thermal core: lepton2 or lepton3")
	thermalHz := fs.Uint("thermal-hz", 20_000_000, "the thermal core's SPI clock")
	resolutions := fs.String("resolutions", "", "the sensor modes, WxH,WxH")
	maxFPS := fs.Uint("max-fps", 30, "the highest frame rate")
	minKbps := fs.Uint("min-kbps", 500, "the lowest bitrate")
	maxKbps := fs.Uint("max-kbps", 8000, "the highest bitrate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *releasePath == "" || *store == "" || *slotsDir == "" || *autoboot == "" || *slotA == "" || *slotB == "" || *resolutions == "" {
		return errors.New("-release, -store, -slots, -autoboot, -slot-a, -slot-b and -resolutions are required")
	}
	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	logf := func(event string) { logger.Println(event) }

	release, err := readRelease(*releasePath)
	if err != nil {
		return err
	}
	ranges, err := parseRanges(*resolutions, *maxFPS, *minKbps, *maxKbps)
	if err != nil {
		return err
	}
	bus, err := se.OpenI2C(*element, uint16(*elementAddr))
	if err != nil {
		return err
	}
	el, err := se.Open(bus)
	if err != nil {
		return errors.New("secure element did not open")
	}
	part, trial, err := readBootloader(*bootDT)
	if err != nil {
		return err
	}
	slots, err := newSlots(*autoboot, *slotsDir, [2]string{*slotA, *slotB}, [2]int{*partA, *partB}, part)
	if err != nil {
		return err
	}
	manifest, image, err := slots.running()
	if err != nil {
		return err
	}
	held := false
	if *button != "" {
		if held, err = buttonHeld(*button, uint16(*buttonKey)); err != nil {
			return err
		}
	}

	ccfg := capture.Config{Encoder: []string{*encoder}, Log: logf}
	ranges.IR = *irPath != ""
	if ranges.IR {
		path := *irPath
		ccfg.IR = func(mode uint8) error { return setIR(path, mode) }
	}
	if *thermalDev != "" {
		switch *thermalCore {
		case "lepton2":
			ccfg.Shape = capture.Lepton2
		case "lepton3":
			ccfg.Shape = capture.Lepton3
		default:
			return errors.New("-thermal-core is lepton2 or lepton3")
		}
		dev, hz := *thermalDev, uint32(*thermalHz)
		ccfg.Thermal = func() (io.ReadCloser, error) { return capture.OpenSPI(dev, hz) }
	}
	cam := capture.New(ccfg)
	defer cam.Close()

	ln, err := listener(*listen)
	if err != nil {
		return err
	}
	return serve(ln, camnode.Config{
		Element:  el,
		Store:    camnode.FileStore{Dir: *store},
		Source:   cam,
		Ranges:   ranges,
		Thermal:  ccfg.Shape,
		Image:    image,
		Button:   held,
		Release:  release,
		Slots:    slots,
		Manifest: manifest,
		Trial:    trial,
		Log:      logf,
	})
}

// serve starts the node and serves ln until it fails. Everything after the
// hardware is open runs here, so the socket test runs this path whole.
func serve(ln net.Listener, cfg camnode.Config) error {
	defer ln.Close()
	n, err := camnode.New(cfg)
	if err != nil {
		return err
	}
	return n.Serve(ln)
}

// listener is the socket systemd passed as fd 3 (LISTEN_PID and LISTEN_FDS
// name this process and one socket), or a TCP listener on addr.
func listener(addr string) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
		f := os.NewFile(3, "stream")
		defer f.Close()
		return net.FileListener(f)
	}
	return net.Listen("tcp", addr)
}

// readRelease reads the release signer's public key: base64 on one line.
func readRelease(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("release key is not a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(k), nil
}

// parseRanges reads the declared sensor ranges.
func parseRanges(res string, fps, lo, hi uint) (camnode.Ranges, error) {
	r := camnode.Ranges{MaxFPS: uint8(fps), MinKbps: uint32(lo), MaxKbps: uint32(hi)}
	if fps == 0 || fps > 255 || lo == 0 || lo > hi || hi > 1<<31 {
		return r, errors.New("frame rate or bitrate range out of bounds")
	}
	for _, m := range strings.Split(res, ",") {
		w, h, ok := strings.Cut(m, "x")
		wi, e1 := strconv.ParseUint(w, 10, 16)
		hi, e2 := strconv.ParseUint(h, 10, 16)
		if !ok || e1 != nil || e2 != nil || wi == 0 || hi == 0 {
			return r, errors.New("resolution is not WxH")
		}
		r.Resolutions = append(r.Resolutions, camnode.Resolution{Width: uint16(wi), Height: uint16(hi)})
	}
	return r, nil
}

// setIR writes the illuminator's brightness file: on for IROn and IRAuto
// (no ambient sensor is fitted; camnode ASSUMPTIONS CAM-bin-4), off for IROff.
func setIR(path string, mode uint8) error {
	v := "0"
	if mode != camwire.IROff {
		v = "1"
	}
	return os.WriteFile(path, []byte(v), 0)
}
