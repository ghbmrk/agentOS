// Command e2e-encoder stands in for rpicam-vid on the QEMU board, which has no camera (CAM-node
// part c's end-to-end test only; it ships in no CM4 image). It takes rpicam-vid's flags and writes
// generated H.264 Annex B access units to standard output at the asked frame rate: an SPS, a PPS
// and an IDR slice every --intra frames, a non-IDR slice otherwise. The slices carry synthetic
// bytes, not a decodable picture: the test checks the node's framing and transport, and the core
// decodes only in CAM-clerk's sandbox.
//
// It is built inside the broker's module as one file (image/camnode/build.sh) and imports only
// the standard library.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	fs := flag.NewFlagSet("e2e-encoder", flag.ExitOnError)
	fs.Bool("nopreview", false, "")
	fs.Bool("inline", false, "")
	fs.Bool("flush", false, "")
	fs.Int("timeout", 0, "")
	fs.String("codec", "h264", "")
	fs.String("output", "-", "")
	fs.Int("width", 1920, "")
	fs.Int("height", 1080, "")
	fs.Int("bitrate", 0, "")
	fps := fs.Int("framerate", 30, "")
	intra := fs.Int("intra", 60, "")
	if err := fs.Parse(os.Args[1:]); err != nil || *fps <= 0 || *fps > 255 || *intra <= 0 {
		fmt.Fprintln(os.Stderr, "e2e-encoder: bad flags")
		os.Exit(2)
	}
	w := bufio.NewWriter(os.Stdout)
	tick := time.NewTicker(time.Second / time.Duration(*fps))
	defer tick.Stop()
	for n := uint32(0); ; n++ {
		if n%uint32(*intra) == 0 {
			nal(w, 0x67, n, 16) // SPS
			nal(w, 0x68, n, 4)  // PPS
			nal(w, 0x65, n, 2000)
		} else {
			nal(w, 0x41, n, 600)
		}
		if err := w.Flush(); err != nil {
			os.Exit(0) // the node closed the pipe
		}
		<-tick.C
	}
}

// nal writes one NAL unit: a 4-byte start code, the header byte, then size bytes that open with
// first_mb_in_slice 0 (a leading 1 bit) and the frame number, and contain no zero byte, so no
// start code or emulation-prevention pattern can appear inside.
func nal(w *bufio.Writer, header byte, frame uint32, size int) {
	w.Write([]byte{0, 0, 0, 1, header})
	var num [4]byte
	binary.BigEndian.PutUint32(num[:], frame)
	w.WriteByte(0x80 | 0x40)
	for _, b := range num {
		w.WriteByte(b | 0x01)
	}
	for i := 5; i < size; i++ {
		w.WriteByte(byte(i*31+int(frame))%254 + 1)
	}
}
