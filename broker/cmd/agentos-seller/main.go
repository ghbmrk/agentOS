// Command agentos-seller is the seller flow for one preloaded box (SPEC
// §8.1, HW-10; D-105: the project is the seller for the first M6 Ultra).
//
//	agentos-seller prep -image agentos_V.raw -sums SHA256SUMS -out DIR
//	agentos-seller write -image DIR/box.raw -sums DIR/SHA256SUMS -device /dev/X
//
// prep checks a CI-built image against its SHA256SUMS, seals a new claim
// code into its root file system at claim.StatePath (a salted verifier
// only, HW-1) and writes DIR/box.raw, DIR/SHA256SUMS and the sticker
// (DIR/sticker.html, DIR/sticker.txt). The sticker files are the only
// place the code is written. It needs e2fsprogs' debugfs and e2fsck.
//
// write copies box.raw to an unmounted disk at least as large, syncs, and
// reads every byte back against the checksum (A1).
//
// It is a one-box tool (D-104): no general seller or flasher.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  agentos-seller prep -image agentos_V.raw -sums SHA256SUMS -out DIR
  agentos-seller write -image DIR/box.raw -sums DIR/SHA256SUMS -device /dev/X`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("agentos-seller "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "the image")
	sums := fs.String("sums", "", "the SHA256SUMS that lists the image")
	out := fs.String("out", "", "prep: a new directory for box.raw, SHA256SUMS and the sticker")
	device := fs.String("device", "", "write: the target disk")
	var err error
	switch args[0] {
	case "prep":
		if fs.Parse(args[1:]) != nil || *image == "" || *sums == "" || *out == "" || *device != "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		err = prep(prepConfig{Image: *image, Sums: *sums, Out: *out, Log: stdout})
	case "write":
		if fs.Parse(args[1:]) != nil || *image == "" || *sums == "" || *device == "" || *out != "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		err = write(*image, *sums, *device, stdout)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "agentos-seller:", err)
		return 1
	}
	return 0
}
