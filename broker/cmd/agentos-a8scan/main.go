// Command agentos-a8scan is A8's at-rest check for an owner session on real
// hardware (broker/recovery/A8-SESSION.md): it scans a drive's plaintext
// partitions, or any files and directories, for the vault data key and
// every secret the vault holds, in raw, hex, base64 and base32 forms at
// every alignment, and checks that the key-slot file holds only the TPM,
// passphrase and recovery slots.
//
//	agentos-a8scan -vault DIR/vault -keys DIR/vault.keys TARGET...
//
// The recovery key is read from standard input, never from the command
// line. Each TARGET is a block device or file (scanned raw, start to end)
// or a directory (every regular file, no symlinks followed). Before
// scanning, it plants every needle in a scratch blob and stops unless the
// scan finds all of them, so a clean result means something. It prints
// findings by name, place and encoding, never values, and exits 1 on any
// finding.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

func main() {
	log.SetFlags(0)
	vp := flag.String("vault", "", "the drive's vault file")
	kp := flag.String("keys", "", "the drive's key-slot file")
	flag.Parse()
	if *vp == "" || *kp == "" || flag.NArg() == 0 {
		log.Fatal("usage: agentos-a8scan -vault FILE -keys FILE TARGET... (recovery key on stdin)")
	}
	fmt.Fprint(os.Stderr, "Recovery key: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	rk, err := recovery.ParseRecoveryKey(line)
	if err != nil {
		log.Fatal(err)
	}
	n, err := run(*vp, *kp, rk, flag.Args(), os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
	if n > 0 {
		os.Exit(1)
	}
}

func run(vp, kp string, rk recovery.RecoveryKey, targets []string, out io.Writer) (int, error) {
	raw, err := os.ReadFile(kp)
	if err != nil {
		return 0, err
	}
	if err := recovery.CheckKeys(raw); err != nil {
		fmt.Fprintf(out, "FAIL key-slot file: %v\n", err)
		return 1, nil
	}
	fmt.Fprintln(out, "ok   key-slot file holds only TPM, passphrase and recovery slots")
	v, err := vault.OpenSealed(vp, kp, recovery.Factor(rk))
	if err != nil {
		return 0, fmt.Errorf("the recovery key does not open this vault: %w", err)
	}
	b := &recovery.Box{VaultPath: vp, KeysPath: kp, V: v}
	needles, err := recovery.AuditNeedles(b, rk)
	v.Close()
	if err != nil {
		return 0, err
	}
	s, err := recovery.NewScanner(needles)
	if err != nil {
		return 0, err
	}
	if err := control(s, needles); err != nil {
		return 0, err
	}
	fmt.Fprintf(out, "ok   control: all %d needles found when planted\n", len(needles))
	found := 0
	for _, t := range targets {
		fi, err := os.Stat(t)
		if err != nil {
			return found, err
		}
		var got []recovery.Finding
		if fi.IsDir() {
			var skipped []string
			got, skipped, err = s.Tree(t)
			for _, p := range skipped {
				fmt.Fprintf(out, "skip %s (not a regular file)\n", p)
			}
		} else {
			var f *os.File
			if f, err = os.Open(t); err == nil {
				got, err = s.Reader(t, f)
				f.Close()
			}
		}
		if err != nil {
			return found, fmt.Errorf("%s: %w", t, err)
		}
		for _, g := range got {
			fmt.Fprintf(out, "FIND %s\n", g)
		}
		if len(got) == 0 {
			fmt.Fprintf(out, "ok   %s: nothing found\n", t)
		}
		found += len(got)
	}
	return found, nil
}

// control plants each needle, hex-encoded and inside base64, in random
// data and requires the scanner to find every one.
func control(s *recovery.Scanner, needles []recovery.Needle) error {
	for _, n := range needles {
		for _, form := range [][]byte{n.Value, []byte(hex.EncodeToString(n.Value)), []byte(base64.StdEncoding.EncodeToString(append([]byte("x"), n.Value...)))} {
			pad := make([]byte, 4096)
			rand.Read(pad)
			got, err := s.Reader("control", bytes.NewReader(append(append(pad, form...), pad...)))
			if err != nil {
				return err
			}
			hit := false
			for _, g := range got {
				hit = hit || g.Needle == n.Name
			}
			if !hit {
				return fmt.Errorf("control: the scanner missed %s; refusing to report a clean scan", n.Name)
			}
		}
	}
	return nil
}
