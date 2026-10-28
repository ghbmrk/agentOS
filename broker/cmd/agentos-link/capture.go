package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// The pre-store mode (decision 3): before the Owner Card confirm there is
// no sealed store and no kernel, so the first valid hello on the link
// interface is written to a capture file that enrollment reads at the
// confirm (agentos-enroll -first-edge). Enrollment takes the file only when
// root owns it and no one else can write it (b2 decision 2), so the parent
// runs as root; it never parses a byte from the edge. A child of it, under
// the link's own uid, runs TLS and reads the hello, and hands the parent
// the 128 bytes, which the parent checks again before it writes them.

// captureLen is the capture file: key, nonce, signature.
const captureLen = ed25519.PublicKeySize + edgelink.NonceLen + edgelink.HelloLen

var (
	errStoreExists = errors.New("agentos-link: the sealed store exists, so the first edge was fixed at the confirm")
	errTaken       = errors.New("agentos-link: a first edge was captured already")
	errBadCapture  = errors.New("agentos-link: the hello reader handed back no valid hello")
)

// validCapture reports whether b is one hello enrollment would take: a key
// not of small order that signed kernel.HelloMsg over the nonce.
func validCapture(b []byte) bool {
	if len(b) != captureLen {
		return false
	}
	key := ed25519.PublicKey(b[:ed25519.PublicKeySize])
	nonce, sig := b[ed25519.PublicKeySize:ed25519.PublicKeySize+edgelink.NonceLen], b[ed25519.PublicKeySize+edgelink.NonceLen:]
	return !kernel.SmallOrder(key) && ed25519.Verify(key, kernel.HelloMsg(nonce), sig)
}

// takeCapture reads one capture from r, checks it and writes it to path,
// unless store exists or path does.
func takeCapture(r io.Reader, path, store string) error {
	b := make([]byte, captureLen)
	if _, err := io.ReadFull(r, b); err != nil || !validCapture(b) {
		return errBadCapture
	}
	return writeCapture(path, store, b)
}

// writeCapture writes b to path, mode 0600 and owned by this process's
// euid, only while store does not exist and path does not: the first
// capture wins and none is ever replaced. The bytes go to a new file in the
// same directory first and are linked to path in one step, so enrollment
// never reads part of one.
func writeCapture(path, store string, b []byte) error {
	if _, err := os.Lstat(store); !errors.Is(err, os.ErrNotExist) {
		return errStoreExists
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errTaken
	}
	return linkCapture(path, b)
}

// linkCapture writes b to a new 0600 file beside path and links it to path,
// which link(2) refuses when path exists, so even a capture that passed the
// checks above at the same time as another never replaces it.
func linkCapture(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".first-edge-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errTaken
		}
		return err
	}
	return nil
}

// captureConfig is the pre-store core's TLS configuration: an ephemeral key
// in place of the link key, which does not exist before enrollment
// (decision 5); the edge pins the core's key only after enrolment.
func captureConfig() (*tls.Config, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return edgelink.ServerConfig(priv)
}

// firstHello returns the first valid hello any connection on ln sends,
// handling connections side by side so a slow one holds no other back.
// Every other connection is closed; ln is left open for the caller.
func firstHello(ln net.Listener, cfg *tls.Config, log io.Writer, wait time.Duration) (hello, error) {
	got := make(chan hello, 1)
	stop := make(chan struct{})
	defer close(stop)
	errs := make(chan error, 1)
	slots := newSlots()
	refused := 0
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				errs <- err
				return
			}
			if !slots.take() {
				raw.Close()
				refused++
				fmt.Fprintf(log, "agentos-link: refused a connection before the store over the handshake cap (%d so far)\n", refused)
				continue
			}
			go func() {
				defer slots.give()
				conn, key, err := handshake(raw, cfg)
				defer conn.Close()
				if err == nil {
					var h hello
					if h, err = readHello(conn, key, wait); err == nil {
						select {
						case got <- h:
						default: // a hello was taken already: this one is ignored
						}
						return
					}
				}
				select {
				case <-stop:
				default:
					fmt.Fprintln(log, "agentos-link: closed a connection before the store on a fault")
				}
			}()
		}
	}()
	select {
	case h := <-got:
		return h, nil
	case err := <-errs:
		return hello{}, err
	}
}

// helloChild is the child's whole run: read the first hello on ln and
// write its capture bytes to out.
func helloChild(ln net.Listener, out io.Writer, log io.Writer) error {
	cfg, err := captureConfig()
	if err != nil {
		return err
	}
	h, err := firstHello(ln, cfg, log, helloFor)
	if err != nil {
		return err
	}
	_, err = out.Write(h.capture())
	return err
}
