// Command agentos-drone is the stand-in key-holder process for the drone
// (DRONE-sim, #3516). It holds the MAVLink signing key, loads the
// owner-signed flight policy, uploads it and reads it back, starts a flight
// from an owner-signed flight record, serves the core side's one command
// (return to dock) on a local socket, and sends the aircraft its heartbeat.
// DRONE-enforcer (#3517) runs it on the enforcer.
//
// The key and the owner's public key are read from files only, never from an
// argument or the environment (P2). The aircraft is a serial device (its USB
// or radio link), never a network address, so the key-holder dials nothing.
//
//	agentos-drone -new-key PATH
//	agentos-drone -key PATH -owner PATH -state DIR -aircraft DEVICE [-provision] [-policy PATH] [-flight PATH] [-core SOCKET]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/drone"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentos-drone:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("agentos-drone", flag.ContinueOnError)
	newKey := fs.String("new-key", "", "write a fresh signing key to this path (mode 0600) and exit")
	keyPath := fs.String("key", "", "the signing key file (mode 0600, owned by this user)")
	ownerPath := fs.String("owner", "", "the owner's Ed25519 public key, base64, in a file")
	state := fs.String("state", "", "the key-holder's state directory")
	aircraft := fs.String("aircraft", "", "the aircraft's MAVLink serial device")
	provision := fs.Bool("provision", false, "store the key on an aircraft that holds none (first set-up link only)")
	policyPath := fs.String("policy", "", "a signed policy to load")
	flightPath := fs.String("flight", "", "a signed flight record to fly")
	corePath := fs.String("core", "", "a unix socket path for the core side's return_to_dock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newKey != "" {
		k, err := drone.NewKey(nil)
		if err != nil {
			return err
		}
		return drone.WriteKeyFile(*newKey, k)
	}
	if *keyPath == "" || *ownerPath == "" || *state == "" || *aircraft == "" {
		return errors.New("-key, -owner, -state and -aircraft are required")
	}
	k, err := drone.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	owner, err := readOwner(*ownerPath)
	if err != nil {
		return err
	}
	conn, err := os.OpenFile(*aircraft, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	if *provision {
		if err := drone.Provision(conn, k, time.Now()); err != nil {
			return err
		}
	}
	link, err := drone.Dial(conn, k)
	if err != nil {
		return err
	}
	defer link.Close()
	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	if _, err := link.WaitHeartbeat(time.Time{}, 20*time.Second); err != nil {
		return fmt.Errorf("no signed heartbeat from the aircraft: %w", err)
	}
	h, err := drone.NewHolder(link, owner, *state, logger)
	if err != nil {
		return err
	}
	if *policyPath != "" {
		env, err := os.ReadFile(*policyPath)
		if err != nil {
			return err
		}
		if err := h.Load(env); err != nil {
			return err
		}
	} else if err := h.ReadBack(); err != nil {
		logger.Printf("boot read-back: %v", err)
	} else {
		logger.Printf("boot read-back: the aircraft holds policy version %d", h.Policy().Version)
	}
	stop := link.KeepAlive()
	defer stop()
	if *flightPath != "" {
		env, err := os.ReadFile(*flightPath)
		if err != nil {
			return err
		}
		if err := h.Fly(env); err != nil {
			return err
		}
	}
	if *corePath != "" {
		ln, err := net.Listen("unix", *corePath)
		if err != nil {
			return err
		}
		defer ln.Close()
		go serveCore(ln, h, logger)
	}
	<-link.Done()
	return errors.New("the aircraft link closed")
}

// serveCore serves one core-side connection at a time: the channel is the
// core's, and the core is one client.
func serveCore(ln net.Listener, h *drone.Holder, logger *log.Logger) {
	for {
		c, err := ln.Accept()
		if err != nil {
			logger.Printf("core socket: %v", err)
			return
		}
		h.ServeCore(c)
		c.Close()
	}
}

func readOwner(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("the owner key file is not a base64 Ed25519 public key")
	}
	return pub, nil
}
