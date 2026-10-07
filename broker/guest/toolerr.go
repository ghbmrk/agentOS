package guest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"strings"
)

// guestVisible is an error a tool package built for the guest. Its text
// is an allowlisted sentence, not a wrapped host error.
type guestVisible interface{ GuestVisible() }

// ScrubToolError is the tool-result exit (SR2-3g). An error a tool
// package marked for the guest is returned as it is. Any other error
// whose text names a path is replaced with a ref; the detail is logged
// where no agent machine can read it. A fixed sentence with no path
// stays, so "give a query" still reaches the guest.
func ScrubToolError(tool string, err error) error {
	if err == nil {
		return nil
	}
	var vis guestVisible
	if errors.As(err, &vis) {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, "/") && !strings.Contains(msg, `\`) {
		return err
	}
	ref := toolRef()
	log.Printf("guest tool %s: ref %s: %v", clip(tool, 64), ref, err)
	return errors.New("that failed (ref " + ref + "); the broker's log has the detail")
}

func toolRef() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
