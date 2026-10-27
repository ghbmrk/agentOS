package homekit

import (
	"errors"
	"fmt"
)

var (
	// ErrAuthentication: the accessory refused the setup code or a proof failed.
	ErrAuthentication = errors.New("homekit: authentication failed")
	// ErrMaxTries: the accessory refuses pair-setup until it is reset.
	ErrMaxTries = errors.New("homekit: accessory reached its maximum pairing attempts")
	// ErrBackoff, ErrMaxPeers, ErrUnavailable, ErrBusy: accessory states.
	ErrBackoff     = errors.New("homekit: accessory asks to retry later")
	ErrMaxPeers    = errors.New("homekit: accessory has no room for another controller")
	ErrUnavailable = errors.New("homekit: accessory is already paired")
	ErrBusy        = errors.New("homekit: accessory is pairing with another controller")
	// ErrIdentity: the accessory did not prove the pinned key (DEV-3).
	ErrIdentity = errors.New("homekit: accessory identity does not match the pin")
	// ErrProtocol: malformed or oversized input from the accessory.
	ErrProtocol = errors.New("homekit: protocol error")
	// ErrRefused: a read or write outside the resolved, declared shapes (DEV-4).
	ErrRefused = errors.New("homekit: operation refused")
	// ErrClosed: the session ended; open a new one with pair-verify.
	ErrClosed = errors.New("homekit: session closed")
)

// accessoryError maps the TLV8 kTLVError codes.
func accessoryError(code []byte) error {
	if len(code) != 1 {
		return fmt.Errorf("%w: error item of %d bytes", ErrProtocol, len(code))
	}
	switch code[0] {
	case 2:
		return ErrAuthentication
	case 3:
		return ErrBackoff
	case 4:
		return ErrMaxPeers
	case 5:
		return ErrMaxTries
	case 6:
		return ErrUnavailable
	case 7:
		return ErrBusy
	}
	return fmt.Errorf("%w: accessory error %d", ErrProtocol, code[0])
}
