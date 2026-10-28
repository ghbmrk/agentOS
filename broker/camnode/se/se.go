// Package se is the camera node's secure-element driver (CAM-node part b2,
// #3513; SPEC DEV-3, NET-2 Cameras, KRN-2, A16): an Infineon OPTIGA Trust M
// class part on the board's I2C bus (brief question 6), behind
// camnode.Element.
//
// The element holds the node's device key, generated inside it, two
// monotonic counters (settings and image; camwire ASSUMPTIONS CAM-wire-4)
// and one 32-byte data object naming the committed bundle (camnode
// ASSUMPTIONS CAM-server-3). There is no export: the driver sends no
// command that reads the key slot, and no method returns private key
// material (camnode TestDeviceKeyNeverExported).
package se

import "errors"

// Errors besides the link's.
var (
	// ErrCounter is a raise that would not raise, or past what the
	// element's counter holds.
	ErrCounter = errors.New("se: counter can only rise, within the element's range")
	// ErrDigest is a Sign asked for anything but a SHA-256 digest.
	ErrDigest = errors.New("se: element signs SHA-256 digests only")
)
