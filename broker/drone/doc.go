// Package drone is the drone key-holder (DRONE-sim, #3516; SPEC NET-2
// Drones, A18). It holds the 32-byte MAVLink 2 signing secret, loads the
// owner-signed flight policy, derives the flight controller's parameters,
// fences and dock rally point from it by one pure function, uploads them
// over a signed link, and refuses to arm unless they read back equal.
//
// It is enforcer code (DRONE-enforcer, #3517, builds it into the enforcer
// image): it imports nothing from agentOS, only the standard library and
// the MAVLink framing of github.com/bluenviron/gomavlib (ARC-2, pinned by
// broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package drone
