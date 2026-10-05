// Package control handles the owner's control words (SPEC CH-2, CH-11).
//
// Everything here is deterministic: fixed parsing, fixed reply templates,
// and calls into the journal engine. Nothing in this package reaches a
// model, a guest, or the network (ARC-2), so STOP, RESUME, STATUS, and HELP
// work with every model and guest down. Task chat is the one path that
// leaves the package, through the Agent interface, and its failure only
// produces a fixed reply.
package control
