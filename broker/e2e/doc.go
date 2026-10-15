// Package e2e holds end-to-end assurance runs that compose broker packages
// the way the box does (P1-7): the A5 canary target and A14 egress proof
// through a machine's guest socket, and the A9 offline scenario. The
// package has tests only; it ships nothing. Its boxe2e directory is the
// in-image setup run (#1688), a command CI injects into a booted image.
package e2e
