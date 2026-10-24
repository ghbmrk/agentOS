// Package goosimportsloopstest imports loopstest only on plan9, so every
// file is excluded from the host build: the check must still read it.
package goosimportsloopstest

import _ "github.com/ghbmrk/agentos/broker/loops/loopstest"
