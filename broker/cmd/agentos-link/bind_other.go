//go:build !linux

package main

import (
	"errors"
	"net"
)

// listenLink needs SO_BINDTODEVICE, which only Linux has.
func listenLink(string, int) (net.Listener, error) {
	return nil, errors.New("agentos-link: the link listens on Linux only")
}

func boundDevice(net.Listener) (string, error) {
	return "", errors.New("agentos-link: Linux only")
}
