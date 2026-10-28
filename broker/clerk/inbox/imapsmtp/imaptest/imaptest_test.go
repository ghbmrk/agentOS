package imaptest

import (
	"bufio"
	"fmt"
	"net"
	"testing"
)

// Stopping the server while a client is mid-LOGIN ends that session before
// go-imap's Close runs, so its Close never reads a login the serving
// goroutine is still writing (#3595). Run under -race; the old stop, which
// called srv.Close straight away, raced here.
func TestStopDuringLogin(t *testing.T) {
	for i := range 200 {
		s, stop, err := Run()
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", s.IMAP)
		if err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(c)
		if _, err := r.ReadString('\n'); err != nil { // the greeting
			t.Fatal(err)
		}
		fmt.Fprintf(c, "a%d LOGIN %s %s\r\n", i, User, Password)
		if i%2 == 1 {
			r.ReadString('\n') // let some logins finish before the stop
		}
		stop()
		c.Close()
	}
}

// After stop, the server takes no new IMAP connection.
func TestStopRefusesNewConnections(t *testing.T) {
	s, stop, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	stop()
	c, err := net.Dial("tcp", s.IMAP)
	if err != nil {
		return
	}
	defer c.Close()
	if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
		t.Fatal("a connection after stop was greeted")
	}
}
