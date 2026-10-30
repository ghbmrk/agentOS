package thread

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio"
)

// Commands is the closed list of ot-daemon commands the adapter ever
// sends: bring-up (form a network once, then start it with the SRP server
// on) and the read. Nothing the radio host sends becomes a command.
var Commands = []string{
	"dataset active -x",
	"dataset init new",
	"dataset commit active",
	"srp server enable",
	"ifconfig up",
	"thread start",
	"state",
}

// roles are the answers to "state" a read reports.
var roles = []string{"disabled", "detached", "child", "router", "leader"}

const (
	cliTimeout = 10 * time.Second
	maxLines   = 32
	maxLine    = 1024
)

var (
	ErrCommand = errors.New("thread: command not on the adapter's list")
	ErrCLI     = errors.New("thread: ot-daemon's answer refused")
)

// Status is a read of the Thread network.
type Status struct {
	Role string
}

// Adapter is the adapter process's main, run after confine.Trampoline: it
// connects to ot-daemon's command socket in its working directory, brings
// the network up, and serves the radio host on fd 3.
func Adapter() error {
	return Serve(Socket, os.NewFile(3, "interface"), 15*time.Second)
}

// Serve is the adapter on ot-daemon's socket sock (waiting up to wait for
// it to appear) and the radio host's interface iface.
func Serve(sock string, iface io.ReadWriteCloser, wait time.Duration) error {
	c, err := dialCLI(sock, wait)
	if err != nil {
		iface.Close()
		return err
	}
	if err := c.bringUp(); err != nil {
		iface.Close()
		return err
	}
	return radio.NewServer(radio.StackThread, iface).Serve(c.serve)
}

type cli struct {
	path string
	conn net.Conn // nil after a fault: the next command opens a new session
	r    *bufio.Reader
}

// dialCLI connects to ot-daemon's socket, waiting up to wait for it to
// appear while ot-daemon starts.
func dialCLI(path string, wait time.Duration) (*cli, error) {
	deadline := time.Now().Add(wait)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return &cli{path: path, conn: conn, r: bufio.NewReaderSize(conn, maxLine)}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("thread: ot-daemon's socket: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// do sends one listed command and returns its output lines before Done.
// An Error line is an error; output longer than the bounds, a timeout or a
// closed socket is ErrCLI and ends the session, so no later command reads
// what this one left behind.
func (c *cli) do(cmd string) ([]string, error) {
	if !slices.Contains(Commands, cmd) {
		return nil, ErrCommand
	}
	if c.conn == nil {
		n, err := dialCLI(c.path, time.Second)
		if err != nil {
			return nil, err
		}
		*c = *n
	}
	out, err := c.exchange(cmd)
	if errors.Is(err, ErrCLI) {
		c.conn.Close()
		c.conn = nil
	}
	return out, err
}

func (c *cli) exchange(cmd string) ([]string, error) {
	c.conn.SetDeadline(time.Now().Add(cliTimeout))
	if _, err := c.conn.Write([]byte(cmd + "\n")); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCLI, err)
	}
	var out []string
	for len(out) <= maxLines {
		line, err := c.r.ReadSlice('\n')
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCLI, err)
		}
		s := strings.TrimPrefix(strings.TrimRight(string(line), "\r\n"), "> ")
		switch {
		case s == "Done":
			return out, nil
		case strings.HasPrefix(s, "Error "):
			return nil, fmt.Errorf("thread: %s: %s", cmd, s)
		case s != "":
			out = append(out, s)
		}
	}
	return nil, fmt.Errorf("%w: more than %d lines", ErrCLI, maxLines)
}

// bringUp forms a network the first time (ot-daemon keeps its dataset in
// its state directory) and starts it with the SRP server on.
func (c *cli) bringUp() error {
	if _, err := c.do("dataset active -x"); err != nil {
		for _, cmd := range []string{"dataset init new", "dataset commit active"} {
			if _, err := c.do(cmd); err != nil {
				return err
			}
		}
	}
	for _, cmd := range []string{"srp server enable", "ifconfig up", "thread start"} {
		if _, err := c.do(cmd); err != nil {
			return err
		}
	}
	return nil
}

// serve answers the radio host. Server has already held the request to
// radio.Declared[radio.StackThread], so only reads arrive.
func (c *cli) serve(r radio.Request) ([]byte, radio.Code) {
	if r.Op != radio.OpRead || r.Device != Network {
		return nil, radio.CodeRefused
	}
	out, err := c.do("state")
	if err != nil {
		return nil, radio.CodeFailed
	}
	if len(out) != 1 || !slices.Contains(roles, out[0]) {
		return nil, radio.CodeFailed
	}
	b, _ := json.Marshal(Status{Role: out[0]})
	return b, radio.CodeOK
}
