// Command guest is the agent-machine stand-in for gvisor's integration test.
//
//	guest serve      hold a random token in memory and serve requests
//	guest svc SOCK PATH  GET PATH from the broker service socket SOCK and
//	                 print the status and body
//	guest stdin N    write "oops\n" to stderr, copy stdin to stdout, then
//	                 exit N (worker exec)
//	guest linger     ignore catchable signals, keep stdout open, and append
//	                 a byte to /work/linger every 20ms until killed
//	guest tamper PATH...  try to write each PATH (LOOP-7) and print how many
//	                 writes the guest's view accepted
//	guest press KIND MS   apply KIND pressure for MS milliseconds (LOOP-7)
//	guest idle       sleep until killed (a pressure process)
//	guest <cmd> ...  send one request to the server and print the answer
//
// Requests: token; write PATH TEXT; read PATH; remove PATH; stat PATH;
// hold SOCK (keep a connection to SOCK open); heldget PATH (GET over the
// held connection).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/machprobe"
)

const sock = "/tmp/guest.sock"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve()
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "stdin" {
		os.Stderr.WriteString("oops\n")
		io.Copy(os.Stdout, os.Stdin)
		var n int
		fmt.Sscan(os.Args[2], &n)
		os.Exit(n)
	}
	if len(os.Args) == 2 && os.Args[1] == "linger" {
		linger()
	}
	if len(os.Args) > 3 && os.Args[1] == "tamper" {
		fmt.Println(machprobe.Tamper(os.Args[2], os.Args[3:]))
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "press" {
		ms, _ := strconv.Atoi(os.Args[3])
		o := machprobe.Options{MemMB: 48, DiskMB: 32, Dir: "/work", Procs: 16, Child: []string{"/guest", "idle"}}
		if err := machprobe.Press(context.Background(), os.Args[2], time.Duration(ms)*time.Millisecond, o); err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		fmt.Println("ok")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "idle" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if len(os.Args) == 4 && os.Args[1] == "svc" {
		fmt.Println(get(os.Args[2], os.Args[3]))
		return
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Fprintln(c, strings.Join(os.Args[1:], " "))
	line, _ := bufio.NewReader(c).ReadString('\n')
	fmt.Print(line)
}

// linger stands in for a command that outlives its timeout: only SIGKILL
// ends it, and it holds stdout open while it runs.
func linger() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE)
	fmt.Println("lingering")
	for {
		if f, err := os.OpenFile("/work/linger", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.Write([]byte("."))
			f.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var held []net.Conn

// get sends one HTTP/1.0 GET over a Unix socket; the stdlib client would
// need a custom dialer, and the answer is one short line.
func get(sock, path string) string {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.0\r\nHost: broker\r\n\r\n", path)
	b, _ := io.ReadAll(c)
	status, rest, _ := strings.Cut(string(b), "\r\n")
	_, body, _ := strings.Cut(rest, "\r\n\r\n")
	_, status, _ = strings.Cut(status, " ") // drop the protocol version
	return status + " " + strings.TrimSpace(body)
}

func fill(path string, mb int) string {
	f, err := os.Create(path)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i) | 1
	}
	for i := 0; i < mb; i++ {
		if _, err := f.Write(buf); err != nil {
			return fmt.Sprintf("ERR after %d MiB: %v", i, err)
		}
		if err := f.Sync(); err != nil {
			return fmt.Sprintf("ERR after %d MiB: %v", i, err)
		}
	}
	return "ok"
}

func serve() {
	var b [16]byte
	rand.Read(b[:])
	token := hex.EncodeToString(b[:]) // lives only in memory
	// Keep some heap busy so a checkpoint has pages to save.
	ballast := make([]byte, 32<<20)
	for i := range ballast {
		ballast[i] = byte(i)
	}
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		f := strings.SplitN(strings.TrimSpace(line), " ", 3)
		var out string
		switch f[0] {
		case "token":
			out = token + fmt.Sprint(ballast[len(ballast)-1]*0)
		case "write":
			if err := os.WriteFile(f[1], []byte(f[2]), 0o644); err != nil {
				out = "ERR " + err.Error()
			} else {
				out = "ok"
			}
		case "read":
			b, err := os.ReadFile(f[1])
			if err != nil {
				out = "ERR " + err.Error()
			} else {
				out = string(b)
			}
		case "hold":
			if h, err := net.Dial("unix", f[1]); err != nil {
				out = "ERR " + err.Error()
			} else {
				held = append(held, h)
				out = "ok"
			}
		case "heldget":
			// One keep-alive GET on the newest held connection.
			if len(held) == 0 {
				out = "ERR none held"
				break
			}
			h := held[len(held)-1]
			h.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(h, "GET %s HTTP/1.1\r\nHost: broker\r\n\r\n", f[1])
			buf := make([]byte, 4096)
			n, err := h.Read(buf)
			if err != nil {
				out = "ERR " + err.Error()
				break
			}
			_, body, _ := strings.Cut(string(buf[:n]), "\r\n\r\n")
			out = strings.TrimSpace(body)
		case "remove":
			if err := os.RemoveAll(f[1]); err != nil {
				out = "ERR " + err.Error()
			} else {
				out = "ok"
			}
		case "fill":
			// fill PATH MB: write MB MiB, synced, or as much as fits.
			mb, _ := strconv.Atoi(f[2])
			out = fill(f[1], mb)
		case "spam":
			// spam MB: print MB MiB to the console.
			mb, _ := strconv.Atoi(f[1])
			line := strings.Repeat("y", 1023) + "\n"
			for i := 0; i < mb<<10; i++ {
				os.Stdout.WriteString(line)
			}
			out = "ok"
		case "stat":
			if _, err := os.Stat(f[1]); err != nil {
				out = "absent"
			} else {
				out = "present"
			}
		default:
			out = "ERR unknown"
		}
		fmt.Fprintln(c, out)
		c.Close()
	}
}
