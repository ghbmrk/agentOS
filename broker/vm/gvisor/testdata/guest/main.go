// Command guest is the agent-machine stand-in for gvisor's integration test.
//
//	guest serve      hold a random token in memory and serve requests
//	guest svc SOCK PATH  GET PATH from the broker service socket SOCK and
//	                 print the status and body
//	guest stdin N    write "oops\n" to stderr, copy stdin to stdout, then
//	                 exit N (worker exec)
//	guest linger     ignore catchable signals, keep stdout open, and append
//	                 a byte to /work/linger every 20ms until killed
//	guest tamper NONCE PATH...  try to create a sibling named by NONCE
//	                 beside or inside each PATH, never writing PATH itself
//	                 (LOOP-7), and print how many the guest's view accepted
//	guest press KIND MS   apply KIND pressure for MS milliseconds (LOOP-7)
//	guest idle       sleep until killed (a pressure process)
//	guest relay SOCK MODE [RECORD REQID [TO]]  act on the next owner
//	                 message from the broker socket SOCK as an agent that
//	                 obeys its input would (P3-4b-4d): reply answers the
//	                 owner with its text; label asks to label RECORD with
//	                 it; archive asks to archive RECORD; autoreply asks to
//	                 reply to RECORD with it, addressed to TO (ADP-11,
//	                 P3-4b-4e). It prints the broker's answer, which
//	                 decides nothing
//	guest <cmd> ...  send one request to the server and print the answer
//
// Requests: token; write PATH TEXT; read PATH; remove PATH; stat PATH;
// hold SOCK (keep a connection to SOCK open); heldget PATH (GET over the
// held connection).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if len(os.Args) > 3 && os.Args[1] == "relay" {
		out, err := relay(os.Args[2], os.Args[3], os.Args[4:])
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		fmt.Println(out)
		return
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

// call sends one HTTP/1.0 request over a Unix socket and returns the
// status code and body.
func call(sock, method, path string, body []byte) (int, []byte, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return 0, nil, err
	}
	defer c.Close()
	fmt.Fprintf(c, "%s %s HTTP/1.0\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", method, path, len(body))
	c.Write(body)
	b, err := io.ReadAll(c)
	if err != nil {
		return 0, nil, err
	}
	head, rest, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	var code int
	fmt.Sscanf(string(head), "HTTP/%s %d", new(string), &code)
	return code, rest, nil
}

// relay is an agent that does what its input says (P3-4b-4d).
func relay(sock, mode string, args []string) (string, error) {
	var msg struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	}
	if mode != "archive" {
		code, body, err := call(sock, "GET", "/owner/next", nil)
		if err != nil || code != 200 {
			return "", fmt.Errorf("owner/next: %d %v", code, err)
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			return "", err
		}
	}
	out, answer := "replied", msg.Text
	switch mode {
	case "reply":
	case "label", "archive", "autoreply":
		want := 2
		if mode == "autoreply" {
			want = 3
		}
		if len(args) != want {
			return "", errors.New("need RECORD REQID, and TO for autoreply")
		}
		action, params := "mail.archive", map[string]any{"record": args[0]}
		effect := map[string]any{"request_id": args[1], "account": "mail", "params": params}
		switch mode {
		case "label":
			action, params["label"], answer = "mail.label", msg.Text, "done"
		case "autoreply":
			action, params["body"], answer = "mail.reply", msg.Text, "done"
			effect["recipients"] = []string{args[2]}
		}
		effect["action"] = action
		req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "effect_request", "arguments": effect}})
		code, body, err := call(sock, "POST", "/mcp", req)
		if err != nil || code != 200 {
			return "", fmt.Errorf("mcp: %d %v", code, err)
		}
		out = strings.TrimSpace(string(body))
	default:
		return "", fmt.Errorf("no mode %q", mode)
	}
	if mode != "archive" {
		rep, _ := json.Marshal(map[string]string{"id": msg.ID, "text": answer})
		if code, _, err := call(sock, "POST", "/owner/reply", rep); err != nil || code != 204 {
			return "", fmt.Errorf("owner/reply: %d %v", code, err)
		}
	}
	return out, nil
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
