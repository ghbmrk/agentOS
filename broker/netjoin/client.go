package netjoin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Client is agentosd's side of the helper's socket.
type Client struct {
	// Path is the helper's socket.
	Path string
}

// errAnswer is any answer that is not one of the six codes. It carries
// nothing of the request.
var errAnswer = errors.New("netjoin: helper gave no answer")

// Join asks the helper to write the home connection and returns its code,
// within CallTimeout. An error means the helper could not be reached or
// answered nothing usable; it never carries the request.
func (c Client) Join(ctx context.Context, ssid, psk string) (Code, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return "", errAnswer
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req := struct {
		Op   string  `json:"op"`
		Args Request `json:"args"`
	}{OpJoin, Request{SSID: ssid, PSK: psk}}
	b, err := json.Marshal(req)
	if err != nil {
		return "", errAnswer
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return "", errAnswer
	}
	r := bufio.NewReaderSize(conn, 4096)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", errAnswer
	}
	var resp sockets.Response
	if json.Unmarshal(line, &resp) != nil || !resp.OK {
		return "", errAnswer
	}
	var a Answer
	if json.Unmarshal(resp.Result, &a) != nil || !a.Code.Known() {
		return "", errAnswer
	}
	return a.Code, nil
}
