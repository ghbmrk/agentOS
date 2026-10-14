package netjoin

import (
	"bufio"
	"bytes"
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
	res, err := c.call(ctx, OpJoin, Request{SSID: ssid, PSK: psk})
	if err != nil {
		return "", err
	}
	var a Answer
	if json.Unmarshal(res, &a) != nil || !a.Code.Known() {
		return "", errAnswer
	}
	return a.Code, nil
}

// Networks asks the helper for the home networks in range, within
// ScanTimeout. It re-checks the answer: more than MaxNetworks names, or a
// name that is not Showable, is an error.
func (c Client) Networks(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, ScanTimeout)
	defer cancel()
	res, err := c.call(ctx, OpScan, struct{}{})
	if err != nil {
		return nil, err
	}
	var n Networks
	d := json.NewDecoder(bytes.NewReader(res))
	d.DisallowUnknownFields()
	if d.Decode(&n) != nil || n.SSIDs == nil || len(n.SSIDs) > MaxNetworks {
		return nil, errAnswer
	}
	for _, s := range n.SSIDs {
		if !Showable([]byte(s)) {
			return nil, errAnswer
		}
	}
	return n.SSIDs, nil
}

// call sends one request and returns its result, or errAnswer.
func (c Client) call(ctx context.Context, op string, args any) (json.RawMessage, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, errAnswer
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req := struct {
		Op   string `json:"op"`
		Args any    `json:"args"`
	}{op, args}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, errAnswer
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, errAnswer
	}
	// 20 names of 32 bytes, each byte escaped to six, fit with room.
	r := bufio.NewReaderSize(conn, 8192)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, errAnswer
	}
	var resp sockets.Response
	if json.Unmarshal(line, &resp) != nil || !resp.OK {
		return nil, errAnswer
	}
	return resp.Result, nil
}
