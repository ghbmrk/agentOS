package sipline_test

// REQ: ADP-12
// Row: VULN-gobwas-ws-r2 (#6650).

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// A SIP message close to sipgo's ParseMaxMessageLength crosses the line's
// own WS transport (its gobwas/ws dialer) intact. A gobwas/ws or sipgo bump
// that caps or splits WS messages below that size fails here, not on the box.
func TestWSCarriesAMessageNearTheParseLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	far, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	defer far.Close()
	srv, err := sipgo.NewServer(far)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *sip.Request, 1)
	srv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		got <- req.Clone()
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	})
	go func() { _ = srv.ServeWS(ln) }()
	defer ln.Close()

	g := sipline.ReachLoopback(netguard.New(netguard.Config{}))
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(sipline.TransportOptions(g)...))
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	cli, err := sipgo.NewClient(ua)
	if err != nil {
		t.Fatal(err)
	}

	to := sip.Uri{User: "far", Host: "127.0.0.1", Port: port, UriParams: sip.NewParams()}
	to.UriParams.Add("transport", "ws")
	req := sip.NewRequest(sip.MESSAGE, to)
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain"))
	// Size the body so the whole request, with the headers the client adds,
	// lands just under the limit; the margin covers those headers.
	const margin = 512
	req.SetBody([]byte("x"))
	head := len(req.String()) - 1
	body := make([]byte, sip.ParseMaxMessageLength-margin-head)
	for i := range body {
		body[i] = 'a' + byte(i*7%26) // a pattern, so a cut or a shuffle shows
	}
	req.SetBody(body)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cli.Do(ctx, req)
	if err != nil {
		t.Fatalf("send over WS: %v", err)
	}
	if res.StatusCode != sip.StatusOK {
		t.Fatalf("far end answered %d", res.StatusCode)
	}
	var in *sip.Request
	select {
	case in = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the far end saw no MESSAGE")
	}
	if in.Transport() != "WS" {
		t.Fatalf("arrived over %q, want WS", in.Transport())
	}
	if !bytes.Equal(in.Body(), body) {
		t.Fatalf("body arrived as %d bytes, want %d intact", len(in.Body()), len(body))
	}
	if n := len(in.String()); n < sip.ParseMaxMessageLength-2*margin || n > sip.ParseMaxMessageLength {
		t.Fatalf("message was %d bytes, want within %d of %d", n, 2*margin, sip.ParseMaxMessageLength)
	}
}
