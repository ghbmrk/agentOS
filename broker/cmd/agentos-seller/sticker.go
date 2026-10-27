package main

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
)

// claimURL is the box's claim page with the code, which the page prefills
// (localui's GET /claim?code=), on the page's name over HTTPS: the plain
// listener's redirect to HTTPS drops the query (ASSUMPTIONS A8).
func claimURL(code string) string { return card.BoxPage + "claim?code=" + code }

var stickerPage = template.Must(template.New("sticker").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AgentOS claim sticker</title>
<style>
@page { margin: 10mm }
body { font-family: sans-serif; margin: 0 }
.sticker { width: 60mm; border: 0.3mm dashed #999; padding: 4mm; text-align: center }
.qr { width: 40mm; height: 40mm }
.code { font: bold 4.2mm monospace; letter-spacing: 0.3mm; margin-top: 2mm }
.hint { font-size: 2.6mm; margin-top: 1mm }
.step { font: bold 3mm sans-serif; margin-top: 3mm }
.net { font: 3.4mm monospace; margin-top: 1mm }
.label { font: 2.8mm sans-serif; margin-top: 2mm }
</style></head>
<body><div class="sticker">
<div class="step">1. Join this Wi-Fi</div>
{{.WiFiQR}}
<div class="net">{{.SSID}}</div>
<div class="label">Wi-Fi password</div>
<div class="code">{{.Password}}</div>
<div class="hint">Scan, or join network {{.SSID}} with this password.</div>
<div class="step">2. Claim this AgentOS box</div>
{{.QR}}
<div class="label">Claim code</div>
<div class="code">{{.Code}}</div>
<div class="hint">Claim this AgentOS box: scan, or open {{.Page}} and type the claim code.</div>
</div></body></html>
`))

// writeSticker writes the sticker, 0600: the only files that hold the
// code (HW-1). It also prints the setup network, which the phone joins
// first to reach the claim page (§8.1, CTRL-claim-ap).
func writeSticker(dir, code string, net claim.SetupNet) error {
	qr, err := card.QRSVG(claimURL(code))
	if err != nil {
		return err
	}
	wifi, err := card.QRSVG(card.WiFiQR(net.SSID, net.Password))
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err := stickerPage.Execute(&b, struct {
		QR, WiFiQR                 template.HTML
		Code, Page, SSID, Password string
	}{qr, wifi, code, card.BoxPage + "claim", net.SSID, net.Password}); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "sticker.html"), b.Bytes()); err != nil {
		return err
	}
	txt := fmt.Sprintf("Wi-Fi network: %s\nWi-Fi password: %s\nAgentOS claim code: %s\nClaim page: %s\n",
		net.SSID, net.Password, code, claimURL(code))
	return writeNew(filepath.Join(dir, "sticker.txt"), []byte(txt))
}
