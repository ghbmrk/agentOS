package main

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"

	"github.com/ghbmrk/agentos/broker/card"
)

// claimURL is the box's claim page with the code, which the page prefills
// (localui's GET /claim?code=).
func claimURL(code string) string { return "http://" + card.BoxAddr + "/claim?code=" + code }

var stickerPage = template.Must(template.New("sticker").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AgentOS claim sticker</title>
<style>
@page { margin: 10mm }
body { font-family: sans-serif; margin: 0 }
.sticker { width: 60mm; border: 0.3mm dashed #999; padding: 4mm; text-align: center }
.qr { width: 40mm; height: 40mm }
.code { font: bold 4.2mm monospace; letter-spacing: 0.3mm; margin-top: 2mm }
.hint { font-size: 2.6mm; margin-top: 1mm }
</style></head>
<body><div class="sticker">
{{.QR}}
<div class="code">{{.Code}}</div>
<div class="hint">Claim this AgentOS box: scan, or open {{.Page}} and type the code.</div>
</div></body></html>
`))

// writeSticker writes the sticker, 0600: the only files that hold the
// code (HW-1).
func writeSticker(dir, code string) error {
	qr, err := card.QRSVG(claimURL(code))
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err := stickerPage.Execute(&b, struct {
		QR         template.HTML
		Code, Page string
	}{qr, code, "http://" + card.BoxAddr + "/claim"}); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "sticker.html"), b.Bytes()); err != nil {
		return err
	}
	txt := fmt.Sprintf("AgentOS claim code: %s\nClaim page: %s\n", code, claimURL(code))
	return writeNew(filepath.Join(dir, "sticker.txt"), []byte(txt))
}
