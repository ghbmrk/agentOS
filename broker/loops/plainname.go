package loops

import "strings"

// Plain names for LOOP-7 subjects (P3-4b-3c). Owner text about a fuzz,
// socket-probe, canary or corpus finding names what was tested only
// through these maps: never a Go identifier, file name, path or digest.
// A subject without an entry gets genericName, and
// TestThePlainNameMapCoversEveryLoop7Subject flags it.

// genericName is the fallback for a subject the maps do not name.
const genericName = "one of my internal checks"

// fuzzNames maps a fuzz target, as loop7 names it ("<package>.<func>"),
// to what it tests.
var fuzzNames = map[string]string{
	"attest.FuzzParse":              "the check that reads attestations",
	"at.FuzzDecodeDeliver":          "the check that reads incoming SMS",
	"at.FuzzTIM1ParseNetworkTime":   "the check that reads the network time",
	"browser.FuzzParse":             "the check that reads browser replies",
	"control.FuzzParse":             "the check that reads your commands",
	"guest.FuzzMCP":                 "the check that reads agent tool calls",
	"hint.FuzzParse":                "the check that reads bridge hints",
	"hostdisk.FuzzProbe":            "the check that reads attached disks",
	"localui.FuzzScanPassphrase":    "the check that reads a passphrase photo",
	"loops.FuzzParseText":           "the check that reads your settings texts",
	"mail.FuzzParse":                "the check that reads incoming mail",
	"modemlink.FuzzInbound":         "the check that reads messages from the modem",
	"owner.FuzzParseReply":          "the check that reads your replies",
	"recovery.FuzzParseRecoveryKey": "the check that reads a typed recovery key",
	"sockets.FuzzFrames":            "the check that reads agent messages",
	"sockets.FuzzRequest":           "the check that reads agent requests",
	"tpmseal.FuzzParse":             "the check that reads sealed-key records",
	"update.FuzzParseAttestation":   "the check that reads update attestations",
}

// probePrefix starts the socket probe's subject ("socket.<machine>").
const probePrefix = "socket."

// probeName is what the socket probe tests.
const probeName = "the agent's connection to me"

// canaryNames maps a canary registry target to where its planted secret
// must never be.
var canaryNames = map[string]string{
	"guest-socket-vault-egress": "what an agent machine can send out",
	"drive-at-rest-a8":          "the stored files on my drive",
}

// corpusCheck is a closed check's plain name and what its self-test
// missed.
type corpusCheck struct{ name, missed string }

// corpusNames maps a closed check's name (a corpus finding's Detail) to
// owner words.
var corpusNames = map[string]corpusCheck{
	"code filter":       {"the code filter", "missed a test code hidden inside a known attack text"},
	"commitment filter": {"the commitment filter", "missed a test promise to pay hidden inside a known attack text"},
	"alert patterns":    {"the security-alert check", "missed a test alert hidden inside a known attack text"},
	"label check":       {"the mail label check", "accepted a known attack text as a label name"},
}

// corpusFallback is corpusNames' entry for a check it does not name.
var corpusFallback = corpusCheck{genericName, "missed a test input hidden inside a known attack text"}

// plainName is the owner's name for a LOOP-7 finding's subject, and
// whether a map named it. Other checks keep their subject (safeName).
func plainName(f Finding) (string, bool) {
	var n string
	var ok bool
	switch f.Check {
	case CheckFuzz:
		n, ok = fuzzNames[f.Subject]
	case CheckProbe:
		n, ok = probeName, strings.HasPrefix(f.Subject, probePrefix)
	case CheckCanary:
		n, ok = canaryNames[f.Subject]
	case CheckCorpus:
		var c corpusCheck
		c, ok = corpusNames[f.Detail]
		n = c.name
	default:
		return safeName(f.Subject), true
	}
	if !ok {
		return genericName, false
	}
	return n, true
}

// plainSubject is plainName without the flag.
func plainSubject(f Finding) string {
	n, _ := plainName(f)
	return n
}
