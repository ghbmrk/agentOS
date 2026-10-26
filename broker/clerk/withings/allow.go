package withings

import (
	"bytes"
	"encoding/binary"
)

// The reader identifies itself as the Withings phone app on Android, as the
// source does (os 1, app 1, app version 202609240, API level 34); the scale
// accepted these.
const (
	appVersion = 202609240
	osVersion  = 34
)

// The fixed frames: every frame the reader writes is one of these, a
// challenge answer, or an unsupported-request error (see allowed).
var (
	probeFrame = message{cmdProbe, []tlv{
		{tAppProbe, []byte{1, 1, appVersion >> 24, appVersion >> 16 & 0xff, appVersion >> 8 & 0xff, appVersion & 0xff}},
		{tAppProbeOSVersion, []byte{0, osVersion}},
	}}.encode()
	batteryFrame       = message{cmd: cmdBattery}.encode()
	connectReasonFrame = message{cmd: cmdConnectReason}.encode()
	// STORED_MEASURE action 0 (status) and 1 (all records), rc 0. Action 2
	// deletes the scale's records and is never sent (protocol.md).
	statusFrame     = message{cmdStoredMeasure, []tlv{{tMeasureAction, []byte{0, 0}}}}.encode()
	allFrame        = message{cmdStoredMeasure, []tlv{{tMeasureAction, []byte{1, 0}}}}.encode()
	syncOKFrame     = message{cmd: cmdSyncOK}.encode()
	syncOKEcho      = message{cmd: cmdSyncOK | deviceRequest}.encode()
	disconnectFrame = message{cmd: cmdDisconnect}.encode()

	fixedFrames = [][]byte{probeFrame, batteryFrame, connectReasonFrame, statusFrame, allFrame,
		syncOKFrame, syncOKEcho, disconnectFrame}
)

const (
	answerLen    = 20 // SHA-1
	challengeLen = 16
	// maxMAC bounds the scale's MAC string, which the challenge answer
	// echoes; the scale sends 17 characters.
	maxMAC = 32
)

// allowed is whether frame is one the reader may write: the closed list of
// read-only shapes from the source's client, checked on the encoded bytes
// so nothing built elsewhere slips past (DEV-4, DEV-12). The source's
// never-send list (association keys, setup, scale session, user and unit
// writes, Wi-Fi, firmware, factory reset, the delete action) is open, and
// TIME_SET is on no list, so the check allows shapes rather than refusing
// opcodes.
func allowed(frame []byte) bool {
	for _, f := range fixedFrames {
		if bytes.Equal(frame, f) {
			return true
		}
	}
	m, err := decode(frame)
	if err != nil {
		return false
	}
	switch m.cmd {
	case cmdChallenge:
		return challengeShape(m)
	case cmdError | deviceRequest:
		// One CMD_ERROR naming the request's command, with "unsupported".
		if len(m.tlvs) != 1 || m.tlvs[0].typ != tCmdError || len(m.tlvs[0].val) != 6 {
			return false
		}
		return int32(binary.BigEndian.Uint32(m.tlvs[0].val[2:])) == errUnsupported
	}
	return false
}

// challengeShape is our answer to the scale's challenge and our own
// challenge to it: PROBE_CHALLENGE_RESPONSE (a 20-byte answer), then
// PROBE_CHALLENGE (the scale's MAC string and 16 bytes).
func challengeShape(m message) bool {
	if len(m.tlvs) != 2 || m.tlvs[0].typ != tChallengeResponse || m.tlvs[1].typ != tChallenge {
		return false
	}
	a := reader{b: m.tlvs[0].val}
	if len(a.str()) != answerLen || !a.done() {
		return false
	}
	c := reader{b: m.tlvs[1].val}
	mac := c.str()
	return len(mac) > 0 && len(mac) <= maxMAC && len(c.str()) == challengeLen && c.done()
}
