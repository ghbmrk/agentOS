package at

// DeliverAlpha encodes an SMS-DELIVER from an alphanumeric sender ID
// (type 101), which can spell any text, a phone number included.
func DeliverAlpha(name, text string) string {
	var septets []byte
	for _, r := range name {
		septets = append(septets, gsm7Code[r])
	}
	oa := append([]byte{byte((len(septets)*7 + 3) / 4), 0xD0}, pack7(septets, 0, nil)...)
	p, _ := encodeDeliver(oa, 0x00, text, 1)
	return p[0]
}

// DeliverNational encodes an SMS-DELIVER from a national-format number.
func DeliverNational(digits, text string) string {
	oa, _ := encodeAddr(digits)
	p, _ := encodeDeliver(oa, 0x00, text, 1)
	return p[0]
}

// DeliverPID encodes an SMS-DELIVER with the given TP-PID.
func DeliverPID(from string, pid byte, text string) string {
	oa, _ := encodeAddr(from)
	p, _ := encodeDeliver(oa, pid, text, 1)
	return p[0]
}
