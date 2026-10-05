package sipline

import "encoding/binary"

// ULaw encodes 16-bit little-endian linear PCM as G.711 mu-law (PCMU), one
// byte per sample (ITU-T G.711).
func ULaw(pcm []byte) []byte {
	out := make([]byte, len(pcm)/2)
	for i := range out {
		out[i] = ulaw(int16(binary.LittleEndian.Uint16(pcm[2*i:])))
	}
	return out
}

// ALaw encodes 16-bit little-endian linear PCM as G.711 A-law (PCMA).
func ALaw(pcm []byte) []byte {
	out := make([]byte, len(pcm)/2)
	for i := range out {
		out[i] = alaw(int16(binary.LittleEndian.Uint16(pcm[2*i:])))
	}
	return out
}

func ulaw(s int16) byte {
	const bias, clip = 0x84, 32635
	x := int(s)
	sign := 0
	if x < 0 {
		x, sign = -x, 0x80
	}
	if x > clip {
		x = clip
	}
	x += bias
	exp := 7
	for mask := 0x4000; x&mask == 0 && exp > 0; mask >>= 1 {
		exp--
	}
	mant := (x >> (exp + 3)) & 0x0F
	return ^byte(sign | exp<<4 | mant)
}

func alaw(s int16) byte {
	x := int(s) >> 3 // 13-bit magnitude
	sign := 0x80
	if x < 0 {
		x, sign = -x-1, 0
	}
	if x > 0xFFF {
		x = 0xFFF
	}
	var b int
	if x < 32 {
		b = x >> 1
	} else {
		exp := 1
		for v := x >> 5; v > 1; v >>= 1 {
			exp++
		}
		b = exp<<4 | (x>>exp)&0x0F
	}
	return byte((sign | b) ^ 0x55)
}
