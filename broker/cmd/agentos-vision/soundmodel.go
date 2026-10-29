package main

import (
	"encoding/binary"
	"math"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Sound events are heard by YAMNet (Apache-2.0; Google's AudioSet
// classifier, as zeropointnine/yamnet-onnx converted it with its waveform
// front-end inside), which scores 521 AudioSet classes on each 0.96 s
// window of 16 kHz audio, 0.48 s apart (VIS-A34). Only its class scores
// are asked for: the model's two other outputs, an embedding of each
// window and its spectrogram, are never computed into a buffer the
// service holds. The pre- and post-processing are here, in plain Go, so
// the default build tests them without the runtime.
const (
	// yamnetClasses is the length of one window's scores.
	yamnetClasses = 521
	// yamnetMinSamples is one window: a shorter clip is padded with
	// silence to it.
	yamnetMinSamples = 15600
)

// soundClasses maps each label on the closed list (vision.SoundLabels) to
// the AudioSet classes, by their index in YAMNet's class map, that hear
// it; a label's score is the best of its classes over the clip's windows.
// No speech class is on any list: what is said is never a label (VIS-A8).
var soundClasses = map[string][]int{
	// Alarm, Car alarm, Police car, Ambulance and Fire engine sirens,
	// Alarm clock, Siren, Civil defense siren, Buzzer, Smoke detector,
	// Fire alarm.
	"alarm": {382, 304, 317, 318, 319, 389, 390, 391, 392, 393, 394},
	// Glass, Shatter.
	"glass-break": {435, 437},
	// Gunshot, Machine gun, Fusillade, Artillery fire, Cap gun.
	"gunshot": {421, 422, 423, 424, 425},
	// Screaming.
	"scream": {11},
	// Dog, Bark, Yip, Bow-wow.
	"dog-bark": {69, 70, 71, 73},
	// Motor vehicle (road), Car, Vehicle horn, Car passing by, Truck,
	// Motorcycle, Accelerating. Not Engine or Idling: those hear a
	// chainsaw, a mower or a washing machine as a vehicle.
	"vehicle": {300, 301, 302, 308, 310, 320, 347},
	// Knock.
	"knock": {353},
	// Doorbell, Ding-dong.
	"doorbell": {349, 350},
}

// soundMinScore is the least score at which a label is heard, set on
// ESC-50 folds 1 and 2 so that each label is heard on few clips of other
// sounds (VIS-A34); the figures are measured on folds 3 and 4.
var soundMinScore = map[string]float64{
	"alarm": 0.7, "glass-break": 0.5, "gunshot": 0.9, "scream": 0.5,
	"dog-bark": 0.7, "vehicle": 0.5, "knock": 0.5, "doorbell": 0.5,
}

// soundInput writes the clip, 16-bit little-endian samples, into dst as
// samples from -1 to 1; dst is at least yamnetMinSamples long, and what
// the clip does not fill is silence. It returns the samples used.
func soundInput(pcm []byte, dst []float32) int {
	n := len(pcm) / 2
	for i := 0; i < n; i++ {
		dst[i] = float32(int16(binary.LittleEndian.Uint16(pcm[2*i:]))) / 32768
	}
	clear(dst[n:])
	return max(n, yamnetMinSamples)
}

// soundDecode is the labels heard in YAMNet's scores, a whole number of
// windows of yamnetClasses: each label whose best score over its classes
// and the windows is at least its soundMinScore, in the closed list's
// order, with that score as a whole percent. A score that is not finite
// hears nothing.
func soundDecode(scores []float32) []vision.Sound {
	if len(scores) == 0 || len(scores)%yamnetClasses != 0 {
		return nil
	}
	var out []vision.Sound
	for _, label := range vision.SoundLabels() {
		best := 0.0
		for w := 0; w < len(scores); w += yamnetClasses {
			for _, c := range soundClasses[label] {
				s := float64(scores[w+c])
				if finite(s) {
					best = math.Max(best, s)
				}
			}
		}
		if best >= soundMinScore[label] {
			out = append(out, vision.Sound{Label: label, Conf: percent(best)})
		}
	}
	return out
}
