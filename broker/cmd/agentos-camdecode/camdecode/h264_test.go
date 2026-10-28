//go:build libavcodec

package camdecode

// REQ: NET-2, KRN-2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// bits writes an H.264 RBSP: fixed-width fields and Exp-Golomb codes.
type bits struct {
	b []byte
	n uint // bits used in the last byte
}

func (w *bits) u(n int, v uint32) {
	for i := n - 1; i >= 0; i-- {
		if w.n == 0 || w.n == 8 {
			w.b, w.n = append(w.b, 0), 0
		}
		w.b[len(w.b)-1] |= byte(v>>uint(i)&1) << (7 - w.n)
		w.n++
	}
}

func (w *bits) ue(v uint32) {
	v++
	n := 0
	for x := v; x > 1; x >>= 1 {
		n++
	}
	w.u(n, 0)
	w.u(n+1, v)
}

func (w *bits) align() {
	for w.n != 0 && w.n != 8 {
		w.u(1, 0)
	}
}

func (w *bits) trailing() {
	w.u(1, 1)
	w.align()
}

// nal frames an RBSP as an Annex B NAL unit, with emulation prevention.
func nal(typ byte, rbsp []byte) []byte {
	out := []byte{0, 0, 0, 1, 3<<5 | typ}
	zeros := 0
	for _, c := range rbsp {
		if zeros >= 2 && c <= 3 {
			out, zeros = append(out, 3), 0
		}
		out = append(out, c)
		if c == 0 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return out
}

// pcmPicture is one IDR access unit (SPS, PPS, slice) of shape s whose
// macroblocks are all I_PCM, so the decoded picture is exactly the
// samples: luma value y and chroma values cb, cr. Each value is nonzero,
// so no emulation prevention lands in the samples. idr alternates the
// IDR picture id, as consecutive IDR pictures need.
func pcmPicture(s camwire.Shape, y, cb, cr byte, idr uint32) []byte {
	mbw, mbh := (uint32(s.Width)+15)/16, (uint32(s.Height)+15)/16
	var sps bits
	sps.u(8, 66) // Baseline
	sps.u(8, 0)
	sps.u(8, 40)
	sps.ue(0)   // seq_parameter_set_id
	sps.ue(0)   // log2_max_frame_num_minus4
	sps.ue(2)   // pic_order_cnt_type: output order is decode order
	sps.ue(1)   // max_num_ref_frames
	sps.u(1, 0) // gaps_in_frame_num_value_allowed_flag
	sps.ue(mbw - 1)
	sps.ue(mbh - 1)
	sps.u(1, 1) // frame_mbs_only_flag
	sps.u(1, 1) // direct_8x8_inference_flag
	cropR, cropB := (mbw*16-uint32(s.Width))/2, (mbh*16-uint32(s.Height))/2
	if cropR|cropB != 0 {
		sps.u(1, 1)
		sps.ue(0)
		sps.ue(cropR)
		sps.ue(0)
		sps.ue(cropB)
	} else {
		sps.u(1, 0)
	}
	sps.u(1, 0) // vui_parameters_present_flag
	sps.trailing()

	var pps bits
	pps.ue(0)   // pic_parameter_set_id
	pps.ue(0)   // seq_parameter_set_id
	pps.u(1, 0) // CAVLC
	pps.u(1, 0)
	pps.ue(0) // num_slice_groups_minus1
	pps.ue(0)
	pps.ue(0)
	pps.u(1, 0)
	pps.u(2, 0)
	pps.ue(0) // pic_init_qp_minus26 (se 0)
	pps.ue(0)
	pps.ue(0)
	pps.u(1, 1) // deblocking_filter_control_present_flag
	pps.u(1, 0)
	pps.u(1, 0)
	pps.trailing()

	var sl bits
	sl.ue(0) // first_mb_in_slice
	sl.ue(7) // I slice, all slices
	sl.ue(0) // pic_parameter_set_id
	sl.u(4, 0)
	sl.ue(idr) // idr_pic_id
	sl.u(1, 0) // no_output_of_prior_pics_flag
	sl.u(1, 0) // long_term_reference_flag
	sl.ue(0)   // slice_qp_delta (se 0)
	sl.ue(1)   // disable_deblocking_filter_idc
	for i := uint32(0); i < mbw*mbh; i++ {
		sl.ue(25) // I_PCM
		sl.align()
		for j := 0; j < 256; j++ {
			sl.u(8, uint32(y))
		}
		for j := 0; j < 64; j++ {
			sl.u(8, uint32(cb))
		}
		for j := 0; j < 64; j++ {
			sl.u(8, uint32(cr))
		}
	}
	sl.trailing()

	au := nal(7, sps.b)
	au = append(au, nal(8, pps.b)...)
	return append(au, nal(5, sl.b)...)
}

func videoFrame(au []byte) []byte {
	out := []byte{byte(camwire.TypeVideo)}
	out = binary.BigEndian.AppendUint32(out, uint32(len(au)))
	return append(out, au...)
}

// wantPicture is the output frame a pcmPicture decodes to.
func wantPicture(s camwire.Shape, y, cb, cr byte, counter uint32) []byte {
	out := AppendHeader(nil, KindVideo, s, counter)
	cw, ch := (int(s.Width)+1)/2, (int(s.Height)+1)/2
	out = append(out, bytes.Repeat([]byte{y}, int(s.Width)*int(s.Height))...)
	out = append(out, bytes.Repeat([]byte{cb}, cw*ch)...)
	return append(out, bytes.Repeat([]byte{cr}, cw*ch)...)
}

// TestRunVideo: each access unit comes out as one picture of the declared
// shape, its samples exact (I_PCM), counted from 1, interleaved with
// thermal frames in input order.
func TestRunVideo(t *testing.T) {
	var in, want []byte
	in = append(in, videoFrame(pcmPicture(fuzzVideo, 0x10, 0x20, 0x30, 0))...)
	want = append(want, wantPicture(fuzzVideo, 0x10, 0x20, 0x30, 1)...)
	in = append(in, thermalFrame(4, 3, 9)...)
	want = append(want, AppendHeader(nil, KindThermal, fuzzThermal, 9)...)
	want = append(want, make([]byte, Len(KindThermal, fuzzThermal))...)
	in = append(in, videoFrame(pcmPicture(fuzzVideo, 0xe0, 0x70, 0x90, 1))...)
	want = append(want, wantPicture(fuzzVideo, 0xe0, 0x70, 0x90, 2)...)
	var out bytes.Buffer
	if err := Run(bytes.NewReader(in), &out, Config{Video: fuzzVideo, Thermal: fuzzThermal}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out %d bytes, want %d:\n%x\n%x", out.Len(), len(want), out.Bytes(), want)
	}
}

// TestRunVideoRefuses: a picture of another shape than the bundle
// declares, a larger coded size than the declared shape allows (refused
// before the decoder allocates for it), and a slice with no parameter
// sets each end the run with ErrVideo and exit code 11, writing no
// picture.
func TestRunVideoRefuses(t *testing.T) {
	for name, au := range map[string][]byte{
		"other shape": pcmPicture(camwire.Shape{Width: 6, Height: 8}, 1, 1, 1, 0),
		"oversized":   pcmPicture(camwire.Shape{Width: 128, Height: 128}, 1, 1, 1, 0),
		"no sps":      {0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x33},
	} {
		var out bytes.Buffer
		err := Run(bytes.NewReader(videoFrame(au)), &out, Config{Video: fuzzVideo})
		if err != ErrVideo || ExitCode(err) != 11 || out.Len() != 0 {
			t.Errorf("%s: Run = %v (exit %d), %d bytes out", name, err, ExitCode(err), out.Len())
		}
	}
}

// TestRunVideoCropped: a shape off the 16-pixel macroblock grid decodes
// through the SPS cropping to exactly the declared shape.
func TestRunVideoCropped(t *testing.T) {
	s := camwire.Shape{Width: 18, Height: 14}
	var out bytes.Buffer
	if err := Run(bytes.NewReader(videoFrame(pcmPicture(s, 5, 6, 7, 0))), &out, Config{Video: s}); err != nil {
		t.Fatal(err)
	}
	if want := wantPicture(s, 5, 6, 7, 1); !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out %x", out.Bytes())
	}
}
