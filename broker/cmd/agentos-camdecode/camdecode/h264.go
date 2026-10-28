//go:build libavcodec

package camdecode

// The H.264 decoder (CAM-clerk part b2, #3514): libavcodec built with its
// H.264 decoder alone (image/libavcodec.sh), linked statically into
// agentos-camdecode. Only this file touches C. It decodes on one thread,
// logs nothing, and refuses a stream whose coded size exceeds the declared
// shape's, beyond alignment padding, before the decoder allocates frame
// buffers for it (max_pixels; its per-macroblock tables, at most about
// 100 MB, are allocated first and fit the sandbox's memory limit).

/*
#cgo pkg-config: libavcodec libavutil
#cgo LDFLAGS: -lm
#include <errno.h>
#include <string.h>
#include <libavcodec/avcodec.h>
#include <libavutil/log.h>
#include <libavutil/pixfmt.h>

static AVCodecContext *cd_open(int w, int h) {
	av_log_set_level(AV_LOG_QUIET);
	const AVCodec *c = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!c) return NULL;
	AVCodecContext *ctx = avcodec_alloc_context3(c);
	if (!ctx) return NULL;
	ctx->thread_count = 1;
	// The coded size is the shape rounded up to macroblocks; frame buffers
	// pad it further for alignment, so allow 64 pixels a side for that.
	ctx->max_pixels = (int64_t)(((w + 15) & ~15) + 64) * (((h + 15) & ~15) + 64);
	if (avcodec_open2(ctx, c, NULL) < 0) {
		avcodec_free_context(&ctx);
		return NULL;
	}
	return ctx;
}

// cd_send copies one access unit into a padded packet and sends it; a
// NULL p with n 0 sends the flush packet.
static int cd_send(AVCodecContext *ctx, AVPacket *pkt, const unsigned char *p, int n) {
	if (!p) return avcodec_send_packet(ctx, NULL);
	av_packet_unref(pkt);
	if (av_new_packet(pkt, n) < 0) return AVERROR(ENOMEM);
	memcpy(pkt->data, p, n);
	int r = avcodec_send_packet(ctx, pkt);
	av_packet_unref(pkt);
	return r;
}

static int cd_eagain(int r) { return r == AVERROR(EAGAIN); }
static int cd_eof(int r) { return r == AVERROR_EOF; }
static int cd_i420(int f) { return f == AV_PIX_FMT_YUV420P || f == AV_PIX_FMT_YUVJ420P; }

// cd_pack packs the frame's I420 planes of a w by h picture into dst,
// each row cut to the plane's width (linesize pads it); dst holds
// w*h + 2*((w+1)/2)*((h+1)/2) bytes. A missing plane or a linesize short
// of the plane's width is 0.
static int cd_pack(const AVFrame *f, int w, int h, unsigned char *dst) {
	for (int i = 0; i < 3; i++) {
		int pw = i ? (w + 1) / 2 : w, ph = i ? (h + 1) / 2 : h;
		if (!f->data[i] || f->linesize[i] < pw) return 0;
		for (int y = 0; y < ph; y++) {
			memcpy(dst, f->data[i] + (size_t)y * f->linesize[i], pw);
			dst += pw;
		}
	}
	return 1;
}

static void cd_close(AVCodecContext *ctx, AVPacket *pkt, AVFrame *fr) {
	av_frame_free(&fr);
	av_packet_free(&pkt);
	avcodec_free_context(&ctx);
}
*/
import "C"

import "github.com/ghbmrk/agentos/broker/camwire"

// HasH264 reports whether this build decodes video.
const HasH264 = true

type h264 struct {
	ctx   *C.AVCodecContext
	pkt   *C.AVPacket
	fr    *C.AVFrame
	shape camwire.Shape
	buf   []byte // one picture's I420 planes, reused
}

func newH264(s camwire.Shape) (*h264, error) {
	d := &h264{ctx: C.cd_open(C.int(s.Width), C.int(s.Height)), pkt: C.av_packet_alloc(), fr: C.av_frame_alloc(), shape: s,
		buf: make([]byte, Len(KindVideo, s))}
	if d.ctx == nil || d.pkt == nil || d.fr == nil {
		d.close()
		return nil, ErrVideo
	}
	return d, nil
}

// feed sends one access unit (nil flushes the decoder) and passes each
// picture it then yields to pic as I420 planes of the declared shape, in
// a buffer pic must not keep.
// A decoder error, or a picture of another size or pixel format, is
// ErrVideo.
func (d *h264) feed(au []byte, pic func(i420 []byte) error) error {
	var r C.int
	if au == nil {
		r = C.cd_send(d.ctx, d.pkt, nil, 0)
	} else {
		r = C.cd_send(d.ctx, d.pkt, (*C.uchar)(&au[0]), C.int(len(au)))
	}
	if r < 0 {
		return ErrVideo
	}
	for {
		r = C.avcodec_receive_frame(d.ctx, d.fr)
		if C.cd_eagain(r) != 0 || C.cd_eof(r) != 0 {
			return nil
		}
		if r < 0 {
			return ErrVideo
		}
		err := d.picture(pic)
		C.av_frame_unref(d.fr)
		if err != nil {
			return err
		}
	}
}

// picture checks the decoded frame against the declared shape and hands
// pic its planes packed (cd_pack). The C side takes Go memory only as
// byte pointers, so this file imports no unsafe (TestClerkDoesNotLinkDecoder).
func (d *h264) picture(pic func(i420 []byte) error) error {
	w, h := int(d.shape.Width), int(d.shape.Height)
	if int(d.fr.width) != w || int(d.fr.height) != h || C.cd_i420(C.int(d.fr.format)) == 0 ||
		len(d.buf) != Len(KindVideo, d.shape) || C.cd_pack(d.fr, C.int(w), C.int(h), (*C.uchar)(&d.buf[0])) == 0 {
		return ErrVideo
	}
	return pic(d.buf)
}

func (d *h264) close() {
	C.cd_close(d.ctx, d.pkt, d.fr)
	d.ctx, d.pkt, d.fr = nil, nil, nil
}
